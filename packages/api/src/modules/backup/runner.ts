import type { BackupManifest, Placement, Resources } from "@hullbay/shared"
import type { DockerEngineService } from "../docker-engine/service"
import type { ArtifactProducer, ProducedArtifact } from "./engine/lifecycle"
import { BackupError } from "./engine/lifecycle"
import { SwarmTaskExecutor, type TaskSecret } from "./engine/swarm-task"
import { buildRcloneRemoteString, scrubSecrets } from "./storage/remote-string"
import type { ResolvedDestination } from "./storage/registry"
import type { StrategyPlan, StrategyTarget } from "./strategies/types"
import { CHECKSUM_FILE, MANIFEST_FILE } from "./manifest"

/**
 * Exécuteur Swarm one-shot du Backup Engine.
 *
 * Contraintes (Direction + plan) :
 *  - jamais de `docker exec` : un service éphémère par étape, supprimé ensuite ;
 *  - credentials uniquement en Docker Secrets montés en fichiers ;
 *  - aucun volume d'archive : extraction → gzip → `rclone rcat` en streaming ;
 *  - le manifest est écrit en dernier (marqueur de commit).
 */

const RESULT_MARKER = "HULLBAY_BACKUP_RESULT"

export interface SwarmRunnerDeps {
  engine: DockerEngineService
  image: string
  networkName: string
  volumeName?: string
  placement?: Placement
  resources?: Resources
  timeoutSec: number
  pollMs?: number
}

function secretName(prefix: string, runId: string): string {
  return `${prefix}_${runId}`.slice(0, 60)
}

export class SwarmBackupRunner implements ArtifactProducer {
  private readonly tasks: SwarmTaskExecutor

  constructor(private readonly deps: SwarmRunnerDeps) {
    this.tasks = new SwarmTaskExecutor(deps.engine)
  }

  async produce(ctx: {
    runId: string
    artifactId: string
    stagingPrefix: string
    destination: ResolvedDestination
    target: StrategyTarget
    plan: StrategyPlan
    onPhase: (phase: "transferring") => Promise<void>
  }): Promise<ProducedArtifact> {
    const payloadFile = `payload.${ctx.plan.payloadFormat}`
    const payloadKey = `${ctx.stagingPrefix}/${payloadFile}`
    const created: string[] = []

    try {
      const remoteSecret = secretName("backup_remote", ctx.runId)
      await this.deps.engine.upsertSecret(remoteSecret, this.remoteFor(ctx.destination), {
        "bozando.backupRunId": ctx.runId,
      })
      created.push(remoteSecret)

      const secrets: TaskSecret[] = [
        { secretName: remoteSecret, target: "/run/secrets/backup_remote" },
      ]
      if (ctx.target.passwordSecretRef) {
        secrets.push({
          secretName: ctx.target.passwordSecretRef,
          target: "/run/secrets/db_password",
        })
      }
      await this.mountKeySecret(ctx.runId, ctx.destination, secrets, created)

      const script = [
        "set -euo pipefail",
        'REMOTE="$(cat /run/secrets/backup_remote)"',
        `trap 'rclone purge "$REMOTE/${ctx.stagingPrefix}" >/dev/null 2>&1 || true' ERR`,
        "mkdir -p /tmp/work",
        ctx.plan.prereqScript ?? "",
        "{",
        ctx.plan.extractionScript,
        "} | tee \\",
        "  >(sha256sum | awk '{print $1}' > /tmp/work/checksum) \\",
        "  >(wc -c | tr -d ' ' > /tmp/work/size) \\",
        `  | rclone rcat "$REMOTE/${payloadKey}"`,
        "wait",
        `printf '${RESULT_MARKER} %s %s\\n' "$(cat /tmp/work/size)" "$(cat /tmp/work/checksum)"`,
      ]
        .filter((line) => line.length > 0)
        .join("\n")

      await ctx.onPhase("transferring")
      const logs = await this.tasks.run({
        runId: ctx.runId,
        suffix: "transfer",
        script,
        env: ctx.plan.env,
        secrets,
        networkName: this.deps.networkName,
        volumeName: this.deps.volumeName,
        image: this.deps.image,
        placement: this.deps.placement,
        resources: this.deps.resources,
        timeoutSec: this.deps.timeoutSec,
        pollMs: this.deps.pollMs,
      })

      const parsed = this.parseResult(logs)
      if (!parsed) {
        throw new BackupError(
          "transfer_failed",
          "le task n'a pas produit de résultat exploitable",
        )
      }
      return { payloadKey, payloadFileName: payloadFile, ...parsed }
    } catch (error) {
      throw this.classifyTransferFailure(error)
    } finally {
      await this.removeSecrets(created)
    }
  }

  /**
   * Le checksum est calculé pendant le transfert. La relecture distante a lieu
   * dans le task de commit, avant toute promotion du payload.
   */
  async verify(produced: ProducedArtifact) {
    return {
      sizeBytes: produced.sizeBytes,
      checksumSha256: produced.checksumSha256,
    }
  }

  async commit(ctx: {
    produced: ProducedArtifact
    destination: ResolvedDestination
    finalPrefix: string
    manifest: BackupManifest
  }): Promise<void> {
    const runId = ctx.manifest.runId
    const remoteSecret = secretName("backup_remote", runId)
    const manifestSecret = secretName("backup_manifest", runId)
    const created: string[] = []

    try {
      await this.deps.engine.upsertSecret(
        remoteSecret,
        this.remoteFor(ctx.destination),
        { "bozando.backupRunId": runId },
      )
      created.push(remoteSecret)
      await this.deps.engine.upsertSecret(
        manifestSecret,
        JSON.stringify(ctx.manifest, null, 2),
        { "bozando.backupRunId": runId },
      )
      created.push(manifestSecret)

      const secrets: TaskSecret[] = [
        { secretName: remoteSecret, target: "/run/secrets/backup_remote" },
        { secretName: manifestSecret, target: "/run/secrets/backup_manifest" },
      ]
      await this.mountKeySecret(runId, ctx.destination, secrets, created)

      const script = [
        "set -euo pipefail",
        'REMOTE="$(cat /run/secrets/backup_remote)"',
        `SRC="$REMOTE/${ctx.produced.payloadKey}"`,
        `DST="$REMOTE/${ctx.finalPrefix}/${ctx.produced.payloadFileName}"`,
        `EXPECTED="${ctx.produced.checksumSha256}"`,
        // Relecture distante avant promotion : un payload corrompu n'est jamais commité.
        'HAVE="$(rclone hashsum sha256 "$SRC" 2>/dev/null | awk \'{print $1}\')" || HAVE=""',
        'if [ -n "$HAVE" ] && [ "$HAVE" != "$EXPECTED" ]; then',
        '  echo "checksum distant different" >&2',
        "  exit 4",
        "fi",
        'rclone moveto "$SRC" "$DST"',
        `printf '%s  %s\\n' "$EXPECTED" "${ctx.produced.payloadFileName}" | rclone rcat "$REMOTE/${ctx.finalPrefix}/${CHECKSUM_FILE}"`,
        `rclone rcat "$REMOTE/${ctx.finalPrefix}/${MANIFEST_FILE}" < /run/secrets/backup_manifest`,
      ].join("\n")

      await this.tasks.run({
        runId,
        suffix: "commit",
        script,
        secrets,
        networkName: this.deps.networkName,
        image: this.deps.image,
        placement: this.deps.placement,
        resources: this.deps.resources,
        timeoutSec: this.deps.timeoutSec,
        pollMs: this.deps.pollMs,
      })
    } catch (error) {
      throw this.classifyCommitFailure(error)
    } finally {
      await this.removeSecrets(created)
    }
  }

  // ── Interne ────────────────────────────────────────────────────────────────

  /**
   * Traduit un échec de task en code métier stable. Le classement se fait sur
   * le code de sortie et la trace, jamais sur le message brut (qui peut contenir
   * des identifiants de connexion → scrub avant persistance).
   */
  private classifyTransferFailure(error: unknown): unknown {
    if (!(error instanceof BackupError) || error.code !== "task_failed") return error
    const logs = scrubSecrets(error.logs ?? "")
    if (error.exitCode === 3) {
      return new BackupError("prereq_failed", "prérequis du moteur non satisfaits", { logs })
    }
    if (
      /rclone|Failed to (?:create|copy|open|stat|delete|move)|dial tcp|no such host|connection refused|i\/o timeout|context deadline exceeded/i.test(
        logs,
      )
    ) {
      return new BackupError("destination_unreachable", "destination de sauvegarde injoignable", {
        logs,
      })
    }
    return new BackupError("transfer_failed", error.message, { logs })
  }

  private classifyCommitFailure(error: unknown): unknown {
    if (!(error instanceof BackupError) || error.code !== "task_failed") return error
    const logs = scrubSecrets(error.logs ?? "")
    if (error.exitCode === 4 || /checksum distant different/i.test(logs)) {
      return new BackupError("checksum_mismatch", "checksum distant différent", { logs })
    }
    if (
      /rclone|dial tcp|no such host|connection refused|i\/o timeout|context deadline exceeded/i.test(
        logs,
      )
    ) {
      return new BackupError("destination_unreachable", "destination de sauvegarde injoignable", {
        logs,
      })
    }
    return new BackupError("commit_failed", "commit de l'artifact échoué", { logs })
  }

  private remoteFor(destination: ResolvedDestination): string {
    return buildRcloneRemoteString({
      protocol: destination.protocol,
      config: destination.config,
      basePath: destination.basePath,
      secretFiles: {
        privateKey:
          destination.config.protocol === "sftp" ? "/run/secrets/backup_key" : undefined,
        serviceAccountJson:
          destination.config.protocol === "gcs" ? "/run/secrets/backup_key" : undefined,
      },
    })
  }

  private async mountKeySecret(
    runId: string,
    destination: ResolvedDestination,
    secrets: TaskSecret[],
    created: string[],
  ): Promise<void> {
    const needsKey =
      (destination.config.protocol === "sftp" && Boolean(destination.config.privateKey)) ||
      destination.config.protocol === "gcs"
    if (!needsKey) return

    const keySecret = secretName("backup_key", runId)
    let material: string
    if (destination.config.protocol === "sftp") {
      material = destination.config.privateKey!
    } else if (destination.config.protocol === "gcs") {
      material = destination.config.serviceAccountJson
    } else {
      return
    }
    await this.deps.engine.upsertSecret(keySecret, material, {
      "bozando.backupRunId": runId,
    })
    created.push(keySecret)
    secrets.push({ secretName: keySecret, target: "/run/secrets/backup_key" })
  }

  private async removeSecrets(names: string[]): Promise<void> {
    for (const name of names) {
      await this.deps.engine.removeSecret(name).catch(() => undefined)
    }
  }

  private parseResult(logs: string): { sizeBytes: number; checksumSha256: string } | null {
    const line = logs
      .split(/\r?\n/)
      .reverse()
      .find((candidate) => candidate.includes(RESULT_MARKER))
    if (!line) return null
    const [, size, checksum] = line.trim().split(/\s+/)
    if (!size || !checksum) return null
    const sizeBytes = Number.parseInt(size, 10)
    if (!Number.isFinite(sizeBytes) || !/^[0-9a-f]{64}$/i.test(checksum)) return null
    return { sizeBytes, checksumSha256: checksum.toLowerCase() }
  }
}

/**
 * Probe de capacité d'une destination, exécutée dans un task one-shot.
 * Séquence : auth → write → stat → hash → move → delete (plan §9).
 */
export async function probeDestination(input: {
  engine: DockerEngineService
  image: string
  destination: ResolvedDestination
  timeoutSec?: number
}): Promise<{ ok: boolean; capabilities: Record<string, boolean>; logs: string }> {
  const executor = new SwarmTaskExecutor(input.engine)
  const runId = `probe${Date.now().toString(36)}`
  const remoteSecret = secretName("backup_probe", runId)
  const created: string[] = [remoteSecret]
  const probeKey = `.probe/${runId}`
  const script = [
    "set -euo pipefail",
    'REMOTE="$(cat /run/secrets/backup_remote)"',
    "READ=false; WRITE=false; DELETE=false; CHECKSUM=false; MOVE=false",
    'if rclone lsd "$REMOTE" >/dev/null 2>&1; then READ=true; fi',
    `if printf 'probe' | rclone rcat "$REMOTE/${probeKey}" >/dev/null 2>&1; then WRITE=true; fi`,
    'if [ "$WRITE" = true ]; then',
    `  if rclone hashsum sha256 "$REMOTE/${probeKey}" 2>/dev/null | grep -Eq '^[0-9a-f]{64}'; then CHECKSUM=true; fi`,
    `  if rclone moveto "$REMOTE/${probeKey}" "$REMOTE/${probeKey}.moved" >/dev/null 2>&1; then MOVE=true; fi`,
    `  if rclone deletefile "$REMOTE/${probeKey}" >/dev/null 2>&1; then DELETE=true; fi`,
    `  rclone deletefile "$REMOTE/${probeKey}.moved" >/dev/null 2>&1 || true`,
    "fi",
    'printf "HULLBAY_PROBE read=%s write=%s delete=%s checksum=%s move=%s\\n" "$READ" "$WRITE" "$DELETE" "$CHECKSUM" "$MOVE"',
  ].join("\n")

  try {
    const needsKey =
      (input.destination.config.protocol === "sftp" &&
        Boolean(input.destination.config.privateKey)) ||
      input.destination.config.protocol === "gcs"
    const secrets: TaskSecret[] = [
      { secretName: remoteSecret, target: "/run/secrets/backup_remote" },
    ]
    if (needsKey) {
      const keySecret = secretName("backup_probe_key", runId)
      const material =
        input.destination.config.protocol === "sftp"
          ? input.destination.config.privateKey!
          : input.destination.config.protocol === "gcs"
            ? input.destination.config.serviceAccountJson
            : ""
      await input.engine.upsertSecret(keySecret, material, {
        "bozando.backupRunId": runId,
      })
      created.push(keySecret)
      secrets.push({ secretName: keySecret, target: "/run/secrets/backup_key" })
    }

    await input.engine.upsertSecret(
      remoteSecret,
      buildRcloneRemoteString({
        protocol: input.destination.protocol,
        config: input.destination.config,
        basePath: input.destination.basePath,
        secretFiles: {
          privateKey: needsKey ? "/run/secrets/backup_key" : undefined,
          serviceAccountJson: needsKey ? "/run/secrets/backup_key" : undefined,
        },
      }),
      { "bozando.backupRunId": runId },
    )
    const logs = await executor.run({
      runId,
      suffix: "probe",
      script,
      secrets,
      image: input.image,
      timeoutSec: input.timeoutSec ?? 60,
    })
    const line = logs.split(/\r?\n/).reverse().find((l) => l.includes("HULLBAY_PROBE"))
    const caps = { read: false, write: false, delete: false, checksum: false, move: false }
    if (line) {
      for (const pair of line.trim().split(/\s+/).slice(1)) {
        const [key, value] = pair.split("=")
        if (key && key in caps) caps[key as keyof typeof caps] = value === "true"
      }
    }
    return {
      ok: caps.read && caps.write && caps.delete,
      capabilities: {
        ...caps,
        atomicCommit: caps.move,
        serverSideEncryption: false,
      },
      logs,
    }
  } finally {
    for (const name of created) {
      await input.engine.removeSecret(name).catch(() => undefined)
    }
  }
}
