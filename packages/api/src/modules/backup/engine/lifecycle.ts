import { randomUUID } from "node:crypto"
import type { BackupManifest, BackupRunPhase } from "@hullbay/shared"
import { scrubSecrets } from "../storage/remote-string"
import type { StorageProvider } from "../storage/types"
import type { ResolvedDestination } from "../storage/registry"
import { artifactPrefix, buildManifest, CHECKSUM_FILE, MANIFEST_FILE } from "../manifest"
import type { BackupStrategy, StrategyPlan, StrategyTarget } from "../strategies/types"

/**
 * Cycle de vie d'un backup.
 *
 * Invariant central : un artifact n'existe qu'après vérification ET commit.
 * `partial backup ≠ valid backup` — toute erreur avant le commit laisse zéro
 * artifact et ne peut jamais déclencher de rétention.
 */

export type RunTrigger = "manual" | "scheduled"

export interface ProducedArtifact {
  /** Clé du payload encore en staging. */
  payloadKey: string
  payloadFileName: string
  checksumSha256: string
  sizeBytes: number
}

export interface ArtifactProducer {
  /**
   * Vérification côté exécutant (le task Swarm n'a pas de provider in-process).
   * Retourne les mesures relues après transfert.
   */
  verify?(produced: ProducedArtifact): Promise<{
    sizeBytes: number
    checksumSha256: string
  }>
  /** Commit distant : staging → clé finale, manifest écrit en dernier. */
  commit?(ctx: {
    produced: ProducedArtifact
    destination: ResolvedDestination
    finalPrefix: string
    manifest: BackupManifest
  }): Promise<void>
  /** Nettoyage du staging après échec. */
  cleanup?(stagingPrefix: string): Promise<void>
  produce(ctx: {
    runId: string
    artifactId: string
    /** Préfixe de staging imposé par le moteur (nettoyé dans tous les cas). */
    stagingPrefix: string
    destination: ResolvedDestination
    provider?: StorageProvider
    target: StrategyTarget
    plan: StrategyPlan
    onPhase: (phase: BackupRunPhase) => Promise<void>
  }): Promise<ProducedArtifact>
}

export interface RunStore {
  createRun(policyId: string, trigger: RunTrigger): Promise<{ id: string }>
  setPhase(runId: string, phase: BackupRunPhase): Promise<void>
  complete(runId: string, sizeBytes: number): Promise<void>
  fail(runId: string, errorCode: string, errorMessage: string): Promise<void>
  createArtifact(input: {
    runId: string
    targetId: string
    destinationId: string
    storageKey: string
    manifestJson: BackupManifest
    payloadFormat: string
    checksumSha256: string
    sizeBytes: number
    engine: string
    engineVersion: string
    strategyId: string
    formatVersion: number
  }): Promise<{ id: string }>
}

export interface LifecycleInput {
  policyId: string
  targetId: string
  destinationId: string
  projectSlug: string
  trigger: RunTrigger
  strategy: BackupStrategy
  target: StrategyTarget
  destination: ResolvedDestination
  /** Absent pour un runner distant (le stockage n'est pas monté dans l'API). */
  provider?: StorageProvider
  producer: ArtifactProducer
  verification: "size" | "checksum"
}

export type LifecycleResult =
  | { ok: true; runId: string; artifactId: string; sizeBytes: number }
  | { ok: false; runId: string; errorCode: string }

export class BackupError extends Error {
  readonly logs?: string
  readonly exitCode?: number

  constructor(
    readonly code: string,
    message: string,
    details: { logs?: string; exitCode?: number } = {},
  ) {
    super(message)
    this.name = "BackupError"
    this.logs = details.logs
    this.exitCode = details.exitCode
  }
}

/** Déplace un objet ; dégrade en copy+verify+delete si le backend l'exige. */
export async function moveOrCopy(
  provider: StorageProvider,
  from: string,
  to: string,
  expectedChecksum?: string,
): Promise<"atomic-rename" | "copy-verify-delete"> {
  if (await provider.move(from, to)) return "atomic-rename"

  const sourceHash = expectedChecksum ?? (await provider.hash(from))
  await provider.put(to, await provider.get(from))
  if (sourceHash) {
    const copied = await provider.hash(to)
    if (copied !== sourceHash) {
      await provider.delete(to).catch(() => undefined)
      throw new BackupError("commit_failed", "copie distante non vérifiée")
    }
  }
  await provider.delete(from)
  return "copy-verify-delete"
}

async function cleanupStaging(
  provider: StorageProvider,
  prefix: string,
): Promise<void> {
  try {
    for (const object of await provider.list(prefix)) {
      await provider.delete(object.key).catch(() => undefined)
    }
  } catch {
    // Best-effort : un staging résiduel est inerte (sans manifest, il n'est
    // jamais listé comme artifact restaurable).
  }
}

export class BackupLifecycle {
  constructor(private readonly store: RunStore) {}

  async execute(input: LifecycleInput): Promise<LifecycleResult> {
    const run = await this.store.createRun(input.policyId, input.trigger)
    const artifactId = `bak_${randomUUID()}`
    const stagingPrefix = `.staging/${run.id}`
    let produced: ProducedArtifact | undefined
    // Objet mutable : une variable locale serait figée par le narrowing de TS
    // alors que la phase change dans les callbacks du producteur.
    const state: { phase: BackupRunPhase } = { phase: "resolving" }

    const onPhase = async (next: BackupRunPhase) => {
      state.phase = next
      await this.store.setPhase(run.id, next)
    }

    try {
      await onPhase("resolving")

      const prereq = input.strategy.verifyPrereqs(input.target)
      if (!prereq.ok) {
        throw new BackupError(
          "prereq_failed",
          prereq.reason ?? "prérequis non satisfaits",
        )
      }
      const plan = input.strategy.backup(input.target)

      await onPhase("extracting")
      produced = await input.producer.produce({
        runId: run.id,
        artifactId,
        stagingPrefix,
        destination: input.destination,
        provider: input.provider,
        target: input.target,
        plan,
        onPhase,
      })

      await onPhase("verifying")
      if (input.producer.verify) {
        const evidence = await input.producer.verify(produced)
        if (evidence.sizeBytes !== produced.sizeBytes) {
          throw new BackupError(
            "verify_failed",
            `taille relue ${evidence.sizeBytes} ≠ ${produced.sizeBytes}`,
          )
        }
        if (
          input.verification === "checksum" &&
          evidence.checksumSha256 !== produced.checksumSha256
        ) {
          throw new BackupError("checksum_mismatch", "checksum relu différent")
        }
      } else {
        if (!input.provider) {
          throw new BackupError("verify_failed", "aucun vérificateur disponible")
        }
        const stat = await input.provider.stat(produced.payloadKey)
        if (!stat) {
          throw new BackupError("verify_failed", "payload absent du stockage")
        }
        if (stat.size !== produced.sizeBytes) {
          throw new BackupError(
            "verify_failed",
            `taille distante ${stat.size} ≠ ${produced.sizeBytes}`,
          )
        }
        if (input.verification === "checksum") {
          const remoteHash = await input.provider.hash(produced.payloadKey)
          // Backend sans hash natif : la vérification retombe sur la taille,
          // information consignée dans le run (jamais silencieuse côté code).
          if (remoteHash && remoteHash !== produced.checksumSha256) {
            throw new BackupError("checksum_mismatch", "checksum distant différent")
          }
        }
      }

      await onPhase("committing")
      const finalPrefix = artifactPrefix(
        input.destination.basePath,
        input.projectSlug,
        input.target.name,
        artifactId,
      )
      const manifest = buildManifest({
        artifactId,
        runId: run.id,
        target: {
          nodeId: input.target.nodeId,
          name: input.target.name,
          kind: input.target.kind,
        },
        source: {
          engine: input.target.engine,
          engineVersion: input.target.engineVersion,
          host: input.target.host,
          port: input.target.port,
          database: input.target.database,
          username: input.target.username,
        },
        strategy: {
          id: input.strategy.id,
          version: input.strategy.version,
          tool: plan.tool,
          toolVersion: plan.toolVersion,
        },
        payload: {
          path: produced.payloadFileName,
          format: plan.payloadFormat,
          sizeBytes: produced.sizeBytes,
        },
        checksumSha256: produced.checksumSha256,
        encryptionMode: "none",
        commitMode:
          input.provider && !input.provider.capabilities().atomicCommit
            ? "copy-verify-delete"
            : "atomic-rename",
        restore: {
          strategyId: input.strategy.id,
          command: plan.restoreCommand,
          requires: plan.requires,
        },
      })

      if (input.producer.commit) {
        await input.producer.commit({
          produced,
          destination: input.destination,
          finalPrefix,
          manifest,
        })
      } else {
        if (!input.provider) {
          throw new BackupError("commit_failed", "aucun writer disponible")
        }
        await moveOrCopy(
          input.provider,
          produced.payloadKey,
          `${finalPrefix}/${produced.payloadFileName}`,
          produced.checksumSha256,
        )
        await input.provider.put(
          `${finalPrefix}/${CHECKSUM_FILE}`,
          Buffer.from(
            `${produced.checksumSha256}  ${produced.payloadFileName}\n`,
            "utf8",
          ),
        )
        // Le manifest est écrit EN DERNIER : sa présence vaut commit.
        await input.provider.put(
          `${finalPrefix}/${MANIFEST_FILE}`,
          Buffer.from(JSON.stringify(manifest, null, 2), "utf8"),
        )
      }

      const artifact = await this.store.createArtifact({
        runId: run.id,
        targetId: input.targetId,
        destinationId: input.destinationId,
        storageKey: finalPrefix,
        manifestJson: manifest,
        payloadFormat: plan.payloadFormat,
        checksumSha256: produced.checksumSha256,
        sizeBytes: produced.sizeBytes,
        engine: input.target.engine,
        engineVersion: input.target.engineVersion,
        strategyId: input.strategy.id,
        formatVersion: manifest.formatVersion,
      })

      await onPhase("done")
      await this.store.complete(run.id, produced.sizeBytes)

      return {
        ok: true,
        runId: run.id,
        artifactId: artifact.id,
        sizeBytes: produced.sizeBytes,
      }
    } catch (error) {
      const code =
        error instanceof BackupError
          ? error.code
          : state.phase === "verifying"
            ? "verify_failed"
            : "backup_failed"
      const message = scrubSecrets(
        error instanceof Error ? error.message : String(error),
      )
      await this.store.fail(run.id, code, message)
      // Le staging est nettoyé même si le producteur a échoué avant de rendre
      // la main : le préfixe appartient au moteur, pas au producteur.
      if (input.producer.cleanup) {
        await input.producer.cleanup(stagingPrefix).catch(() => undefined)
      } else if (input.provider) {
        await cleanupStaging(input.provider, stagingPrefix)
      }
      return { ok: false, runId: run.id, errorCode: code }
    }
  }
}
