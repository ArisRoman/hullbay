import { beforeEach, describe, expect, it, vi } from "vitest"
import type { BackupManifest } from "@hullbay/shared"
import type { DockerEngineService } from "../../docker-engine/service"
import { SwarmBackupRunner } from "../runner"
import type { ResolvedDestination } from "../storage/registry"
import { postgresStrategy } from "../strategies/postgres"

const checksum = "c".repeat(64)

const destination: ResolvedDestination = {
  protocol: "s3",
  basePath: "hullbay",
  config: {
    protocol: "s3",
    bucket: "backups",
    accessKeyId: "AKIA",
    secretAccessKey: "super-secret",
    useTls: true,
    pathStyle: false,
  },
}

const target = {
  nodeId: "n1",
  name: "orders-db",
  kind: "postgres" as const,
  engine: "postgres",
  engineVersion: "16",
  host: "boz_shop_db",
  port: 5432,
  database: "orders",
  username: "app",
  passwordSecretRef: "orders_db_password",
}

type FakeTask = {
  Status?: { State?: string }
  ContainerStatus?: { ExitCode?: number }
}

function fakeEngine(logs = `HULLBAY_BACKUP_RESULT 42 ${checksum}`) {
  return {
    upsertSecret: vi.fn(async () => "secret-id"),
    removeSecret: vi.fn(async () => undefined),
    createService: vi.fn(async () => ({ ID: "svc_1" })),
    listServiceTasks: vi.fn(async (): Promise<FakeTask[]> => [{ Status: { State: "complete" } }]),
    serviceLogs: vi.fn(async () => logs),
    removeService: vi.fn(async () => undefined),
  }
}

function makeRunner(engine: DockerEngineService) {
  return new SwarmBackupRunner({
    engine,
    image: "ghcr.io/hullbay/backup-runner:latest",
    networkName: "boz_shop_orders-db-net",
    timeoutSec: 30,
    pollMs: 1,
  })
}

describe("SwarmBackupRunner.produce", () => {
  let engine: ReturnType<typeof fakeEngine>

  beforeEach(() => {
    engine = fakeEngine()
  })

  it("transfère en streaming et retourne la taille + le checksum", async () => {
    const produced = await makeRunner(engine as unknown as DockerEngineService).produce({
      runId: "run_1",
      artifactId: "bak_1",
      stagingPrefix: ".staging/run_1",
      destination,
      target,
      plan: postgresStrategy.backup(target),
      onPhase: async () => undefined,
    })

    expect(produced).toMatchObject({ sizeBytes: 42, checksumSha256: checksum })
    expect(produced.payloadKey).toBe(".staging/run_1/payload.sql.gz")
  })

  it("ne met aucun credential dans l'env ni la commande du service", async () => {
    await makeRunner(engine as unknown as DockerEngineService).produce({
      runId: "run_1",
      artifactId: "bak_1",
      stagingPrefix: ".staging/run_1",
      destination,
      target,
      plan: postgresStrategy.backup(target),
      onPhase: async () => undefined,
    })

    const [, config, , networks, mounts] = (engine.createService as ReturnType<typeof vi.fn>).mock
      .calls[0]!
    expect(JSON.stringify(config.env)).not.toContain("super-secret")
    expect(JSON.stringify(config.cmd)).not.toContain("super-secret")
    expect(JSON.stringify(config.cmd)).toContain("rclone rcat")
    expect(config.cmd).toContain("/bin/bash")
    expect(config.restartPolicy).toBe("no")
    expect(networks).toEqual(["boz_shop_orders-db-net"])
    expect(mounts).toEqual([])
  })

  it("monte le secret DB par référence, sans le recopier", async () => {
    await makeRunner(engine as unknown as DockerEngineService).produce({
      runId: "run_1",
      artifactId: "bak_1",
      stagingPrefix: ".staging/run_1",
      destination,
      target,
      plan: postgresStrategy.backup(target),
      onPhase: async () => undefined,
    })
    const [, config] = (engine.createService as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(config.secrets).toContainEqual({
      secretName: "orders_db_password",
      target: "/run/secrets/db_password",
    })
    expect(config.env.DB_PASSWORD_FILE).toBe("/run/secrets/db_password")
  })

  it("nettoie toujours le service et les secrets", async () => {
    await makeRunner(engine as unknown as DockerEngineService).produce({
      runId: "run_1",
      artifactId: "bak_1",
      stagingPrefix: ".staging/run_1",
      destination,
      target,
      plan: postgresStrategy.backup(target),
      onPhase: async () => undefined,
    })
    expect(engine.removeService).toHaveBeenCalledWith("svc_1")
    expect(engine.removeSecret).toHaveBeenCalled()
  })

  it("échoue si le task ne rend pas de résultat exploitable", async () => {
    const broken = fakeEngine("bruit sans marqueur")
    await expect(
      makeRunner(broken as unknown as DockerEngineService).produce({
        runId: "run_1",
        artifactId: "bak_1",
        stagingPrefix: ".staging/run_1",
        destination,
        target,
        plan: postgresStrategy.backup(target),
        onPhase: async () => undefined,
      }),
    ).rejects.toThrow(/résultat exploitable/)
  })

  it("classe un exit 3 en prereq_failed", async () => {
    engine.listServiceTasks.mockResolvedValue([
      { Status: { State: "failed" }, ContainerStatus: { ExitCode: 3 } },
    ])
    engine.serviceLogs.mockResolvedValue("pg_dump 14 < serveur 16")
    await expect(
      makeRunner(engine as unknown as DockerEngineService).produce({
        runId: "run_1",
        artifactId: "bak_1",
        stagingPrefix: ".staging/run_1",
        destination,
        target,
        plan: postgresStrategy.backup(target),
        onPhase: async () => undefined,
      }),
    ).rejects.toMatchObject({ code: "prereq_failed" })
  })

  it("classe une erreur rclone en destination_unreachable et purge les secrets des logs", async () => {
    engine.listServiceTasks.mockResolvedValue([{ Status: { State: "failed" } }])
    engine.serviceLogs.mockResolvedValue(
      "rclone: Failed to create file: dial tcp 10.0.0.1:443: connect: connection refused ,secret_access_key=super-secret",
    )
    const error = await makeRunner(engine as unknown as DockerEngineService)
      .produce({
        runId: "run_1",
        artifactId: "bak_1",
        stagingPrefix: ".staging/run_1",
        destination,
        target,
        plan: postgresStrategy.backup(target),
        onPhase: async () => undefined,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ code: "destination_unreachable" })
    expect((error as { logs?: string }).logs).not.toContain("super-secret")
  })
})

describe("SwarmBackupRunner.commit", () => {
  it("écrit le manifest en dernier, après le move et le checksum", async () => {
    const engine = fakeEngine()
    const manifest: BackupManifest = {
      formatVersion: 1,
      artifactId: "bak_1",
      runId: "run_1",
      createdAt: "2026-10-25T10:00:00.000Z",
      target: { nodeId: "n1", name: "orders-db", kind: "postgres" },
      source: {
        engine: "postgres",
        engineVersion: "16",
        host: "boz_shop_db",
        port: 5432,
        username: "app",
      },
      strategy: { id: "postgres.pg_dump", version: 1, tool: "pg_dump", toolVersion: "16" },
      payload: { path: "payload.sql.gz", format: "sql.gz", sizeBytes: 42 },
      checksum: { algorithm: "sha256", value: checksum },
      encryption: { mode: "none" },
      commit: { mode: "atomic-rename" },
      restore: { strategyId: "postgres.pg_dump", command: "psql", requires: {} },
    }

    await makeRunner(engine as unknown as DockerEngineService).commit({
      produced: {
        payloadKey: ".staging/run_1/payload.sql.gz",
        payloadFileName: "payload.sql.gz",
        checksumSha256: checksum,
        sizeBytes: 42,
      },
      destination,
      finalPrefix: "hullbay/shop/orders-db/bak_1",
      manifest,
    })

    const [, config] = (engine.createService as ReturnType<typeof vi.fn>).mock.calls[0]!
    const script = (config.cmd as string[])[2]!
    expect(script.indexOf("rclone moveto")).toBeLessThan(script.indexOf("manifest.json"))
    expect(script).toContain("hashsum sha256")
    expect(config.secrets).toContainEqual({
      secretName: "backup_manifest_run_1",
      target: "/run/secrets/backup_manifest",
    })
    expect(engine.removeService).toHaveBeenCalled()
  })

  it("classe un exit 4 (checksum distant) en checksum_mismatch", async () => {
    const engine = fakeEngine()
    engine.listServiceTasks.mockResolvedValue([
      { Status: { State: "failed" }, ContainerStatus: { ExitCode: 4 } },
    ])
    engine.serviceLogs.mockResolvedValue("checksum distant different")
    const manifest = { runId: "run_1" } as BackupManifest

    await expect(
      makeRunner(engine as unknown as DockerEngineService).commit({
        produced: {
          payloadKey: ".staging/run_1/payload.sql.gz",
          payloadFileName: "payload.sql.gz",
          checksumSha256: checksum,
          sizeBytes: 42,
        },
        destination,
        finalPrefix: "hullbay/shop/orders-db/bak_1",
        manifest,
      }),
    ).rejects.toMatchObject({ code: "checksum_mismatch" })
  })

  it("classe un échec de commit non identifiable en commit_failed", async () => {
    const engine = fakeEngine()
    engine.listServiceTasks.mockResolvedValue([{ Status: { State: "failed" } }])
    engine.serviceLogs.mockResolvedValue("erreur inconnue")
    const manifest = { runId: "run_1" } as BackupManifest

    await expect(
      makeRunner(engine as unknown as DockerEngineService).commit({
        produced: {
          payloadKey: ".staging/run_1/payload.sql.gz",
          payloadFileName: "payload.sql.gz",
          checksumSha256: checksum,
          sizeBytes: 42,
        },
        destination,
        finalPrefix: "hullbay/shop/orders-db/bak_1",
        manifest,
      }),
    ).rejects.toMatchObject({ code: "commit_failed" })
  })
})
