#!/usr/bin/env node
/**
 * Backfill multi-tenancy (Phase 5B) — idempotent (peut s'exécuter plusieurs fois).
 *
 * Étape 0 : crée le tenant par défaut ("Default"/"default") si absent.
 * Étape 1 : backfill les lignes SANS tenantId vers le tenant par défaut. Dans le
 *   schéma actuel, seul AuditLog.tenantId est nullable (les autres tables portent
 *   la contrainte NOT NULL dès la migration d'expansion) — le script couvre donc
 *   AuditLog (cas DB de staging, lignes pré-multi-tenancy).
 * Étape 2 : dédup de Cluster — la contrainte @@unique([tenantId, name]) ne peut
 *   pas être posée si deux clusters de même nom partagent le tenant par défaut
 *   (issue entre le cluster existant et un éventuel "Default"). On renomme les
 *   doublons avant la contrainte.
 *
 * Exécution : `npm run backfill:tenant -w @hullbay/api`
 */
import { readFileSync, existsSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

// apiDir = packages/api ROOT : on remonte 4 niveaux (scripts → auth → modules → src → packages/api).
const apiDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..")
if (!process.env.DATABASE_URL && existsSync(resolve(apiDir, ".env"))) {
  for (const line of readFileSync(resolve(apiDir, ".env"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}

const { PrismaClient } = await import("@prisma/client")
const prisma = new PrismaClient()

const DEFAULT_TENANT_ID = "tenant-default"

async function main() {
  const t0 = Date.now()

  // ── Étape 0 : tenant par défaut ──
  const tenant =
    (await prisma.tenant.findUnique({ where: { id: DEFAULT_TENANT_ID } })) ??
    (await prisma.tenant.upsert({
      where: { id: DEFAULT_TENANT_ID },
      create: { id: DEFAULT_TENANT_ID, name: "Default", slug: "default" },
      update: {},
    }))
  console.log(`[backfill:tenant] tenant défaut ok (${tenant.id}, slug=${tenant.slug})`)

  // ── Étape 1 : backfill des lignes sans tenantId (AuditLog = seul nullable) ──
  const tables = ["auditLog"]
  for (const model of tables) {
    const rows = await prisma[model]
      .findMany({ where: { tenantId: null }, take: 10000 })
      .catch(() => [])
    let updated = 0
    for (const row of rows) {
      await prisma[model]
        .update({ where: { id: row.id }, data: { tenantId: DEFAULT_TENANT_ID } })
        .catch(() => {})
      updated++
    }
    console.log(`[backfill:tenant] ${model}: ${updated} lignes → tenant défaut`)
  }

  // ── Étape 2 : dédup Cluster (contrainte @@unique([tenantId, name])) ──
  const clusters = await prisma.cluster.findMany({
    orderBy: { createdAt: "asc" },
  })
  const seen = new Map()
  let renamed = 0
  for (const cluster of clusters) {
    const tenantKey = cluster.tenantId ?? DEFAULT_TENANT_ID
    const key = `${tenantKey}:${cluster.name}`
    const first = seen.get(key)
    if (!first) {
      seen.set(key, cluster)
      continue
    }
    // Doublon : on renomme le plus récent (le premier conservé garde son nom).
    const newName = `${cluster.name}-dup-${cluster.id.slice(0, 6)}`
    await prisma.cluster.update({ where: { id: cluster.id }, data: { name: newName } })
    renamed++
    console.log(
      `[backfill:tenant] cluster doublon "${cluster.name}" (${cluster.id}) → "${newName}"`,
    )
  }
  console.log(`[backfill:tenant] clusters renommés (dédup): ${renamed}`)

  console.log(
    `[backfill:tenant] terminé en ${Date.now() - t0} ms — idempotent (relancer sans effet)`,
  )
}

main()
  .catch((err) => {
    console.error("[backfill:tenant] ERREUR :", err)
    process.exitCode = 1
  })
  .finally(() => prisma.$disconnect())