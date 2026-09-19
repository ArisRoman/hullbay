#!/usr/bin/env node
/**
 * Backfill membership (Correction A3) — idempotent (relançable sans effet).
 *
 * Objectif : éliminer la dépendance au miroir `User.role` dans la résolution de
 * rôle (auth-identity.service.ts) en garantissant que CHAQUE User existant a une
 * membership dans le tenant par défaut — role = (membership déjà présente) sinon
 * `User.role` (miroir legacy).
 *
 *   User sans membership  →  membership(tenant-default, role = User.role)
 *   User avec membership  →  inchangé (jamais d'écrasement)
 *
 * À exécuter AVANT la montée des gardes fail-closed A1/A2 : une fois lancé, le
 * fallback `User.role` ne couvre plus que les comptes réellement orphelins
 * (cas dégradé), plus jamais le tenant par défaut entier.
 *
 * Exécution : `npm run backfill:membership -w @hullbay/api`
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

  // Tenant par défaut garanti (jamais d'échec si absence).
  const tenant =
    (await prisma.tenant.findUnique({ where: { id: DEFAULT_TENANT_ID } })) ??
    (await prisma.tenant.upsert({
      where: { id: DEFAULT_TENANT_ID },
      create: { id: DEFAULT_TENANT_ID, name: "Default", slug: "default" },
      update: {},
    }))
  console.log(`[backfill:membership] tenant défaut ok (${tenant.id}, slug=${tenant.slug})`)

  const users = await prisma.user.findMany({ select: { id: true, role: true } })
  const memberships = await prisma.membership.findMany({
    where: { tenantId: DEFAULT_TENANT_ID },
    select: { userId: true },
  })
  const hasDefault = new Set(memberships.map((m) => m.userId))

  let created = 0
  const skipped = []
  for (const user of users) {
    if (hasDefault.has(user.id)) {
      skipped.push(user.id)
      continue
    }
    await prisma.membership.create({
      data: { userId: user.id, tenantId: DEFAULT_TENANT_ID, role: user.role },
    })
    created++
  }

  console.log(
    `[backfill:membership] memberships créées: ${created}/${users.length} (déjà présentes: ${skipped.length} — inchangées)`,
  )
  if (created > 0) {
    console.log(`[backfill:membership] comptes orphelins → tenant défaut avec leur role User.role legacy`)
  }
  console.log(`[backfill:membership] terminé en ${Date.now() - t0} ms — idempotent (relancer sans effet)`)
}

main()
  .catch((err) => {
    console.error("[backfill:membership] ERREUR :", err)
    process.exitCode = 1
  })
  .finally(() => prisma.$disconnect())