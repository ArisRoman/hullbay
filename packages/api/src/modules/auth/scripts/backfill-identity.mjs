#!/usr/bin/env node
/**
 * Backfill identité — idempotent (peut s'exécuter plusieurs fois).
 *
 * Étape 0 : crée le tenant par défaut ("Default"/"default").
 * Étape 1 : pour chaque User existant → AuthIdentity(local) + Membership(default tenant).
 *   — les credentials existants (passwordHash/mfaSecretEnc/mfaEnabled) N'ONT PAS à être
 *     recopiés ici : ils ont été migrés en SQL (INSERT...SELECT de la migration) ; ce
 *     script assure la cohérence des comptes sans identité, sans écraser quoi que ce soit.
 * Étape 2 : seeds des providers (local enabled, presets désactivés, aucun vendor).
 *
 * Exécution : `npm run backfill:identity -w @hullbay/api`
 */
import { readFileSync, existsSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

// Charge .env du package api si DATABASE_URL n'est pas déjà dans l'environnement.
    // apiDir = packages/api ROOT, pas src/modules/auth : ce script vit dans
    // scripts/ sous la racine du package, donc on remonte 4 niveaux
    // (scripts → auth → modules → src → packages/api) pour lire le VRAI .env
    // du package. (Bug corrigé : `.env` était cherché dans src/modules/auth/.)
    const apiDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..")
if (!process.env.DATABASE_URL && existsSync(resolve(apiDir, ".env"))) {
  for (const line of readFileSync(resolve(apiDir, ".env"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}

const { PrismaClient } = await import("@prisma/client")
const prisma = new PrismaClient()

const DEFAULTS = {
  tenant: { name: "Default", slug: "default" },
  providers: [
    { kind: "local", name: "Local", enabled: true, config: "{}" },
    { kind: "oidc", name: "OIDC", enabled: false, config: "{}" },
    { kind: "oauth2", name: "OAuth2", enabled: false, config: "{}" },
    { kind: "saml", name: "SAML", enabled: false, config: "{}" },
    { kind: "ldap", name: "LDAP", enabled: false, config: "{}" },
  ],
}

async function main() {
  const t0 = Date.now()

  // ── Étape 0 : tenant par défaut ──
  const tenant = await prisma.tenant.upsert({
    where: { slug: DEFAULTS.tenant.slug },
    create: DEFAULTS.tenant,
    update: {},
  })
  console.log(`[backfill] tenant par défaut ok (${tenant.id}, slug=${tenant.slug})`)

  // ── Étape 1 : identités locales + memberships ──
  // NB : les passwordHash/mfaSecretEnc/mfaEnabled existants ont été migrés dans
  // auth_identities par la MIGRATION SQL elle-même (INSERT...SELECT). Ce script
  // ne fait qu'assurer la cohérence (idempotent) pour les comptes sans identité.
  const users = await prisma.user.findMany()
  let created = 0
  for (const user of users) {
    const subject = `local:${user.id}`

    const existingIdentity = await prisma.authIdentity.findFirst({
      where: { providerId: "local", subject },
    })
    if (!existingIdentity) {
      await prisma.authIdentity.create({
        data: {
          userId: user.id,
          providerId: "local",
          kind: "local",
          issuer: null,
          subject,
          email: user.email ?? undefined,
        },
      })
      created++
    }

    await prisma.membership.upsert({
      where: { userId_tenantId: { userId: user.id, tenantId: tenant.id } },
      create: { userId: user.id, tenantId: tenant.id, role: user.role },
      update: {},
    })
  }
  console.log(`[backfill] identités créées: ${created}/${users.length} (users: ${users.length})`)

  // ── Étape 2 : seeds providers (idempotent) ──
  let providerCount = 0
  for (const seed of DEFAULTS.providers) {
    const existing = await prisma.authProvider.findFirst({
      where: { kind: seed.kind },
    })
    if (!existing) {
      await prisma.authProvider.create({ data: seed })
      providerCount++
    }
  }
  console.log(`[backfill] providers créés: ${providerCount} (aucun vendor default)`)

  console.log(`[backfill] terminé en ${Date.now() - t0} ms — idempotent (relancer sans effet)`)
}

main()
  .catch((err) => {
    console.error("[backfill] ERREUR :", err)
    process.exitCode = 1
  })
  .finally(() => prisma.$disconnect())