#!/usr/bin/env node
/**
 * Rotation des secrets chiffrés (Phase 5A1, §8 du plan) — idempotent.
 *
 * Ré-chiffre progressivement, PAR ENREGISTREMENT et PAR CHAMP, les secrets des
 * scopes mfa et provider avec une NOUVELLE clé, sans down-time ni big-bang :
 *
 *   scopes couverts :
 *     - provider : AuthProvider.config — clients secrets OIDC/OAuth2 chiffrés
 *                  individuellement (champs SENSITIVE_FIELDS_BY_KIND)
 *     - mfa      : AuthIdentity.mfaSecretEnc (TOTP)
 *
 * Variables requises :
 *   - PROVIDER_SECRET_KEY_NEW / MFA_ENCRYPTION_KEY_NEW : NOUVELLE clé (64 hex)
 *   - PROVIDER_SECRET_KEY    / MFA_ENCRYPTION_KEY      : clé COURANTE (fallback
 *     JWT_SECRET si absente, comme à la lecture)
 *   - {KEY}_PREVIOUS (optionnel) : clé précédente à conserver le temps de la
 *     bascule (compat descendante : payloads encore chiffrés à l'ancienne clé).
 *
 * Après un premier passage, les payloads W+ portent l'empreinte `k<fp>:…` de la
 * NOUVELLE clé → les passages suivants sont des no-ops (idempotent). La bascule
 * effective de l'environnement (clés courantes = nouvelles) peut se faire prudence
 * gardée : tant qu'un ancien payload traîne, *_{PREVIOUS} le déchiffre encore.
 *
 * Les secrets ne transitent JAMAIS en clair dans les logs — seuls des compteurs
 * (tournés/skip/échecs) et des refs d'enregistrement sont affichés.
 *
 * Exécution : `npm run secrets:rotate -w @hullbay/api`
 */
import { readFileSync, existsSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto"

// ── .env du package api (même mécanique que backfill-identity.mjs) ──
const apiDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..")
if (!process.env.DATABASE_URL && existsSync(resolve(apiDir, ".env"))) {
  for (const line of readFileSync(resolve(apiDir, ".env"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "")
  }
}

const { PrismaClient } = await import("@prisma/client")
const prisma = new PrismaClient()

const SCOPES = {
  provider: {
    env: "PROVIDER_SECRET_KEY",
    newKey: () => envHex("PROVIDER_SECRET_KEY_NEW"),
    label: "PROVIDER",
  },
  mfa: {
    env: "MFA_ENCRYPTION_KEY",
    newKey: () => envHex("MFA_ENCRYPTION_KEY_NEW"),
    label: "MFA",
  },
}

function envHex(name) {
  const v = process.env[name]
  return v && /^[0-9a-fA-F]{64}$/.test(v) ? v : undefined
}

/** Clé courante du scope (fallback JWT_SECRET, identique au service TS). */
function currentKey(rawName) {
  const hex = envHex(rawName)
  if (hex) return hex
  return createHash("sha256").update(process.env.JWT_SECRET || "dev-insecure-key").digest("hex")
}

function fingerprintOf(keyHex) {
  return createHash("sha256").update(keyHex, "hex").digest("hex").slice(0, 16)
}

/** Encrypt AES-256-GCM au format du service : `[k<fp>:]iv:tag:enc`. */
function encryptPlain(plain, keyHex) {
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv)
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  const body = `${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`
  return keyHex ? `k${fingerprintOf(keyHex)}:${body}` : body
}

/** Decrypt conforme au service : tente clé courante, puis *_PREVIOUS. Retourne plain | null. */
function decryptPayload(payload, currentHex, previousHex) {
  for (const keyHex of [currentHex, previousHex]) {
    if (!keyHex) continue
    try {
      return decryptInternal(payload, keyHex)
    } catch {
      // essai suivant
    }
  }
  return null
}

function canDecrypt(payload, keyHex) {
  if (!keyHex) return false
  try {
    decryptInternal(payload, keyHex)
    return true
  } catch {
    return false
  }
}

function decryptInternal(payload, keyHex) {
  const parts = payload.split(":")
  let ivHex, tagHex, dataHex
  if (/^k[0-9a-f]{16}$/.test(parts[0] ?? "") && parts.length === 6) {
    ivHex = parts[2]
    tagHex = parts[3]
    dataHex = parts[4]
  } else if (parts.length === 3) {
    ;[ivHex, tagHex, dataHex] = parts
  } else {
    throw new Error("format secret invalide")
  }
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), Buffer.from(ivHex, "hex"))
  decipher.setAuthTag(Buffer.from(tagHex, "hex"))
  return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8")
}

const SENSITIVE_BY_KIND = { oidc: ["clientSecret"], oauth2: ["clientSecret"], saml: [], local: [], ldap: [] }

/**
 * Rotation d'un champ chiffré : renvoie "rotated" | "skipped" | "failed".
 * - skipped si déjà chiffré avec la NOUVELLE clé (empreinte = idempotent)
 * - rotated sinon (déchiffre avec la clé courante, ré-chiffre avec la nouvelle)
 */
function rotateField(payload, currentHex, newHex, previousHex) {
  if (payload.includes(":") && payload.startsWith(`k${fingerprintOf(newHex)}:`)) return "skipped"
  const plain = decryptPayload(payload, currentHex, previousHex)
  if (plain === null) return "failed"
  return encryptPlain(plain, newHex)
}

async function main() {
  const t0 = Date.now()
  const stats = { provider: { rotated: 0, skipped: 0, failed: 0 }, mfa: { rotated: 0, skipped: 0, failed: 0 } }

  // ── Scope provider : AuthProvider.config (champ sensible par champ) ──
  const prov = SCOPES.provider
  const provCurrent = currentKey(prov.env)
  const provNew = prov.newKey()
  const provPrevious = envHex(`${prov.env}_PREVIOUS`)
  if (!provNew) throw new Error(`[rotate] ${prov.env}_NEW manquant — rotation "provider" impossible`)

  const providers = await prisma.authProvider.findMany()
  for (const row of providers) {
    const config = (row.config ?? {})
    const fields = SENSITIVE_BY_KIND[row.kind] ?? []
    let changed = false
    for (const field of fields) {
      const val = config[field]
      if (typeof val !== "string" || !val.includes(":")) continue
      const out = rotateField(val, provCurrent, provNew, provPrevious)
      if (out === "failed") {
        stats.provider.failed++
        console.warn(`[rotate] provider=${row.id} champ=${field} ÉCHEC (indéchiffrable — vérifie *_PREVIOUS)`)
      } else if (out === "skipped") {
        stats.provider.skipped++
      } else {
        config[field] = out
        changed = true
        stats.provider.rotated++
      }
    }
    if (changed) {
      await prisma.authProvider.update({ where: { id: row.id }, data: { config } })
    }
  }

  // ── Scope mfa : AuthIdentity.mfaSecretEnc ──
  const mfa = SCOPES.mfa
  const mfaCurrent = currentKey(mfa.env)
  const mfaNew = mfa.newKey()
  const mfaPrevious = envHex(`${mfa.env}_PREVIOUS`)
  if (!mfaNew) throw new Error(`[rotate] ${mfa.env}_NEW manquant — rotation "mfa" impossible`)

  // Boucle paginée (progressif, pas de big-bang) : 200 par lot.
  let cursor = ""
  while (true) {
    const page = await prisma.authIdentity.findMany({
      where: cursor ? { id: { gt: cursor } } : {},
      select: { id: true, mfaSecretEnc: true },
      orderBy: { id: "asc" },
      take: 200,
    })
    if (page.length === 0) break
    for (const idn of page) {
      if (!idn.mfaSecretEnc) continue
      const out = rotateField(idn.mfaSecretEnc, mfaCurrent, mfaNew, mfaPrevious)
      if (out === "failed") {
        stats.mfa.failed++
        console.warn(`[rotate] identity=${idn.id} mfaSecretEnc ÉCHEC`)
      } else if (out === "skipped") {
        stats.mfa.skipped++
      } else {
        await prisma.authIdentity.update({ where: { id: idn.id }, data: { mfaSecretEnc: out } })
        stats.mfa.rotated++
      }
      cursor = idn.id
    }
  }

  const ms = Date.now() - t0
  console.log(
    `[rotate] provider: ${stats.provider.rotated} tournés, ${stats.provider.skipped} skip, ${stats.provider.failed} échecs`,
  )
  console.log(
    `[rotate] mfa: ${stats.mfa.rotated} tournés, ${stats.mfa.skipped} skip, ${stats.mfa.failed} échecs`,
  )
  console.log(`[rotate] terminé en ${ms} ms — idempotent (relancer sans effet si *_{NEW} inchangées)`)
}

main()
  .catch((err) => {
    console.error("[rotate] ERREUR :", err)
    process.exitCode = 1
  })
  .finally(() => prisma.$disconnect())