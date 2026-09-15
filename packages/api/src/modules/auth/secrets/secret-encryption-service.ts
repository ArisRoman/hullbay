/**
 * SecretEncryptionService : chiffrement/déchiffrement AES-256-GCM séparé par
 * domaine (MFA / PROVIDER / SESSION) — clé indépendante par scope pour permettre
 * une rotation indépendante (§8 du plan).
 *
 * Les appels existants (auth/service, registry/service, lib/keys, lib/ssh-tunnel,
 * workflows) passent par la façade compat encryptSecret/decryptSecret → scope "mfa".
 */

import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto"

export type SecretKind = "mfa" | "provider" | "session"

const SECRET_CONFIG: Record<SecretKind, { envKey: string; label: string }> = {
  mfa:      { envKey: "MFA_ENCRYPTION_KEY",      label: "MFA" },
  provider: { envKey: "PROVIDER_SECRET_KEY",      label: "PROVIDER" },
  session:  { envKey: "SESSION_SIGNING_KEY",       label: "SESSION" },
}

function keyFor(kind: SecretKind): Buffer {
  const hex = process.env[SECRET_CONFIG[kind].envKey]
  if (hex && /^[0-9a-fA-F]{64}$/.test(hex)) {
    return Buffer.from(hex, "hex")
  }
  const fallback = process.env.JWT_SECRET || "dev-insecure-key"
  return createHash("sha256").update(fallback).digest()
}

function encrypt(kind: SecretKind, plain: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", keyFor(kind), iv)
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`
}

function decrypt(kind: SecretKind, payload: string): string {
  const [ivHex, tagHex, dataHex] = payload.split(":")
  if (!ivHex || !tagHex || !dataHex) throw new Error("format secret invalide")
  const decipher = createDecipheriv("aes-256-gcm", keyFor(kind), Buffer.from(ivHex, "hex"))
  decipher.setAuthTag(Buffer.from(tagHex, "hex"))
  return Buffer.concat([
    decipher.update(Buffer.from(dataHex, "hex")),
    decipher.final(),
  ]).toString("utf8")
}

/** Chiffre les champs sensibles d'un objet (utilisé pour AuthProvider.config). */
export function encryptObject<T extends Record<string, unknown>>(
  config: T,
  sensitiveFields: string[],
): T {
  const copy = { ...config } as Record<string, unknown>
  for (const field of sensitiveFields) {
    const val = copy[field]
    if (typeof val === "string" && val.length > 0) {
      copy[field] = encrypt("provider", val)
    }
  }
  return copy as T
}

/** Déchiffre les champs sensibles d'un objet (utilisé pour AuthProvider.config). */
export function decryptObject<T extends Record<string, unknown>>(
  config: T,
  sensitiveFields: string[],
): T {
  const copy = { ...config } as Record<string, unknown>
  for (const field of sensitiveFields) {
    const val = copy[field]
    if (typeof val === "string" && val.includes(":")) {
      copy[field] = decrypt("provider", val)
    }
  }
  return copy as T
}

/**
 * Rotation de clé (stub Phase 5A) : ré-chiffre progressivement tous les secrets
 * d'un scope avec une nouvelle clé, sans down-time.
 */
export function rotate(_kind: SecretKind): void {
  // implémentation Phase 5A (re-chiffrement incrémental par enregistrement)
}

// ── Façade compat (§8 du plan) ──
// Les appels existants (auth/service, registry/service, lib/keys, lib/ssh-tunnel,
// workflows) conservent leur interface d'origine. La clé utilisée reste celle du
// scope "mfa" pour assurer la compatibilité descendante avec les données existantes.
export function encryptSecret(plain: string): string {
  return encrypt("mfa", plain)
}

export function decryptSecret(storage: string): string {
  return decrypt("mfa", storage)
}
