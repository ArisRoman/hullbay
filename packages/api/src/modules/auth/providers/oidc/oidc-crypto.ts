/**
 * Primitives OIDC/OAuth2 sans dépendance vendor (Phase 3, §15 du plan).
 * node:crypto uniquement. La vérif RS256 passe par jsonwebtoken + construction
 * de clé publique depuis JWK (node:crypto).
 *
 * Les stores state/nonce/PKCE vivent DANS core/auth-state.ts (AuthStateStore,
 * TTL + consommation unique) — pas de duplication ici. Ce module ne garde que
 * les primitives pures : PKCE, constant-time, JWK → PEM, encodage base64url.
 */

import { createHash, createPublicKey, randomBytes } from "node:crypto"

// ── PKCE (RFC 7636) ──

export function generateCodeVerifier(): string {
  return base64url(randomBytes(48))
}

export function computeCodeChallenge(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest())
}

// ── construction de clé publique depuis JWK (RS256) ──

export interface JsonWebKeyRsa {
  kty: "RSA"
  kid?: string
  n: string
  e: string
}

export function publicKeyFromJwk(jwk: JsonWebKeyRsa): string {
  try {
    const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" })
    return key.export({ type: "spki", format: "pem" }).toString()
  } catch {
    throw new Error("JWK_RS256_INVALIDE : impossibilité de construire la clé publique")
  }
}

/** Encodage base64url strict (rejette padding illégal). */
export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url")
}