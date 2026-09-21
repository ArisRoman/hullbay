/**
 * Hash/verification scrypt du mot de passe (déplacé depuis service.ts).
 * Règle : un hash factice (DUMMY_HASH) est vérifié quand l'email n'existe pas, pour
 * égaliser le coût de hachage et empêcher l'énumération par timing.
 */

import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto"

export function hashPassword(password: string, salt?: string): string {
  const s = salt ?? randomBytes(16).toString("hex")
  const derived = scryptSync(password, s, 64).toString("hex")
  return `${s}:${derived}`
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":")
  if (!salt || !hash) return false
  const derived = scryptSync(password, salt, 64)
  const expected = Buffer.from(hash, "hex")
  return derived.length === expected.length && timingSafeEqual(derived, expected)
}

// Hash factice vérifié quand l'email n'existe pas — coût identique au chemin "compte
// existant", pour ne pas révéler l'existence du compte par timing de réponse.
export const DUMMY_HASH = hashPassword("dummy-password-for-timing")
