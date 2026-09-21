/**
 * Opérations TOTP (déplacées depuis service.ts) — generateSecret, generateURI, verify.
 * Fonctionnellement identique à l'ancien code (otplib v13), isolé du reste du service
 * pour permettre des tests unitaires purs de ce facteur.
 */

import { generateSecret as otplibGenerateSecret, generateURI, verify } from "otplib"

export { generateSecret } from "otplib"

export interface TotpEnrollment {
  otpauth: string
  secret: string
}

/** Construit l'URI otpauth:// à partir d'un secret existant (pas de régénération). */
export function totpUri(issuer: string, label: string, secret: string): string {
  return generateURI({
    strategy: "totp",
    issuer,
    label,
    secret,
  })
}

export function startTotpEnrollment(
  issuer: string,
  label: string,
): TotpEnrollment {
  const secret = otplibGenerateSecret({ length: 20 })
  return { otpauth: totpUri(issuer, label, secret), secret }
}

/**
 * Vérifie un code TOTP contre un secret brut (plain-text).
 * Retourne true si le code est valide (tolérance : epochTolerance 30 s par défaut).
 */
export async function verifyTotpCode(
  secret: string,
  code: string,
): Promise<boolean> {
  const result = await verify({ token: code, secret, epochTolerance: 30 })
  return result.valid
}
