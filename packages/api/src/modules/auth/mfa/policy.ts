/**
 * Politique MFA (Phase 2 : stub local → Phase 5A1 : effectif sur le rôle).
 * Règle du plan §10 : une MFA fournie par l'IdP SSO ne doit PAS imposer une 2e MFA
 * locale, SAUF si SecurityPolicy.mfaRequireRoles l'exige (rôle concerné).
 * En 5A2, la politique est persistée par tenant (modèle SecurityPolicy) — le
 * singleton lit l'env jusqu'à ce que le chargement tenant soit branché.
 */

import { securityPolicy } from "../policies/security-policy.service"

export interface MfaDecision {
  requireLocalMfa: boolean
  reason: string
}

export function shouldRequireLocalMfa(input: {
  providerKind: string
  role?: string
}): MfaDecision {
  // Compte local : TOTP imposé (règle de base, inchangée).
  if (input.providerKind === "local") {
    return { requireLocalMfa: true, reason: "compte-local" }
  }
  // SSO : pas de 2e MFA locale SAUF rôle ciblé par la politique.
  const { mfaRequireRoles } = securityPolicy.getPolicy()
  if (input.role && mfaRequireRoles.includes(input.role.toLowerCase())) {
    return { requireLocalMfa: true, reason: "mfa-role-exige-mfa-locale" }
  }
  return { requireLocalMfa: false, reason: "mfa-idp-fournie" }
}
