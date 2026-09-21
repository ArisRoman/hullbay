/**
 * Politique MFA, effective sur le rôle.
 * Une MFA fournie par l'IdP SSO ne doit PAS imposer une 2e MFA locale, SAUF si
 * SecurityPolicy.mfaRequireRoles l'exige (rôle concerné). La politique est
 * persistée par tenant (modèle SecurityPolicy), lue depuis la DB et
 * mise en cache par tenant.
 */

import { securityPolicy } from "../policies/security-policy.service"
import { DEFAULT_TENANT_ID } from "../identity/auth-identity.service"

export interface MfaDecision {
  requireLocalMfa: boolean
  reason: string
}

export function shouldRequireLocalMfa(input: {
  providerKind: string
  role?: string
  /** Tenant effectif : la politique MFA se lit par tenant,
   *  pas sur le singleton par défaut. Login SSO sans contexte tenant → défaut. */
  tenantId?: string
}): MfaDecision {
  // Compte local : TOTP imposé (règle de base, inchangée).
  if (input.providerKind === "local") {
    return { requireLocalMfa: true, reason: "compte-local" }
  }
  // SSO : pas de 2e MFA locale SAUF rôle ciblé par la politique du tenant.
  const { mfaRequireRoles } = securityPolicy.getPolicyCached(input.tenantId ?? DEFAULT_TENANT_ID)
  if (input.role && mfaRequireRoles.includes(input.role.toLowerCase())) {
    return { requireLocalMfa: true, reason: "mfa-role-exige-mfa-locale" }
  }
  return { requireLocalMfa: false, reason: "mfa-idp-fournie" }
}
