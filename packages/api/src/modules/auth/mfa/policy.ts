/**
 * Politique MFA (stub Phase 2 → effectif Phase 5A).
 * Règle du plan §10 : une MFA fournie par l'IdP SSO ne doit PAS imposer une 2e MFA
 * locale, SAUF si SecurityPolicy.mfaRequireRoles l'exige (rôle concerné). En Phase 2,
 * le modèle SecurityPolicy n'existe pas encore (Phase 5A) : le stub impose la MFA
 * locale uniquement pour les comptes de type "local".
 */

export interface MfaDecision {
  requireLocalMfa: boolean
  reason: string
}

export function shouldRequireLocalMfa(input: {
  providerKind: string
  role?: string
}): MfaDecision {
  // Phase 5A : lire SecurityPolicy.mfaRequireRoles et décider selon le rôle.
  // Phase 2 : règle simple — tout compte local exige TOTP ; SSO (oidc/saml/ldap) = non.
  if (input.providerKind !== "local") {
    return { requireLocalMfa: false, reason: "mfa-idp-fournie" }
  }
  return { requireLocalMfa: true, reason: "compte-local" }
}
