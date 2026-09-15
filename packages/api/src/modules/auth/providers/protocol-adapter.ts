/**
 * Fabrique le bon adapter de protocole pour un enregistrement AuthProvider.
 * Phase 2 : seul `local` est implémenté. oidc/oauth2/saml/ldap = stubs lancés
 * en Phase 3/4/5A (interfaces posées ici, pas d'impl vendor).
 */

import type { AuthProviderContract, ProviderKind } from "./types"
import { LocalProvider } from "./local/local-provider"

export function createProvider(kind: ProviderKind, id: string): AuthProviderContract {
  switch (kind) {
    case "local":
      return new LocalProvider(id)
    case "oidc":
    case "oauth2":
    case "saml":
    case "ldap":
      throw new Error(`adapter ${kind} non implémenté (implémentation Phase 3/4/5A)`)
    default:
      throw new Error(`protocole inconnu : ${kind}`)
  }
}
