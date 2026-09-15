/**
 * Seeds du Provider Registry : configurations de base (Phase 2).
 * Aucun fournisseur commercial privilégié — local est un provider comme les autres.
 * Les presets oidc/saml/ldap sont désactivés (implémentation Phase 3/4/5A).
 * Aucune clé vendor par défaut (correctif N°4, N°7 du plan).
 */

import type { ProviderKind } from "../providers/types"

export interface ProviderSeed {
  id: string
  kind: ProviderKind
  name: string
  enabled: boolean
}

export const PROVIDER_SEEDS: ProviderSeed[] = [
  { id: "local", kind: "local", name: "Local", enabled: true },
  { id: "oidc-generic", kind: "oidc", name: "OIDC", enabled: false },
  { id: "oauth2-generic", kind: "oauth2", name: "OAuth2", enabled: false },
  { id: "saml-generic", kind: "saml", name: "SAML", enabled: false },
  { id: "ldap-generic", kind: "ldap", name: "LDAP", enabled: false },
]

export const DEFAULT_TENANT = { name: "Default", slug: "default" } as const
