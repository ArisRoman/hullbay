/**
 * Seeds du Provider Registry : configurations de base (Phase 2/3).
 * Aucun fournisseur commercial privilégié — local est un provider comme les autres.
 * Les presets oidc/oauth2/saml/ldap sont désactivés (implémentation Phase 3/4/5A).
 * Aucune clé vendor par défaut (correctif N°4, N°7 du plan).
 *
 * Test IdP (Keycloak) : JAMAIS un défaut. Il n'est enregistré QUE si les
 * variables d'env de test sont présentes (e2e/CI) — une simple configuration,
 * pas un pilier du modèle (correction N°7).
 */

import type { ProviderKind } from "../providers/types"
import type { ProviderConfig } from "../providers/protocol-adapter"

export interface ProviderSeed {
  id: string
  kind: ProviderKind
  name: string
  enabled: boolean
  /** Configuration du protocole (uniquement pour les providers actifs). */
  config?: ProviderConfig
}

export const PROVIDER_SEEDS: ProviderSeed[] = [
  { id: "local", kind: "local", name: "Local", enabled: true },
  { id: "oidc-generic", kind: "oidc", name: "OIDC", enabled: false },
  { id: "oauth2-generic", kind: "oauth2", name: "OAuth2", enabled: false },
  { id: "saml-generic", kind: "saml", name: "SAML", enabled: false },
  { id: "ldap-generic", kind: "ldap", name: "LDAP", enabled: false },
]

/**
 * Provider OIDC "test" (Keycloak en e2e/CI). Actif uniquement si OIDC_TEST_*
 * renseignées — jamais par défaut, jamais en prod sans config explicite.
 */
export function loadTestOidcSeed(): ProviderSeed | null {
  const issuer = process.env.OIDC_TEST_ISSUER
  const clientId = process.env.OIDC_TEST_CLIENT_ID
  if (!issuer || !clientId) return null

  const enabled = process.env.OIDC_TEST_ENABLED === "true"
  const port = process.env.OIDC_TEST_PORT ?? "8080"
  const base = new URL(issuer.startsWith("http") ? issuer : `http://localhost:${port}/realms/hullbay`)

  return {
    id: "oidc-test",
    kind: "oidc",
    name: "Keycloak (test)",
    enabled,
    config: {
      issuer: base.toString().replace(/\/$/, ""),
      discoveryUrl: `${base.toString().replace(/\/$/, "")}/.well-known/openid-configuration`,
      clientId,
      clientSecret: process.env.OIDC_TEST_CLIENT_SECRET,
      redirectUri:
        process.env.OIDC_TEST_REDIRECT_URI ??
        `http://localhost:${process.env.API_PORT ?? "4000"}/api/auth/sso/oidc-test/callback`,
      scopes: "openid profile email",
    } as ProviderConfig,
  }
}

export const DEFAULT_TENANT = { name: "Default", slug: "default" } as const