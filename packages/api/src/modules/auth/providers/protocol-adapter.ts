/**
 * Fabrique le bon adapter de protocole pour un enregistrement AuthProvider.
 * Phase 2 : local. Phase 3 : local + oidc + oauth2. Phase 4 : + saml.
 * `config` porte les paramètres du protocole (jamais de secrets en dur ici —
 * ils sont injectés via la config du provider, chiffrés au stockage dur Phase 5A).
 */

import type { AuthProviderContract, ProviderKind } from "./types"
import { LocalProvider } from "./local/local-provider"
import { createOidcProvider, type OidcProviderOptions } from "./oidc/oidc-provider"
import { createOauth2Provider, type Oauth2ProviderOptions } from "./oauth2/oauth2-provider"
import { createSamlProvider, type SamlProviderOptions } from "./saml/saml-provider"

export type ProviderConfig =
  | OidcProviderOptions
  | Oauth2ProviderOptions
  | SamlProviderOptions

export function createProvider(kind: ProviderKind, id: string, config?: ProviderConfig): AuthProviderContract {
  switch (kind) {
    case "local":
      return new LocalProvider(id)
    case "oidc":
      if (!config) throw new Error("adapter oidc : config manquante (issuer/clientId/redirectUri)")
      return createOidcProvider({ ...(config as OidcProviderOptions), id })
    case "oauth2":
      if (!config) throw new Error("adapter oauth2 : config manquante")
      return createOauth2Provider({ ...(config as Oauth2ProviderOptions), id })
    case "saml":
      if (!config) throw new Error("adapter saml : config manquante (idpCert/idpIssuer/entryPoint/callbackUrl)")
      return createSamlProvider({ ...(config as SamlProviderOptions), id })
    case "ldap":
      throw new Error(`adapter ${kind} non implémenté (implémentation Phase 5A)`)
    default:
      throw new Error(`protocole inconnu : ${kind}`)
  }
}