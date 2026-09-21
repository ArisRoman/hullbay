/**
 * Fabrique le bon adapter de protocole pour un enregistrement AuthProvider.
 * Kinds supportés : local, oidc, oauth2, saml, ldap (+ passkeys via webauthn).
 * `config` porte les paramètres du protocole (jamais de secrets en dur ici —
 * ils sont injectés via la config du provider, chiffrés au stockage).
 */

import type { AuthProviderContract, ProviderKind } from "./types"
import { LocalProvider } from "./local/local-provider"
import { createOidcProvider, type OidcProviderOptions } from "./oidc/oidc-provider"
import { createOauth2Provider, type Oauth2ProviderOptions } from "./oauth2/oauth2-provider"
import { createSamlProvider, type SamlProviderOptions } from "./saml/saml-provider"
import { createLdapProvider, type LdapProviderOptions } from "./ldap/ldap-provider"

export type ProviderConfig =
  | OidcProviderOptions
  | Oauth2ProviderOptions
  | SamlProviderOptions
  | LdapProviderOptions

export function createProvider(kind: ProviderKind, id: string, config?: ProviderConfig): AuthProviderContract {
  switch (kind) {
    case "local":
      return new LocalProvider(id)
    case "oidc":
      if (!config) throw new Error("Configuration OIDC manquante (issuer/clientId/redirectUri)")
      return createOidcProvider({ ...(config as OidcProviderOptions), id })
    case "oauth2":
      if (!config) throw new Error("Configuration OAuth2 manquante (authorizationUri/tokenUri/userinfoUri/clientId/redirectUri)")
      return createOauth2Provider({ ...(config as Oauth2ProviderOptions), id })
    case "saml":
      if (!config) throw new Error("Configuration SAML manquante (idpCert/idpIssuer/entryPoint/callbackUrl)")
      return createSamlProvider({ ...(config as SamlProviderOptions), id })
    case "ldap":
      if (!config) throw new Error("Configuration LDAP manquante (url/searchBase/searchFilter/stableAttr)")
      return createLdapProvider({ ...(config as LdapProviderOptions), id })
    default:
      throw new Error(`Protocole inconnu : ${kind}`)
  }
}
