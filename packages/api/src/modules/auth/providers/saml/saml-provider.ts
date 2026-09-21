/**
 * Provider SAML 2.0 générique.
 *
 * UN SEUL adapter pour TOUS les IdP SAML (Keycloak, Azure AD, Okta…) :
 * aucune branche `if(provider===…)`, aucun id vendor en dur. La config porte
 * le certificat de signature, l'entity Id IdP, le endpoint ACS (callbackUrl)
 * et le entryPoint (SSO URL). La validation repose sur node-saml qui gère
 * signature, issuer, audience, conditions (NotBefore/NotOnOrAfter + clock
 * skew), InResponseTo (cacheProvider) — et notre saml-replay store complète
 * avec empreinte anti-replay pour réponses sans InResponseTo.
 *
 * Fail-closed :
 * - signature assertion signée obligatoire (wantAssertionsSigned)
 * - issuer document == idpIssuer configuré
 * - audience == issuer SP
 * - InResponseTo toujours validé (validateInResponseTo: "always")
 * - empreinte SAMLResponse unique (anti-replay complet)
 *
 * Le flux SAML : GET /login (AuthnRequest redirect) → POST /acs (SAMLResponse).
 * POST /acs traite la réponse et retourne HTML token ou pending/erreur.
 * GET /metadata expose le SP metadata XML.
 */

import { SAML as SamlLib, type SamlConfig, ValidateInResponseTo, type CacheProvider } from "@node-saml/node-saml"
import * as xpath from "xpath"
import { DOMParser } from "@xmldom/xmldom"
import type {
  AuthProviderContract,
  AuthInput,
  AuthResult,
  ExternalIdentity,
  ProviderPublicConfig,
} from "../types"
import { AuthError } from "../types"
import { samlReplayStore } from "../../core/saml-replay"
import { samlStateStore, type SamlStateRecord } from "../../core/auth-state"

const STATE_TTL_MS = 10 * 60 * 1000

export interface SamlProviderOptions {
  id: string
  enabled: boolean
  /** Nom d'affichage (colonne AuthProvider.name) ; défaut = host de l'entryPoint. */
  name?: string
  /** Certificat X.509 PEM de l'IdP (utilisé pour valider la signature). */
  idpCert: string
  /** Entity ID du fournisseur d'identité (iss) — comparé au issuer de l'assertion. */
  idpIssuer: string
  /** Entity ID de l'application (SP) — utilisé comme issuer SP et audience. */
  spIssuer: string
  /** URL endpoint SSO de l'IdP (AuthnRequest redirect). */
  entryPoint: string
  /** URL callback ACS (où l'IdP envoie la POST SAMLResponse). */
  callbackUrl: string
  /** Audience attendue (défaut = spIssuer). */
  audience?: string
  /** Clock skew autorisé (défaut 60s). */
  acceptedClockSkewMs?: number
  /** CacheProvider InResponseTo injectable (tests) ; défaut = mémoire. */
  cacheProvider?: CacheProvider
}

export class SamlProvider implements AuthProviderContract {
  readonly id: string
  readonly kind = "saml" as const
  readonly enabled: boolean
  private readonly options: SamlProviderOptions
  private readonly samlLib: InstanceType<typeof SamlLib>

  constructor(options: SamlProviderOptions) {
    this.id = options.id
    this.enabled = options.enabled
    this.options = options

    const config: SamlConfig = {
      idpCert: options.idpCert,
      issuer: options.spIssuer,
      callbackUrl: options.callbackUrl,
      entryPoint: options.entryPoint,
      idpIssuer: options.idpIssuer,
      audience: options.audience ?? options.spIssuer,
      acceptedClockSkewMs: options.acceptedClockSkewMs ?? 60_000,
      wantAssertionsSigned: true,
      // Signé au niveau Assertion (comme Keycloak, défaut), pas du Response entier.
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always,
      identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }
    if (options.cacheProvider) config.cacheProvider = options.cacheProvider

    this.samlLib = new SamlLib(config)
  }

  getConfig(): ProviderPublicConfig {
    const host = this.options.entryPoint.split("//")[1]?.split("/")[0] ?? "SAML"
    return {
      id: this.id,
      kind: "saml",
      name: this.options.name?.trim() || host,
      enabled: this.enabled,
    }
  }

  /** Flux SAML = redirect → pas d'authenticate() direct. Lève toujours. */
  authenticate(_input: AuthInput): Promise<AuthResult> {
    return Promise.reject(
      new AuthError("invalid_credentials", "SAML : flux redirect (login/acs) requis", 400),
    )
  }

  /**
   * initiateLogin : génère l'AuthnRequest (AuthnRequest redirect) et retourne
   * l'URL via req.ssoAuthorizeUrl pour la route GET /saml/:id/login (302).
   * Le RelayState porte notre state interne (providerId + redirectUri).
   */
  async initiateLogin(req: unknown, _reply: unknown): Promise<void> {
    const state = samlStateStore.put(
      {
        providerId: this.id,
        redirectUri: this.options.callbackUrl,
      },
      STATE_TTL_MS,
    )

    const url = await this.samlLib.getAuthorizeUrlAsync(
      state, // RelayState = state ID
      undefined, // host (détecté depuis callbackUrl)
      {}, // AuthOptions (pas d'override)
    )

    ;(req as { ssoAuthorizeUrl?: string }).ssoAuthorizeUrl = url
  }

  /**
   * callback (ACS) : reçoit SAMLResponse + RelayState en POST, valide via
   * node-saml (signature/issuer/audience/conditions/InResponseTo), vérifie
   * l'empreinte anti-replay, et retourne l'identité externe.
   * La résolution → User/Pending est faite par sso-callback.ts (fail-closed,
   * jamais d'auto-création ici).
   */
  async callback(_req: unknown, raw: unknown): Promise<ExternalIdentity> {
    const input = raw as { SAMLResponse?: string; RelayState?: string }

    if (!input.SAMLResponse || !input.RelayState) {
      throw new AuthError("invalid_credentials", "callback SAML : SAMLResponse/RelayState manquants", 400)
    }

    // Anti-replay : empreinte SHA-256 de la réponse brute.
    samlReplayStore.mark(input.SAMLResponse)

    // Anti-replay state (RelayState) : vérifie providerId + redirectUri.
    const stateValue = samlStateStore.consume(input.RelayState)
    if (!stateValue) {
      throw new AuthError("invalid_credentials", "callback SAML : RelayState absent, expiré ou déjà consommé", 400)
    }
    if (stateValue.providerId !== this.id) {
      throw new AuthError("invalid_credentials", "callback SAML : RelayState d'un autre provider", 400)
    }

    // Validation node-saml (signature/issuer/audience/conditions/InResponseTo).
    let result: { profile: import("@node-saml/node-saml").Profile | null; loggedOut: boolean }
    try {
      result = await this.samlLib.validatePostResponseAsync({
        SAMLResponse: input.SAMLResponse,
        RelayState: input.RelayState,
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : "SAML validation failed"
      throw new AuthError("invalid_credentials", `SAML invalide (node-saml) : ${msg}`, 400)
    }

    // Destination / Recipient : node-saml NE les valide pas — le plan l'exige.
    this.validateDestination(input.SAMLResponse)

    if (result.loggedOut) {
      throw new AuthError("invalid_credentials", "callback SAML : réponse de déconnexion inattendue", 400)
    }

    const profile = result.profile
    if (!profile) {
      throw new AuthError("invalid_credentials", "callback SAML : assertion sans profil", 400)
    }

    // Issuer de l'assertion : node-saml ne le vérifie pas pour les POST
    // success (seulement les Logout) — contrôle fail-closed ici.
    if (profile.issuer !== this.options.idpIssuer) {
      throw new AuthError(
        "invalid_credentials",
        `callback SAML : issuer inattendu (${profile.issuer ?? "absent"})`,
        400,
      )
    }

    const subject = profile.nameID
    if (!subject) {
      throw new AuthError("invalid_credentials", "callback SAML : assertion sans NameID", 400)
    }

    const email =
      typeof profile.email === "string"
        ? profile.email
        : typeof profile.mail === "string"
          ? profile.mail
          : null

    return {
      providerId: this.id,
      kind: "saml",
      issuer: profile.issuer ?? this.options.idpIssuer,
      subject,
      email,
      name: profile.givenName as string | undefined,
    }
  }

  /**
   * Vérifie `Destination` (Response) et `Recipient` (SubjectConfirmationData)
   * == callbackUrl. node-saml ne les valide pas : un IdP honnête, mais aussi
   * un proxy malveillant, pourraient poster une assertion pour un autre ACS.
   * On vérifie donc à la main, fail-closed.
   */
  private validateDestination(base64Response: string): void {
    let doc: Document
    try {
      const xml = Buffer.from(base64Response, "base64").toString("utf8")
      doc = new DOMParser().parseFromString(xml, "text/xml")
    } catch {
      throw new AuthError("invalid_credentials", "SAML : XML illisible (destination)", 400)
    }

    const destAttr = xpath.select1("/*[local-name()='Response']", doc) as Element | null
    const destValue = destAttr?.getAttribute("Destination")
    if (destValue !== this.options.callbackUrl) {
      // Absent OU différent → rejeter. Spec SAML 2.0 exige Destination == ACS.
      throw new AuthError("invalid_credentials", "SAML : Destination ≠ ACS ou absente (fail-closed)", 400)
    }

    const recipientAttr = xpath.select1(
      "/*[local-name()='Response']/*[local-name()='Assertion']/*[local-name()='Subject']" +
        "/*[local-name()='SubjectConfirmation']/*[local-name()='SubjectConfirmationData']",
      doc,
    ) as Element | null
    const recipientValue = recipientAttr?.getAttribute("Recipient")
    if (recipientValue !== this.options.callbackUrl) {
      // Absent OU différent → rejeter. Recipient requis avec binding bearer.
      throw new AuthError("invalid_credentials", "SAML : Recipient ≠ ACS ou absent (fail-closed)", 400)
    }
  }

  /**
   * Génère le SP metadata XML (GET /api/auth/saml/:id/metadata).
   * Expose l'entity ID, le endpoint ACS, les certificats de signature.
   */
  getMetadata(): string {
    return this.samlLib.generateServiceProviderMetadata(null, null)
  }
}

export function createSamlProvider(options: SamlProviderOptions): SamlProvider {
  return new SamlProvider(options)
}
