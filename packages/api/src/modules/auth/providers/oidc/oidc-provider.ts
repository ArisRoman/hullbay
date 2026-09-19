/**
 * Provider OIDC générique (§15, Phase 3).
 *
 * UN SEUL adapter pour TOUS les émetteurs OIDC (Keycloak, Google, Okta…) :
 * aucune logique `if(provider===…)`, aucun id vendor en dur. La validation
 * repose UNIQUEMENT sur la config (issuer attendu, clientId, redirectUri) +
 * discovery + JWKS. Le double-issuer = DEUX instances OidcProvider avec des
 * configs distinctes — jamais de branche par iss dans le code.
 *
 * Fail-closed :
 * - state consommé une seule fois (anti-replay, TTL 10 min, cf. core/auth-state)
 * - nonce émis au initiateLogin, vérifié dans l'id_token, consommé
 * - PKCE S256 ; code_verifier stocké dans l'enregistrement state
 * - signature RS256 via JWKS (kid apparié), iss/aud/exp vérifiés
 * - discovery : `issuer` document == issuer configuré (sinon refus)
 *
 * Le flux redirect n'a pas d'`authenticate()` : la méthode est implémentée
 * pour respecter AuthProviderContract (§5.1) mais lève systématiquement —
 * le chemin réel est initiateLogin → callback (§15.7/15.9 du plan).
 */

import jwt from "jsonwebtoken"
import type {
  AuthProviderContract,
  AuthInput,
  AuthResult,
  ExternalIdentity,
  ProviderPublicConfig,
} from "../types"
import { AuthError } from "../types"
import { computeCodeChallenge, generateCodeVerifier, publicKeyFromJwk } from "./oidc-crypto"
import { oidcStateStore, type OidcStateRecord } from "../../core/auth-state"

const STATE_TTL_MS = 10 * 60 * 1000
// Cache discovery/JWKS borné : rotation de clés reprise sans restart (TTL 5 min).
const DISCOVERY_TTL_MS = 5 * 60 * 1000

export interface OidcProviderOptions {
  id: string
  enabled: boolean
  /** Nom d'affichage (colonne AuthProvider.name) ; défaut = host de l'issuer. */
  name?: string
  /** Issuer attendu — comparé au discovery ET à l'iss de l'id_token. */
  issuer: string
  clientId: string
  clientSecret?: string
  redirectUri: string
  scopes?: string
  /** Discovery URL ; défaut = issuer + "/.well-known/openid-configuration". */
  discoveryUrl?: string
  /** JWKS URI en surcharge (tests/fixtures). Sinon celle du discovery. */
  jwksUri?: string
  /** Tolérance d'horloge entre ce SP et l'IdP, ms (C8). Défaut 30000 ms —
   *  évite les faux négatifs si l'horloge de l'IdP dérive de quelques secondes. */
  acceptedClockSkewMs?: number
  /** fetch injectable (tests fixtures) ; défaut = fetch global. */
  fetchFn?: typeof fetch
}

interface OidcDiscovery {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint?: string
  jwks_uri: string
}

interface OidcJwk {
  kty?: string
  kid?: string
  n?: string
  e?: string
}

interface IdTokenClaims extends jwt.JwtPayload {
  iss?: string
  sub?: string
  email?: string
  name?: string
  nonce?: string
}

function defaultDiscoveryUrl(issuer: string): string {
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer
  return `${base}/.well-known/openid-configuration`
}

export class OidcProvider implements AuthProviderContract {
  readonly id: string
  readonly kind = "oidc" as const
  readonly enabled: boolean
  private readonly options: OidcProviderOptions
  private readonly fetchFn: typeof fetch
  private discoveryCache: { value: OidcDiscovery; expiresAt: number } | null = null
  private jwksCache: { value: OidcJwk[]; expiresAt: number } | null = null

  constructor(options: OidcProviderOptions) {
    this.id = options.id
    this.enabled = options.enabled
    this.options = options
    this.fetchFn = options.fetchFn ?? ((...args) => fetch(...args))
  }

  getConfig(): ProviderPublicConfig {
    return {
      id: this.id,
      kind: "oidc",
      name: this.options.name?.trim() || this.options.issuer.split("//")[1]?.split("/")[0] || "OIDC",
      enabled: this.enabled,
    }
  }

  /**
   * Flux redirect OIDC — pas de credentials directes. Lève toujours :
   * le contrat exige authenticate(), le chemin réel est initiateLogin/callback.
   */
  authenticate(_input: AuthInput): Promise<AuthResult> {
    return Promise.reject(
      new AuthError("invalid_credentials", "OIDC : flux redirect (initiateLogin/callback) requis", 400),
    )
  }

  /**
   * initiateLogin (§15.7) : discovery fail-closed, PKCE + state + nonce stockés,
   * redirige vers authorization_endpoint. Ne crée JAMAIS d'identité.
   */
  async initiateLogin(req: unknown, _reply: unknown): Promise<void> {
    const discovery = await this.resolveDiscovery()

    const codeVerifier = generateCodeVerifier()
    const codeChallenge = computeCodeChallenge(codeVerifier)
    const nonce = generateCodeVerifier()

    const state = oidcStateStore.put(
      {
        providerId: this.id,
        redirectUri: this.options.redirectUri,
        codeVerifier,
        nonce,
      },
      STATE_TTL_MS,
    )

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      scope: this.options.scopes ?? "openid profile email",
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    })

    const authorizeUrl = `${discovery.authorization_endpoint}?${params.toString()}`
    ;(req as { ssoAuthorizeUrl?: string }).ssoAuthorizeUrl = authorizeUrl
  }

  /**
   * callback (§15.9) : consomme state (anti-replay), échange code→tokens PKCE,
   * valide l'id_token (iss=issuer attendu, aud=clientId, exp, signature RS256
   * via JWKS apparié par kid, nonce) puis retourne l'identité externe.
   * La résolution ExternalIdentity → User/Pending est faite par sso-callback
   * via identity-mapping (fail-closed, jamais d'auto-création ici).
   */
  async callback(req: unknown, raw: unknown): Promise<ExternalIdentity> {
    void req
    const input = raw as { code?: string; state?: string; redirectUri?: string }

    if (!input.code || !input.state) {
      throw new AuthError("invalid_credentials", "callback OIDC : code/state manquants", 400)
    }

    const stateValue = oidcStateStore.consume(input.state)
    if (!stateValue) {
      throw new AuthError("invalid_credentials", "callback OIDC : state absent, expiré ou déjà consommé (anti-replay)", 400)
    }
    if (stateValue.providerId !== this.id) {
      throw new AuthError("invalid_credentials", "callback OIDC : state d'un autre provider", 400)
    }
    if (stateValue.redirectUri !== this.options.redirectUri) {
      throw new AuthError("invalid_credentials", "callback OIDC : redirect_uri du state invalide", 400)
    }

    const discovery = await this.resolveDiscovery()
    const jwks = await this.resolveJwks()

    const tokenResponse = await this.exchangeCode(input.code, stateValue, discovery)
    if (!tokenResponse.id_token) {
      throw new AuthError("invalid_credentials", "callback OIDC : id_token absent", 400)
    }

    const claims = await this.verifyIdToken(tokenResponse.id_token, jwks, stateValue.nonce)

    return {
      providerId: this.id,
      kind: "oidc",
      issuer: claims.iss ?? this.options.issuer,
      subject: claims.sub ?? "",
      email: claims.email,
      name: claims.name,
      emailVerified: claims.email_verified === true,
    }
  }

  private async exchangeCode(
    code: string,
    stateValue: OidcStateRecord,
    discovery: OidcDiscovery,
  ): Promise<{ id_token?: string; access_token?: string }> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.options.redirectUri,
      client_id: this.options.clientId,
      code_verifier: stateValue.codeVerifier,
    })
    if (this.options.clientSecret) {
      body.set("client_secret", this.options.clientSecret)
    }

    const res = await this.fetchFn(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    })
    if (!res.ok) {
      throw new AuthError("invalid_credentials", "échange code→tokens OIDC refusé", 400)
    }
    return (await res.json()) as { id_token?: string; access_token?: string }
  }

  private async verifyIdToken(
    idToken: string,
    jwks: OidcJwk[],
    expectedNonce: string,
  ): Promise<IdTokenClaims> {
    let header: { kid?: string } = {}
    try {
      const decoded = jwt.decode(idToken, { complete: true })
      header = (decoded as { header?: { kid?: string } })?.header ?? {}
    } catch {
      // header illisible → pas de kid ; on retombe sur l'appariement par défaut
    }

    const key = selectJwk(jwks, header.kid)
    const publicKey = publicKeyFromJwk(makeJsonWebKeyRsa(key))

    let decoded: IdTokenClaims
    try {
      decoded = jwt.verify(idToken, publicKey, {
        algorithms: ["RS256"],
        issuer: this.options.issuer,
        audience: this.options.clientId,
        clockTolerance: this.options.acceptedClockSkewMs ?? 30000,
      }) as IdTokenClaims
    } catch {
      throw new AuthError("invalid_credentials", "id_token invalide (signature/iss/aud/exp)", 400)
    }

    if (!decoded.sub) {
      throw new AuthError("invalid_credentials", "id_token sans sub", 400)
    }
    if (decoded.nonce !== expectedNonce) {
      throw new AuthError("invalid_credentials", "id_token : nonce invalide (anti-replay)", 400)
    }

    return decoded
  }

  private async resolveDiscovery(): Promise<OidcDiscovery> {
    if (this.discoveryCache && Date.now() < this.discoveryCache.expiresAt) return this.discoveryCache.value
    const url = this.options.discoveryUrl ?? defaultDiscoveryUrl(this.options.issuer)

    const res = await this.fetchFn(url)
    if (!res.ok) {
      throw new AuthError("invalid_credentials", "discovery OIDC injoignable", 400)
    }
    const doc = (await res.json()) as OidcDiscovery
    if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.issuer || !doc.jwks_uri) {
      throw new AuthError("invalid_credentials", "discovery OIDC incomplète (fail-closed)", 400)
    }
    // L'issuer du document DOIT être celui configuré : jamais de découverte sauvage.
    if (doc.issuer !== this.options.issuer) {
      throw new AuthError("invalid_credentials", "discovery OIDC : issuer inattendu (fail-closed)", 400)
    }
    this.discoveryCache = { value: doc, expiresAt: Date.now() + DISCOVERY_TTL_MS }
    return doc
  }

  private async resolveJwks(): Promise<OidcJwk[]> {
    if (this.jwksCache && Date.now() < this.jwksCache.expiresAt) return this.jwksCache.value
    const jwksUri = this.options.jwksUri ?? (await this.resolveDiscovery()).jwks_uri

    const res = await this.fetchFn(jwksUri)
    if (!res.ok) {
      throw new AuthError("invalid_credentials", "JWKS OIDC injoignable", 400)
    }
    const jwks = (await res.json()) as { keys?: OidcJwk[] }
    if (!jwks.keys?.length) {
      throw new AuthError("invalid_credentials", "JWKS sans clé (fail-closed)", 400)
    }
    this.jwksCache = { value: jwks.keys, expiresAt: Date.now() + DISCOVERY_TTL_MS }
    return this.jwksCache.value
  }
}

/** Apparie une clé JWKS au kid du token. kid présent non apparié → refus fail-closed. */
function selectJwk(keys: OidcJwk[], kid?: string): OidcJwk {
  if (kid) {
    const match = keys.find((k) => k.kid === kid && k.kty === "RSA")
    if (match) return match
    throw new AuthError("invalid_credentials", "id_token : kid non apparié dans la JWKS (fail-closed)", 400)
  }
  const fallback = keys.find((k) => k.kty === "RSA" && k.n && k.e)
  if (!fallback) throw new AuthError("invalid_credentials", "JWKS sans clé RSA (fail-closed)", 400)
  return fallback
}

function makeJsonWebKeyRsa(key: OidcJwk): { kty: "RSA"; kid?: string; n: string; e: string } {
  if (!key.n || !key.e) {
    throw new AuthError("invalid_credentials", "JWKS : clé sans paramètres RSA", 400)
  }
  return { kty: "RSA", kid: key.kid, n: key.n, e: key.e }
}

export function createOidcProvider(options: OidcProviderOptions): OidcProvider {
  return new OidcProvider(options)
}