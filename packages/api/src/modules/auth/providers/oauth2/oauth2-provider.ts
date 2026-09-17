/**
 * Provider OAuth2 générique (autorization_code) — flux "GitHub-style" (§15.2).
 *
 * Configuration = endpoints explicites (authorizationUri, tokenUri, userinfoUri),
 * clientId/secret, scopes, groupAttr optionnel. Aucune intégration vendor :
 * GitHub, GitLab, Facebook… passent par la MÊME classe avec des configs.
 *
 * Fail-closed : state consommé une seule fois (TTL, cf. core/auth-state),
 * échange code→access_token avec client_secret, userinfo obligatoire (échec
 * si injoignable ou si aucun sub/id stable). issuer = null (pas de notion
 * d'issuer en OAuth2) : l'identité stable = (providerId, subject=user id).
 *
 * Comme OIDC : pas d'`authenticate()` — initiateLogin → callback (§15.2).
 */

import type {
  AuthProviderContract,
  AuthInput,
  AuthResult,
  ExternalIdentity,
  ProviderPublicConfig,
} from "../types"
import { AuthError } from "../types"
import { oauth2StateStore, type Oauth2StateRecord } from "../../core/auth-state"

const STATE_TTL_MS = 10 * 60 * 1000

export interface Oauth2ProviderOptions {
  id: string
  enabled: boolean
  /** Nom d'affichage (colonne AuthProvider.name) ; défaut = host d'autorisation. */
  name?: string
  authorizationUri: string
  tokenUri: string
  userinfoUri: string
  clientId: string
  clientSecret: string
  redirectUri: string
  scopes?: string
  /** Chemin de l'attribut "groupes" dans la réponse userinfo (ex: "groups"). */
  groupAttr?: string
  /** fetch injectable (tests fixtures) ; défaut = fetch global. */
  fetchFn?: typeof fetch
}

export class Oauth2Provider implements AuthProviderContract {
  readonly id: string
  readonly kind = "oauth2" as const
  readonly enabled: boolean
  private readonly options: Oauth2ProviderOptions
  private readonly fetchFn: typeof fetch

  constructor(options: Oauth2ProviderOptions) {
    this.id = options.id
    this.enabled = options.enabled
    this.options = options
    this.fetchFn = options.fetchFn ?? ((...args) => fetch(...args))
  }

  getConfig(): ProviderPublicConfig {
    const host = this.options.authorizationUri.split("//")[1]?.split("/")[0] ?? "OAuth2"
    return {
      id: this.id,
      kind: "oauth2",
      name: this.options.name?.trim() || host,
      enabled: this.enabled,
    }
  }

  /** Flux redirect OAuth2 — pas de credentials directes (cf. OidcProvider.authenticate). */
  authenticate(_input: AuthInput): Promise<AuthResult> {
    return Promise.reject(
      new AuthError("invalid_credentials", "OAuth2 : flux redirect (initiateLogin/callback) requis", 400),
    )
  }

  /** Redirige vers authorizationUri avec state enregistré (consommé au callback). */
  async initiateLogin(req: unknown, _reply: unknown): Promise<void> {
    const state = oauth2StateStore.put(
      {
        providerId: this.id,
        redirectUri: this.options.redirectUri,
      },
      STATE_TTL_MS,
    )

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      scope: this.options.scopes ?? "read:user user:email",
      state,
    })

    const authorizeUrl = `${this.options.authorizationUri}?${params.toString()}`
    ;(req as { ssoAuthorizeUrl?: string }).ssoAuthorizeUrl = authorizeUrl
  }

  /**
   * callback : consomme state, échange le code contre un access_token, appelle
   * userinfo, extrait un subject stable (sub OU id) et retourne l'identité externe.
   */
  async callback(req: unknown, raw: unknown): Promise<ExternalIdentity> {
    void req
    const input = raw as { code?: string; state?: string; redirectUri?: string }

    if (!input.code || !input.state) {
      throw new AuthError("invalid_credentials", "callback OAuth2 : code/state manquants", 400)
    }

    const stateValue = oauth2StateStore.consume(input.state)
    if (!stateValue) {
      throw new AuthError("invalid_credentials", "callback OAuth2 : state absent, expiré ou déjà consommé (anti-replay)", 400)
    }
    if (stateValue.providerId !== this.id || stateValue.redirectUri !== this.options.redirectUri) {
      throw new AuthError("invalid_credentials", "callback OAuth2 : state invalide", 400)
    }

    const tokens = await this.exchangeCode(input.code)
    if (!tokens.access_token) {
      throw new AuthError("invalid_credentials", "échange OAuth2 : access_token absent", 400)
    }

    const userinfo = await this.fetchUserinfo(tokens.access_token)
    const subject = String(userinfo.sub ?? userinfo.id ?? "")
    if (!subject || subject === "undefined" || subject === "null") {
      throw new AuthError("invalid_credentials", "userinfo OAuth2 : aucun identifiant stable", 400)
    }

    const groups = extractGroups(userinfo, this.options.groupAttr)

    return {
      providerId: this.id,
      kind: "oauth2",
      issuer: null,
      subject,
      email: typeof userinfo.email === "string" ? userinfo.email : null,
      name: typeof userinfo.name === "string" ? userinfo.name : undefined,
      groups,
    }
  }

  private async exchangeCode(code: string): Promise<{ access_token?: string }> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.options.redirectUri,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
    })

    const res = await this.fetchFn(this.options.tokenUri, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
    })
    if (!res.ok) {
      throw new AuthError("invalid_credentials", "échange code→token OAuth2 refusé", 400)
    }
    return (await res.json()) as { access_token?: string }
  }

  private async fetchUserinfo(accessToken: string): Promise<Record<string, unknown>> {
    const res = await this.fetchFn(this.options.userinfoUri, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
    })
    if (!res.ok) {
      throw new AuthError("invalid_credentials", "userinfo OAuth2 injoignable", 400)
    }
    return (await res.json()) as Record<string, unknown>
  }
}

function extractGroups(userinfo: Record<string, unknown>, groupAttr?: string): string[] | undefined {
  const value = userinfo[groupAttr ?? "groups"]
  if (Array.isArray(value)) return value.map(String)
  if (typeof value === "string") return value.split(",").map((g) => g.trim()).filter(Boolean)
  return undefined
}

export function createOauth2Provider(options: Oauth2ProviderOptions): Oauth2Provider {
  return new Oauth2Provider(options)
}