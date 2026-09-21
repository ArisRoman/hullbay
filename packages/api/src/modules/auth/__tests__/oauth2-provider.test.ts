/**
 * Tests OAuth2 générique — fixtures MockOauth2 sans réseau.
 * Cas : flow complet (state/subject/groups), anti-replay state, erreurs
 * (manquants, state inconnu, échange refusé, userinfo KO, sujet absent),
 * pas d'integrations vendor (config explicite, aucune branche par provider).
 */

import { describe, it, expect, beforeEach } from "vitest"
import { Oauth2Provider, createOauth2Provider } from "../providers/oauth2/oauth2-provider"
import { MockOauth2 } from "./fixtures/oauth2/helpers"

const BASE = "https://github.test"
const AUTH_URI = `${BASE}/login/oauth/authorize`
const TOKEN_URI = `${BASE}/login/oauth/access_token`
const USERINFO_URI = `${BASE}/api/v3/user`
const CLIENT_ID = "gh-client"
const CLIENT_SECRET = "gh-secret"
const REDIRECT = "http://localhost:4000/api/auth/sso/oauth2-github/callback"

function buildProvider(mock: MockOauth2, overrides: Record<string, unknown> = {}) {
  return createOauth2Provider({
    id: "oauth2-github",
    enabled: true,
    authorizationUri: AUTH_URI,
    tokenUri: TOKEN_URI,
    userinfoUri: USERINFO_URI,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT,
    scopes: "read:user",
    fetchFn: mock.makeFetch(),
    ...overrides,
  }) as Oauth2Provider
}

async function startFlow(provider: Oauth2Provider) {
  const req: { ssoAuthorizeUrl?: string } = {}
  await provider.initiateLogin(req, null)
  const url = new URL(req.ssoAuthorizeUrl!)
  return { url, state: url.searchParams.get("state")! }
}

describe("Oauth2Provider", () => {
  let mock: MockOauth2

  beforeEach(() => {
    mock = new MockOauth2({ authorizationUri: AUTH_URI, tokenUri: TOKEN_URI, userinfoUri: USERINFO_URI, clientId: CLIENT_ID })
    mock.tokenRequests.length = 0
  })

  it("getConfig() expose id/kind/name/enabled — aucun secret", () => {
    const cfg = buildProvider(mock).getConfig()
    expect(cfg).toEqual({ id: "oauth2-github", kind: "oauth2", name: "github.test", enabled: true })
  })

  it("authenticate() lève : flux redirect uniquement (contrat respecté)", async () => {
    await expect(buildProvider(mock).authenticate({ kind: "oauth2" })).rejects.toMatchObject({
      code: "invalid_credentials",
      status: 400,
    })
  })

  it("initiateLogin construit une URL d'autorisation avec state + scopes", async () => {
    const { url, state } = await startFlow(buildProvider(mock))
    expect(url.searchParams.get("response_type")).toBe("code")
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID)
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT)
    expect(url.searchParams.get("scope")).toBe("read:user")
    expect(state).toBeTruthy()
  })

  it("callback code+state → ExternalIdentity{issuer: null, sub, email, name, groups}", async () => {
    const provider = buildProvider(mock)
    const { state } = await startFlow(provider)
    const identity = await provider.callback(null, { code: "auth-code", state })
    expect(identity).toMatchObject({
      providerId: "oauth2-github",
      kind: "oauth2",
      issuer: null,
      subject: "42",
      email: "alice@example.test",
      name: "Alice Test",
      groups: ["admins"],
    })
    expect(mock.tokenRequests.at(-1)).toContain(`client_secret=${CLIENT_SECRET}`)
    expect(mock.tokenRequests.at(-1)).toContain("code=auth-code")
  })

  it("email absent → null ; groupes via groupAttr paramétré", async () => {
    mock.setUserinfo({ id: 7, login: "bob", groups: "dev,sre " })
    const provider = buildProvider(mock)
    const { state } = await startFlow(provider)
    const identity = await provider.callback(null, { code: "c", state })
    expect(identity.subject).toBe("7")
    expect(identity.email).toBeNull()
    expect(identity.groups).toEqual(["dev", "sre"])
  })

  it("refuse code/state manquants", async () => {
    const provider = buildProvider(mock)
    await expect(provider.callback(null, {})).rejects.toMatchObject({ code: "invalid_credentials" })
    await expect(provider.callback(null, { code: "c" })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un state inconnu (anti-replay)", async () => {
    const provider = buildProvider(mock)
    await expect(provider.callback(null, { code: "c", state: "inconnu" })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("state consommé une seule fois : replay du même state échoue", async () => {
    const provider = buildProvider(mock)
    const { state } = await startFlow(provider)
    const identity = await provider.callback(null, { code: "c", state })
    expect(identity.subject).toBe("42")
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("refuse un userinfo sans identifiant stable (pas de sub/id)", async () => {
    mock.setUserinfo({ login: "alice", name: "Alice" })
    const provider = buildProvider(mock)
    const { state } = await startFlow(provider)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("refuse un échange de code rejeté par le fournisseur (token 401)", async () => {
    const provider = buildProvider(mock, { fetchFn: mock.makeFetch({ tokenStatus: 401 }) })
    const { state } = await startFlow(provider)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("refuse un access_token absent (réponse fantaisiste)", async () => {
    const provider = buildProvider(mock, {
      fetchFn: (async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch,
    })
    const { state } = await startFlow(provider)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("refuse un userinfo injoignable (403)", async () => {
    const provider = buildProvider(mock, { fetchFn: mock.makeFetch({ userinfoStatus: 403 }) })
    const { state } = await startFlow(provider)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })
})