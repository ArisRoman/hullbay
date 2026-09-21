/**
 * Tests OIDC générique — fixtures MockIdp sans réseau.
 * Cas : flow complet, issuer/audience/signature/expiration, nonce, state
 * (anti-replay), PKCE, rotation JWKS, double-issuer (aucune branche vendor).
 */

import { describe, it, expect, beforeEach, vi } from "vitest"
import jwt from "jsonwebtoken"
import { OidcProvider, createOidcProvider } from "../providers/oidc/oidc-provider"
import { MockIdp } from "./fixtures/oidc/helpers"

const ISSUER = "https://keycloak.test/realms/hullbay"
const CLIENT_ID = "hullbay-client"
const REDIRECT = "http://localhost:4000/api/auth/sso/oidc-test/callback"

/** Ref partagé : le mock token lit le nonce courant ici. */
function makeNonceRef() {
  const ref: { nonce?: string } = {}
  return ref
}

function buildProvider(idp: MockIdp, nonceRef?: { nonce?: string }, overrides: Record<string, unknown> = {}) {
  return createOidcProvider({
    id: "oidc-test",
    enabled: true,
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT,
    discoveryUrl: idp.discovery_url,
    fetchFn: idp.makeFetch({ nonce: nonceRef ? () => nonceRef.nonce : undefined }),
    ...overrides,
  }) as OidcProvider
}

async function startFlow(provider: OidcProvider, nonceRef?: { nonce?: string }) {
  const req: { ssoAuthorizeUrl?: string } = {}
  await provider.initiateLogin(req, null)
  const url = new URL(req.ssoAuthorizeUrl!)
  const nonce = url.searchParams.get("nonce")!
  if (nonceRef) nonceRef.nonce = nonce
  return { url, state: url.searchParams.get("state")!, nonce }
}

describe("OidcProvider", () => {
  let idp: MockIdp

  beforeEach(() => {
    idp = new MockIdp({ issuer: ISSUER, clientId: CLIENT_ID })
    idp.requests.length = 0
  })

  it("getConfig() expose id/kind/name/enabled — aucun secret", () => {
    const provider = buildProvider(idp)
    const cfg = provider.getConfig()
    expect(cfg).toEqual({ id: "oidc-test", kind: "oidc", name: "keycloak.test", enabled: true })
  })

  it("authenticate() lève : flux redirect uniquement (contrat respecté)", async () => {
    const provider = buildProvider(idp)
    await expect(provider.authenticate({ kind: "oidc" })).rejects.toMatchObject({
      code: "invalid_credentials",
      status: 400,
    })
  })

  it("initiateLogin construit une URL d'autorisation complète (PKCE + state + nonce)", async () => {
    const provider = buildProvider(idp)
    const { url, state, nonce } = await startFlow(provider)

    expect(url.searchParams.get("response_type")).toBe("code")
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID)
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT)
    expect(url.searchParams.get("scope")).toContain("openid")
    expect(url.searchParams.get("code_challenge_method")).toBe("S256")
    expect(state).toBeTruthy()
    expect(nonce).toBeTruthy()
    expect(url.searchParams.get("code_challenge")).toHaveLength(43)
  })

  it("callback code+state → ExternalIdentity{iss, sub, email, name}", async () => {
    const ref = makeNonceRef()
    const provider = buildProvider(idp, ref)
    const { state } = await startFlow(provider, ref)
    const identity = await provider.callback(null, { code: "auth-code", state })
    expect(identity).toMatchObject({
      providerId: "oidc-test",
      kind: "oidc",
      issuer: ISSUER,
      subject: "sub-42",
      email: "alice@example.test",
    })
    const tokenReq = idp.requests.find((r) => r.url.endsWith("/token"))
    expect(tokenReq?.body).toContain("code_verifier=")
    expect(tokenReq?.body).toContain(`client_id=${CLIENT_ID}`)
  })

  it("refuse code/state manquants", async () => {
    const provider = buildProvider(idp)
    await expect(provider.callback(null, {})).rejects.toMatchObject({ code: "invalid_credentials" })
    await expect(provider.callback(null, { code: "c" })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un state inconnu (anti-replay)", async () => {
    const provider = buildProvider(idp)
    await expect(provider.callback(null, { code: "c", state: "inconnu" })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("state consommé une seule fois : 2e callback avec le même state échoue (replay)", async () => {
    const ref = makeNonceRef()
    const provider = buildProvider(idp, ref)
    const { state } = await startFlow(provider, ref)
    const identity = await provider.callback(null, { code: "auth-code", state })
    expect(identity.subject).toBe("sub-42")
    await expect(provider.callback(null, { code: "auth-code", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
    const tokenReqs = idp.requests.filter((r) => r.url.endsWith("/token"))
    expect(tokenReqs).toHaveLength(1)
  })

  it("refuse un discovery dont l'issuer ≠ issuer configuré", async () => {
    const evil = new MockIdp({ issuer: "https://evil.example/realms/hullbay", clientId: CLIENT_ID })
    const provider = buildProvider(idp, undefined, { discoveryUrl: evil.discovery_url, fetchFn: evil.makeFetch() })
    await expect(provider.initiateLogin({} as never, null)).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("refuse un id_token au mauvais issuer", async () => {
    const evil = new MockIdp({ issuer: "https://evil.example", clientId: CLIENT_ID })
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ idToken: evil.signIdToken({}) }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un id_token à la mauvaise audience", async () => {
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ idToken: idp.signIdToken({ aud: "autre-client" }) }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un id_token expiré", async () => {
    const expired = idp.signIdToken({ exp: Math.floor(Date.now() / 1000) - 60 })
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ idToken: expired }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un id_token dont la signature ne correspond plus à la clé de l'IdP", async () => {
    const rogue = new MockIdp({ issuer: ISSUER, clientId: CLIENT_ID })
    rogue.removeKey("key-a")
    rogue.removeKey("key-b")
    rogue.addKey("rogue-key")
    const forged = rogue.signIdToken({}, "rogue-key")
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ idToken: forged }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un id_token au nonce différent (anti-replay nonce)", async () => {
    const provider = buildProvider(idp, undefined, {
      fetchFn: idp.makeFetch({ idToken: idp.signIdToken({ nonce: "l-attaquant" }) }),
    })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rotation JWKS : nouveaux tokens valides, anciens rejetés après purge", async () => {
    const ref = makeNonceRef()
    const p1 = buildProvider(idp, ref)
    const { state } = await startFlow(p1, ref)
    const identity = await p1.callback(null, { code: "c", state })
    expect(identity.subject).toBe("sub-42")

    const idp2 = new MockIdp({ issuer: ISSUER, clientId: CLIENT_ID })
    const ref2 = makeNonceRef()
    const p2 = buildProvider(idp2, ref2)
    const { state: s2 } = await startFlow(p2, ref2)
    const identity2 = await p2.callback(null, { code: "c", state: s2 })
    expect(identity2.subject).toBe("sub-42")

    // Signe le stale token AVANT de purger la clé.
    const staleToken = idp.signIdToken({}, "key-b")
    idp.removeKey("key-a")
    idp.removeKey("key-b")
    const stale = buildProvider(idp, ref, { fetchFn: idp.makeFetch({ idToken: staleToken }) })
    const { state: s3 } = await startFlow(stale, ref)
    await expect(stale.callback(null, { code: "c", state: s3 })).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("refuse un id_token au kid non apparié dans la JWKS (fail-closed)", async () => {
    const { privateKey } = idp.getKeys()[0]!
    const ghost = jwt.sign(
      {
        iss: ISSUER,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 300,
        sub: "sub-42",
      },
      privateKey,
      { algorithm: "RS256", keyid: "ghost-kid" },
    )
    expect(idp.getKeys().some((k) => k.kid === "ghost-kid")).toBe(false)
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ idToken: ghost }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({
      code: "invalid_credentials",
    })
  })

  it("rotation : la JWKS est re-fetchée après expiration du cache (pas de restart)", async () => {
    vi.useFakeTimers()
    try {
      const ref = makeNonceRef()
      const provider = buildProvider(idp, ref)
      const { state } = await startFlow(provider, ref)
      await provider.callback(null, { code: "c", state }) // remplit le cache

      const jwksBefore = idp.requests.filter((r) => r.url.endsWith("/certs")).length
      expect(jwksBefore).toBeGreaterThanOrEqual(1)

      // Rotation : nouvelle clé "current" sur l'IdP, cache arrivé à expiration.
      idp.addKey("key-c")
      vi.setSystemTime(Date.now() + 6 * 60 * 1000)

      const ref2 = makeNonceRef()
      const p2 = buildProvider(idp, ref2)
      const { state: s2 } = await startFlow(p2, ref2)
      const identity2 = await p2.callback(null, { code: "c", state: s2 })
      expect(identity2.subject).toBe("sub-42")

      const jwksAfter = idp.requests.filter((r) => r.url.endsWith("/certs")).length
      expect(jwksAfter).toBe(jwksBefore + 1)
    } finally {
      vi.useRealTimers()
    }
  })

  it("double-issuer : même classe sert Google ET Keycloak, aucune branche vendor", async () => {
    const googleIssuer = "https://google.test/accounts"
    const google = new MockIdp({ issuer: googleIssuer, clientId: "google-client" })
    const kc = new MockIdp({ issuer: ISSUER, clientId: "kc-client" })

    const refG = makeNonceRef()
    const gProvider = createOidcProvider({
      id: "oidc-google",
      enabled: true,
      issuer: googleIssuer,
      clientId: "google-client",
      redirectUri: "http://localhost:4000/api/auth/sso/oidc-google/callback",
      discoveryUrl: google.discovery_url,
      fetchFn: google.makeFetch({ nonce: () => refG.nonce }),
    }) as OidcProvider
    const refK = makeNonceRef()
    const kProvider = createOidcProvider({
      id: "oidc-test",
      enabled: true,
      issuer: ISSUER,
      clientId: "kc-client",
      redirectUri: REDIRECT,
      discoveryUrl: kc.discovery_url,
      fetchFn: kc.makeFetch({ nonce: () => refK.nonce }),
    }) as OidcProvider

    const { state: sg } = await startFlow(gProvider, refG)
    const identityG = await gProvider.callback(null, { code: "c", state: sg })
    expect(identityG.subject).toBe("sub-42")
    expect(identityG.issuer).toBe(googleIssuer)

    const { state: sk } = await startFlow(kProvider, refK)
    const identityK = await kProvider.callback(null, { code: "c", state: sk })
    expect(identityK.subject).toBe("sub-42")
    expect(identityK.issuer).toBe(ISSUER)
  })

  it("refuse un échange de code refusé par l'IdP (token endpoint 400)", async () => {
    const provider = buildProvider(idp, undefined, { fetchFn: idp.makeFetch({ tokenStatus: 400 }) })
    const ref = makeNonceRef()
    const { state } = await startFlow(provider, ref)
    await expect(provider.callback(null, { code: "c", state })).rejects.toMatchObject({ code: "invalid_credentials" })
  })
})