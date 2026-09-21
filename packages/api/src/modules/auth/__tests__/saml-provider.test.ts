/**
 * Test unitaire SamlProvider — cycle complet SAML 2.0 :
 * AuthnRequest (initiateLogin) + SAMLResponse (callback), validation
 * signature/issuer/audience/conditions/Destination/Recipient/InResponseTo,
 * anti-replay (empreinte + RelayState), et les 9 cas négatifs.
 * AUCUN réseau (cacheProvider + fixtures de test injectés).
 */

import { beforeEach, describe, expect, it, vi } from "vitest"
import { SamlProvider, type SamlProviderOptions } from "../providers/saml/saml-provider"
import { buildSamlResponse, MemoryCacheProvider, SAML_IDP_CERT } from "./fixtures/saml/helpers"
import { samlReplayStore } from "../core/saml-replay"
import { samlStateStore } from "../core/auth-state"

const SP_ISSUER = "https://sp.example.org/saml/me"
const IDP_ISSUER = "https://idp.example.org/realms/test"
const CALLBACK_URL = "https://sp.example.org/api/auth/saml/me/acs"

function makeProvider(overrides: Partial<SamlProviderOptions> = {}) {
  const cache = new MemoryCacheProvider()
  const provider = new SamlProvider({
    id: "saml-test",
    enabled: true,
    idpCert: SAML_IDP_CERT,
    idpIssuer: IDP_ISSUER,
    spIssuer: SP_ISSUER,
    entryPoint: "https://idp.example.org/realms/test/protocol/saml/clients/sp",
    callbackUrl: CALLBACK_URL,
    cacheProvider: cache as never,
    ...overrides,
  })
  return { provider, cache }
}

describe("SamlProvider", () => {
  beforeEach(() => {
    samlReplayStore.reset()
  })

  const makeRelayState = (providerId: string): string =>
    samlStateStore.put({ providerId, redirectUri: CALLBACK_URL }, 10 * 60 * 1000)

  // ── 4A. Flux complet valide ──
  it("accepte un SAMLResponse signé valide avec InResponseTo correct (flow complet)", async () => {
    const { provider, cache } = makeProvider()

    // initiateLogin : produit l'AuthnRequest et enregistre son ID dans le cache.
    const req = {} as { ssoAuthorizeUrl?: string }
    await provider.initiateLogin(req, {})
    expect(req.ssoAuthorizeUrl).toBeTruthy()
    expect(req.ssoAuthorizeUrl).toContain("SAMLRequest=")
    expect(req.ssoAuthorizeUrl).toContain("RelayState=")
    const requestId = cache.firstRequestId()
    expect(requestId).toBeTruthy()

    const { base64 } = buildSamlResponse({
      inResponseTo: requestId,
      issuer: IDP_ISSUER,
      audience: SP_ISSUER,
      destination: CALLBACK_URL,
      recipient: CALLBACK_URL,
      mail: "alice@example.org",
    })

    const identity = await provider.callback(
      {},
      { SAMLResponse: base64, RelayState: makeRelayState("saml-test") },
    )
    expect(identity).toMatchObject({
      providerId: "saml-test",
      kind: "saml",
      issuer: IDP_ISSUER,
      subject: "user@example.org",
      email: "alice@example.org",
    })
    // Check si l'e-mail du NameID était aussi le NameID format → subject.
  })

  it("rejette une assertion dont la signature est invalide (pas de signature)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({ inResponseTo: cache.firstRequestId(), signed: false })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une assertion signée avec une clé étrangère (cert non reconnu)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({ inResponseTo: cache.firstRequestId(), wrongKey: true })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une assertion dont l'audience ne matche pas le SP", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({
      inResponseTo: cache.firstRequestId(),
      audience: "https://evil.example.org/saml",
    })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une assertion dont l'issuer ne matche pas l'IdP", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({
      inResponseTo: cache.firstRequestId(),
      issuer: "https://evil.example.org/realms/other",
    })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une assertion expirée (NotOnOrAfter passé)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({
      inResponseTo: cache.firstRequestId(),
      notOnOrAfterOffsetSec: -60, // déjà périmée depuis 60s
    })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une assertion falsifiée (changement après signature)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({ inResponseTo: cache.firstRequestId(), tamper: true })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette un wrapping de signature (assertion valide + assertion parasite)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({ inResponseTo: cache.firstRequestId(), wrap: true })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une response avec Destination ≠ ACS", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({
      inResponseTo: cache.firstRequestId(),
      destination: "https://attacker.example.org/acs",
    })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une réponse dont le Recipient (SubjectConfirmationData) != ACS", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({
      inResponseTo: cache.firstRequestId(),
      recipient: "https://attacker.example.org/acs",
    })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une réponse avec InResponseTo absent (replay de type CSRF)", async () => {
    const { provider } = makeProvider()
    // Pas d'initiateLogin : l'InResponseTo ne peut pas matcher un requête émise.
    const { base64 } = buildSamlResponse({ inResponseTo: "_ghost-request-id" })
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une réponse replayée (même empreinte SAMLResponse)", async () => {
    const { provider, cache } = makeProvider()
    await provider.initiateLogin({} as { ssoAuthorizeUrl?: string }, {})
    const { base64 } = buildSamlResponse({ inResponseTo: cache.firstRequestId() })
    // Premier mark OK, second mark → lève (replay détecté AVANT même le callback).
    samlReplayStore.mark(base64) // premier appel OK
    await expect(
      provider.callback({}, { SAMLResponse: base64, RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })

  it("rejette une réponse structurellement cassée (base64 non-SAML)", async () => {
    const { provider } = makeProvider()
    await expect(
      provider.callback({}, { SAMLResponse: "not-a-valid-saml-response", RelayState: makeRelayState("saml-test") }),
    ).rejects.toMatchObject({ code: "invalid_credentials" })
  })
})