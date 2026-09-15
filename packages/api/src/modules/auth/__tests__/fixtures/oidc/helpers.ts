/**
 * Fixture IdP OIDC de test — génère des clés RSA à l'exécution (JAMAIS de clé
 * de prod), expose un fetchFn mocké : discovery + JWKS + token_endpoint qui
 * signe des id_token RS256. Permet de tester tout le cycle OIDC sans réseau.
 */

import { createPublicKey, generateKeyPairSync } from "node:crypto"
import jwt from "jsonwebtoken"

export interface MockIdpKey {
  kid: string
  n: string
  e: string
  privateKey: string
  current: boolean
}

export interface RecordedRequest {
  url: string
  method: string
  body?: string
}

export class MockIdp {
  readonly issuer: string
  readonly clientId: string
  readonly authorization_endpoint: string
  readonly token_endpoint: string
  readonly userinfo_endpoint: string
  readonly jwks_uri: string
  readonly discovery_url: string

  private keys: MockIdpKey[] = []
  /** Désactiver la vérification du body token (assertions PKCE). */
  readonly requests: RecordedRequest[] = []

  constructor(opts: { issuer: string; clientId: string }) {
    this.issuer = opts.issuer
    this.clientId = opts.clientId
    this.authorization_endpoint = `${opts.issuer}/protocol/openid-connect/auth`
    this.token_endpoint = `${opts.issuer}/protocol/openid-connect/token`
    this.userinfo_endpoint = `${opts.issuer}/protocol/openid-connect/userinfo`
    this.jwks_uri = `${opts.issuer}/protocol/openid-connect/certs`
    this.discovery_url = `${opts.issuer}/.well-known/openid-configuration`

    // Deux clés dès le départ (rotation testable) ; la première est "current".
    this.addKey("key-a")
    this.addKey("key-b")
  }

  /** Ajoute une clé RSA (kid). La dernière ajoutée devient "current". */
  addKey(kid: string): MockIdpKey {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    })
    const exported = createPublicKey(publicKey).export({ format: "jwk" }) as { n?: string; e?: string }

    for (const k of this.keys) k.current = false
    const key: MockIdpKey = {
      kid,
      n: exported.n ?? "",
      e: exported.e ?? "",
      privateKey,
      current: true,
    }
    this.keys.push(key)
    return key
  }

  /** Retire une clé (simule une rotation purgée). */
  removeKey(kid: string): void {
    this.keys = this.keys.filter((k) => k.kid !== kid)
    const last = this.keys.at(-1)
    if (last) for (const k of this.keys) k.current = k === last
  }

  /** Les clés actives (JWKS servi). */
  getKeys(): MockIdpKey[] {
    return [...this.keys]
  }

  currentKey(): MockIdpKey {
    const cur = this.keys.find((k) => k.current) ?? this.keys[0]!
    return cur
  }

  /** Signe un id_token avec la clé courante (ou kid explicite) + claims. */
  signIdToken(claims: Record<string, unknown>, kid?: string): string {
    const key = kid ? this.keys.find((k) => k.kid === kid) : this.currentKey()
    if (!key) throw new Error(`MockIdp : clé ${kid} absente`)
    return jwt.sign(
      {
        iss: this.issuer,
        aud: this.clientId,
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        sub: "sub-42",
        email: "alice@example.test",
        name: "Alice Test",
        ...claims,
      },
      key.privateKey,
      { algorithm: "RS256", keyid: key.kid },
    )
  }

  /** fetchFn mocké : discovery, JWKS, token. Signe l'id_token via `idToken` (ou auto). */
  makeFetch(opts: { idToken?: string | null; tokenStatus?: number; nonce?: string | (() => string | undefined) } = {}) {
    const self = this
    return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input)
      self.requests.push({ url, method: init?.method ?? "GET", body: String(init?.body ?? "") })

      if (url === self.discovery_url) {
        return jsonResponse({
          issuer: self.issuer,
          authorization_endpoint: self.authorization_endpoint,
          token_endpoint: self.token_endpoint,
          userinfo_endpoint: self.userinfo_endpoint,
          jwks_uri: self.jwks_uri,
        })
      }

      if (url === self.jwks_uri) {
        return jsonResponse({
          keys: self.keys.map((k) => ({
            kty: "RSA",
            kid: k.kid,
            use: "sig",
            alg: "RS256",
            n: k.n,
            e: k.e,
          })),
        })
      }

      if (url === self.token_endpoint) {
        if (opts.tokenStatus && opts.tokenStatus !== 200) {
          return new Response(JSON.stringify({ error: "bad_grant" }), {
            status: opts.tokenStatus,
            headers: { "content-type": "application/json" },
          })
        }
        const idToken =
          opts.idToken !== undefined
            ? opts.idToken
            : self.signIdToken(opts.nonce ? { nonce: typeof opts.nonce === "function" ? opts.nonce() : opts.nonce } : {})
        return jsonResponse({ id_token: idToken, access_token: "at-123", token_type: "Bearer" })
      }

      return new Response("not found", { status: 404 })
    }
  }
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}