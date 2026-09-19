/**
 * FAKE — fournisseur d'identité OIDC simulé (remplace Keycloak/Okta/GitLab).
 *
 * Seul l'IdP est simulé : tout le reste du flux est réel — le navigateur
 * navigue VRAIMENT vers cet IdP, l'API fait la découverte `.well-known`,
 * valide l'id_token (iss/aud/sig RS256 via notre JWKS, nonce, PKCE S256),
 * consomme le state. Port 5280.
 */

import { createServer } from "node:http"
import {
  createHash,
  createSign,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  type ServerResponse,
} from "node:crypto"

const PORT = Number(process.env.FAKE_OIDC_PORT ?? 5280)
const ISSUER = `http://127.0.0.1:${PORT}`
const KID = "fake-oidc-1"

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, string>
const JWK_KEY = {
  kty: "RSA",
  kid: KID,
  use: "sig",
  alg: "RS256",
  n: publicJwk.n,
  e: publicJwk.e,
}

const b64url = (input: string) => Buffer.from(input, "utf8").toString("base64url")

function signJwt(payload: Record<string, unknown>): string {
  const header = { alg: "RS256", typ: "JWT", kid: KID }
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  return `${data}.${createSign("RSA-SHA256").update(data).sign(privateKey).toString("base64url")}`
}

function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url")
}

type Authorization = {
  clientId: string
  redirectUri: string
  codeChallenge: string
  nonce: string
  sub: string
  email: string
}

// code (one-shot) → enregistrement d'autorisation.
const codes = new Map<string, Authorization>()
// nonces consommés une seule fois (anti-replay, miroir réel de l'IdP).
const usedNonces = new Set<string>()

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json" })
  res.end(JSON.stringify(body))
}

function redirect(res: ServerResponse, location: string) {
  res.writeHead(302, { location })
  res.end()
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`)

  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200)
    res.end("ok")
    return
  }

  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    return sendJson(res, 200, {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      jwks_uri: `${ISSUER}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "email", "profile"],
    })
  }

  if (req.method === "GET" && url.pathname === "/jwks") {
    return sendJson(res, 200, { keys: [JWK_KEY] })
  }

  if (req.method === "GET" && url.pathname === "/authorize") {
    const params = url.searchParams
    const clientId = params.get("client_id") ?? ""
    const redirectUri = params.get("redirect_uri") ?? ""
    const nonce = params.get("nonce") ?? ""
    const state = params.get("state") ?? ""
    const codeChallenge = params.get("code_challenge") ?? ""
    const codeChallengeMethod = params.get("code_challenge_method") ?? ""
    const responseType = params.get("response_type") ?? ""

    if (responseType !== "code" || !clientId || !redirectUri || !nonce || !state || !codeChallenge) {
      return sendJson(res, 400, { error: "invalid_request", error_description: "requête authorize incomplète" })
    }
    if (codeChallengeMethod && codeChallengeMethod !== "S256") {
      return sendJson(res, 400, { error: "invalid_request", error_description: "PKCE S256 exigé" })
    }
    if (usedNonces.has(nonce)) {
      return sendJson(res, 400, { error: "invalid_request", error_description: "nonce déjà utilisé (replay)" })
    }
    usedNonces.add(nonce)

    // Simule un utilisateur IdP déjà connecté : l'IdP approuve l'accès.
    const authorization: Authorization = {
      clientId,
      redirectUri,
      codeChallenge,
      nonce,
      sub: "sub-jdoe",
      email: "jdoe@corp.local",
    }
    const code = randomUUID()
    codes.set(code, authorization)

    const callback = new URL(redirectUri)
    callback.searchParams.set("code", code)
    callback.searchParams.set("state", state)
    return redirect(res, callback.toString())
  }

  if (req.method === "POST" && url.pathname === "/token") {
    let raw = ""
    req.on("data", (chunk) => (raw += chunk))
    req.on("end", () => {
      const body = new URLSearchParams(raw)
      const code = body.get("code") ?? ""
      const authorization = codes.get(code)
      if (!authorization) return sendJson(res, 400, { error: "invalid_grant" })
      codes.delete(code)

      const verifier = body.get("code_verifier") ?? ""
      if (pkceS256(verifier) !== authorization.codeChallenge) {
        return sendJson(res, 400, { error: "invalid_grant", error_description: "mauvais code_verifier (PKCE)" })
      }

      const now = Math.floor(Date.now() / 1000)
      const idToken = signJwt({
        iss: ISSUER,
        sub: authorization.sub,
        aud: authorization.clientId,
        exp: now + 300,
        iat: now,
        nonce: authorization.nonce,
        name: "Jane Doe",
        email: authorization.email,
        email_verified: true,
        preferred_username: "jdoe",
        groups: ["devs", "admins"],
      })
      return sendJson(res, 200, {
        id_token: idToken,
        access_token: randomBytes(32).toString("hex"),
        token_type: "Bearer",
        expires_in: 300,
      })
    })
    return
  }

  if (req.method === "GET" && url.pathname === "/userinfo") {
    return sendJson(res, 200, { sub: "sub-jdoe", email: "jdoe@corp.local", name: "Jane Doe", preferred_username: "jdoe" })
  }

  sendJson(res, 404, { error: "not_found", path: url.pathname })
})

server.listen(PORT, "127.0.0.1", () => console.log(`fake OIDC IdP → http://127.0.0.1:${PORT}`))