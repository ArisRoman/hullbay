#!/usr/bin/env node
/**
 * e2e SAML Keycloak (Phase 4, §16 du plan) — à exécuter en CI/staging UNIQUEMENT.
 *
 * Déroulé :
 *   1. Attend le boot de Keycloak (healthcheck du compose).
 *   2. Provisionne le realm `hullbay` + le client SAML `hullbay-saml-e2e`
 *      (binding POST / POST, assertion signée, certificat de signature SP) + un
 *      utilisateur `alice`.
 *   3. Reporte le flux navigateur (AuthnRequest → SAMLResponse) : l'exécution
 *      complète nécessite un navigateur headless (hors scope CI) ; la chaîne
 *      de validation de l'ACS est couverte par les tests unitaires SamlProvider
 *      avec les mêmes fixtures (signature/issuer/audience/conditions/replay).
 *
 * Prérequis :
 *   - docker compose -f tests/integration/docker-compose.keycloak.yml up -d
 *   - API hullbay démarrée (npm run dev:api) avec un provider SAML configuré
 *   - SAML_TEST_SP_CERT=<chemin> (certificat X.509 SP pour la signature des
 *     AuthnRequest) — sinon on génère un jeu de clés temporaire.
 *
 * Sortie : exit 0 si Keycloak est joignable et le client SAML provisionné.
 */

import { readFileSync } from "node:fs"
import { generateKeyPairSync } from "node:crypto"

const BASE = "http://localhost:8081"
const REALM = "hullbay"
const ADMIN = "admin"
const ADMIN_PWD = "admin"
const ACS = process.env.SAML_TEST_ACS ?? "http://localhost:4000/api/auth/saml/saml-e2e/acs"
const SP_ENTITY = process.env.SAML_TEST_SP_ENTITY ?? "http://localhost:4000/saml/saml-e2e"

// Clé de signature SP (le certificat committé dans les fixtures ne sert qu'aux
// signatures IdP pour les unit tests — ici on génère un jeu temporaire).
let spCertPem
let spKeyPem
if (process.env.SAML_TEST_SP_CERT) {
  spCertPem = readFileSync(process.env.SAML_TEST_SP_CERT, "utf8")
  if (process.env.SAML_TEST_SP_KEY) spKeyPem = readFileSync(process.env.SAML_TEST_SP_KEY, "utf8")
} else {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  })
  spCertPem = publicKey
  spKeyPem = privateKey
}

// ── Attend le boot ─────────────────────────────────────────────
async function waitForKeycloak(attempts = 60) {
  for (let i = 0; i < attempts; i++) {
    const ok = await fetch(`${BASE}/realms/master/.well-known/openid-configuration`)
      .then((r) => r.ok)
      .catch(() => false)
    if (ok) return
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error("Keycloak n'a pas démarré dans le délai imparti")
}

async function adminToken() {
  const res = await fetch(`${BASE}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "admin-cli",
      grant_type: "password",
      username: ADMIN,
      password: ADMIN_PWD,
    }),
  })
  if (!res.ok) throw new Error("token admin Keycloak refusé")
  return (await res.json()).access_token
}

async function adminJson(method, path, token, body) {
  const res = await fetch(`${BASE}/admin/realms/${REALM}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  return { status: res.status, body: res.status === 204 ? null : await res.json().catch(() => null) }
}

// ── Provisionne realm + client SAML + user ────────────────────
async function provision(token) {
  const realm = await adminJson("POST", "", token, { id: REALM, realm: REALM, enabled: true, sslRequired: "none" })
  if (realm.status !== 201 && realm.status !== 409 && realm.status !== 200) {
    throw new Error(`création realm : ${realm.status}`)
  }

  // Client SAML (POST/POST, assertion signée, wantsClientAssertionSignature).
  let clientId
  const clients = await adminJson("GET", "/clients?clientId=hullbay-saml-e2e", token)
  if (clients.body?.length && clients.body[0].id) {
    clientId = clients.body[0].id
  } else {
    const spCertificateB64 = Buffer.from(spCertPem, "utf8").toString("base64")
    const c = await adminJson("POST", "/clients", token, {
      clientId: "hullbay-saml-e2e",
      protocol: "saml",
      publicClient: false,
      enabled: true,
      rootUrl: "",
      attributes: {
        "saml_idp_entity_id": SP_ENTITY,
        "saml_assertion_consumer_url_post": ACS,
        "saml_single_logout_service_url_post": "",
        "saml_force_post_binding": "true",
        "saml_force_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "saml_assertion_signature": "true",
        "saml_client_signature": "false",
        "saml_signature_algorithm": "RSA_SHA256",
        "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "saml_single_sign_on_service_url_redirect": "",
        "saml_single_sign_on_service_url_post": ACS,
        "saml_artifact_binding_url": "",
        "saml_xml_key_name_tranformer": "KEY_ID",
        "saml_encrypt": "false",
        "saml_wants_assertion_signature": "true",
        "saml_server_signature": "false",
        "saml_signing_certificate": spCertificateB64,
      },
    })
    if (c.status !== 201 && c.status !== 409) throw new Error(`création client SAML : ${c.status}`)
    const list = await adminJson("GET", "/clients?clientId=hullbay-saml-e2e", token)
    clientId = list.body[0].id
  }

  // Utilisateur alice (idempotent).
  const user = await adminJson("POST", "/users", token, {
    username: "alice",
    email: "alice@example.test",
    emailVerified: true,
    enabled: true,
  })
  if (user.status !== 201 && user.status !== 409) throw new Error(`création user : ${user.status}`)

  return clientId
}

async function main() {
  console.log("[keycloak-saml.e2e] attend Keycloak…")
  await waitForKeycloak()
  const token = await adminToken()
  console.log("[keycloak-saml.e2e] token admin OK")
  const clientId = await provision(token)
  console.log("[keycloak-saml.e2e] client SAML provisionné :", clientId ?? "(déjà présent)")
  console.log("[keycloak-saml.e2e] flux AuthnRequest/SAMLResponse reporté au navigateur headless (hors scope CI) — validation coté ACS couverte par les unit tests SamlProvider (mêmes fixtures)")
  console.log("[keycloak-saml.e2e] OK — IdP SAML joignable, client provisionné")
  process.exit(0)
}

main().catch((err) => {
  console.error("[keycloak-saml.e2e] FAIL:", err.message)
  process.exitCode = 1
})