/**
 * Fixture IdP SAML de test — construit des SAMLResponse signées (RSA-SHA256,
 * signature au niveau Assertion comme Keycloak) avec le certificat TEST committé
 * dans `saml/keys/` (JAMAIS de clé de prod). Couvre le flux complet node-saml :
 * Response > Assertion signée > SubjectConfirmationData, Conditions, audience.
 *
 * Le test contrôle le `cacheProvider` : pour coupler une réponse à une requête,
 * l'assertion AUSSITÔT après `initiateLogin`, il suffit de lire la clé que
 * node-saml a misée en cache (InResponseTo). Le helper expose donc `saveRequestId`
 * pour simuler l'AuthnRequest enregistré, et `sign` pour produire la réponse.
 */

import { readFileSync } from "node:fs"
import { generateKeyPairSync } from "node:crypto"
import { join } from "node:path"
import { SignedXml } from "xml-crypto"

export const SAML_IDP_CERT = readFileSync(join(__dirname, "keys", "idp-cert.pem"), "utf8")
export const SAML_IDP_PRIVATE_KEY = readFileSync(join(__dirname, "keys", "idp-private-key.pem"), "utf8")

/** CacheProvider in-memory minimal (interface node-saml). */
export class MemoryCacheProvider {
  private values = new Map<string, { value: string; createdAt: number }>()

  async saveAsync(key: string, value: string): Promise<unknown> {
    this.values.set(key, { value, createdAt: Date.now() })
    return { value, createdAt: Date.now() }
  }

  async getAsync(key: string): Promise<string | null> {
    return this.values.get(key)?.value ?? null
  }

  async removeAsync(key: string | null): Promise<string | null> {
    const value = key ? this.values.get(key)?.value ?? null : null
    if (key) this.values.delete(key)
    return value
  }

  /** Premier ID en cache (celui de l'AuthnRequest le plus récent). */
  firstRequestId(): string {
    return this.values.keys().next().value as string
  }
}

export interface SamlResponseOptions {
  /** ID porté par l'AuthnRequest (réponse associée). */
  inResponseTo: string
  /** Issuer IdP (assertion + Response). */
  issuer?: string
  /** Audience de l'assertion (Conditions/AudienceRestriction). */
  audience?: string
  /** Destination du Response (ACS attendu). */
  destination?: string
  /** Recipient du SubjectConfirmationData. */
  recipient?: string
  /** clock skew simulé : NotBefore/NotOnOrAfter relatifs à maintenant. */
  notBeforeOffsetSec?: number
  notOnOrAfterOffsetSec?: number
  /** Signer l'assertion ? défaut true. false → assertion non signée. */
  signed?: boolean
  /** Signer avec une clé différente (cert/pair non reconnus) ? */
  wrongKey?: boolean
  /** Corrompre la valeur signée après signature (tamper) ? */
  tamper?: boolean
  /** Ajouter une 2e assertion non signée (tentative de wrapping) ? */
  wrap?: boolean
  /** NameID (sujet). */
  nameID?: string
  /** Attribut mail. */
  mail?: string
}

export interface SamlResponseResult {
  /** Base64 du SAMLResponse prêt à être soumis comme POST. */
  base64: string
  /** ID de l'assertion construite (utile pour assertion wrapping). */
  assertionId: string
}

const NOW = Date.now()
const iso = (ms: number) => new Date(ms).toISOString()

/**
 * Génère une assertion + Response signées, prêtes à être testées.
 */
export function buildSamlResponse(opts: SamlResponseOptions): SamlResponseResult {
  const spIssuer = opts.audience ?? "https://sp.example.org/saml/me"
  const idpIssuer = opts.issuer ?? "https://idp.example.org/realms/test"
  const destination = opts.destination ?? "https://sp.example.org/api/auth/saml/me/acs"
  const recipient = opts.recipient ?? destination
  const nameID = opts.nameID ?? "user@example.org"
  const mail = opts.mail ?? "user@example.org"
  const notBeforeOffset = opts.notBeforeOffsetSec ?? -10
  const notOnOrAfterOffset = opts.notOnOrAfterOffsetSec ?? 300
  const sign = opts.signed ?? true
  const issueInstant = iso(NOW)

  const assertionId = "_assert" + Math.random().toString(36).slice(2, 10)

  const assertion = `<saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Issuer>${idpIssuer}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameID}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="${opts.inResponseTo}" NotOnOrAfter="${iso(NOW + notOnOrAfterOffset * 1000)}" Recipient="${recipient}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="${iso(NOW + notBeforeOffset * 1000)}" NotOnOrAfter="${iso(NOW + notOnOrAfterOffset * 1000)}">
<saml:AudienceRestriction><saml:Audience>${spIssuer}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="s1">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement>
<saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>${mail}</saml:AttributeValue></saml:Attribute>
</saml:AttributeStatement>
</saml:Assertion>`

  let signedAssertion = assertion
  if (sign) {
    const privateKey = opts.wrongKey ? generateWrongKey() : SAML_IDP_PRIVATE_KEY
    const sig = new SignedXml({
      privateKey,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    })
    sig.addReference({
      xpath: `//*[@ID="${assertionId}"]`,
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
      ],
      uri: `#${assertionId}`,
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    })
    sig.computeSignature(assertion, {
      prefix: "ds",
      location: { reference: `//*[@ID="${assertionId}"]`, action: "prepend" },
    })
    signedAssertion = sig.getSignedXml()
  }

  if (opts.tamper) {
    signedAssertion = signedAssertion.replace(
      /<saml:AttributeValue>.*?<\/saml:AttributeValue>/,
      "<saml:AttributeValue>HACKED</saml:AttributeValue>",
    )
  }

  const extraAssertion = opts.wrap
    ? `<saml:Assertion ID="_wrapped" Version="2.0" IssueInstant="${issueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Issuer>${idpIssuer}</saml:Issuer>
<saml:Subject><saml:NameID>attacker@evil.org</saml:NameID></saml:Subject>
<saml:Conditions><saml:AudienceRestriction><saml:Audience>${spIssuer}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
</saml:Assertion>`
    : ""

  const response = `<samlp:Response ID="_resp${assertionId.slice(-4)}" Version="2.0" IssueInstant="${issueInstant}" Destination="${destination}" InResponseTo="${opts.inResponseTo}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Issuer>${idpIssuer}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
${signedAssertion}
${extraAssertion}
</samlp:Response>`

  return {
    base64: Buffer.from(response, "utf8").toString("base64"),
    assertionId,
  }
}

/** Génère une paire RSA jetable (pour signer avec une clé non reconnue). */
let _wrongKeyCache: string | null = null
function generateWrongKey(): string {
  if (!_wrongKeyCache) {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    })
    _wrongKeyCache = privateKey
  }
  return _wrongKeyCache
}