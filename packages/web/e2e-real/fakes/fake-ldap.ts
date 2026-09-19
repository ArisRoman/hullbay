/**
 * FAKE — annuaire LDAP simulé (remplace OpenLDAP / Active Directory).
 *
 * Seul l'annuaire est simulé : l'API se connecte VRAIMENT sur
 * `ldaps://127.0.0.1:1389` via ldapts (le client ldapts de l'API est TOUJOURS
 * en TLS — l'option tlsOptions lui fait wrapper la socket même sur ldap://) :
 * bind service account, recherche utilisateur scoped et bind utilisateur —
 * mêmes opérations réelles qu'un vrai annuaire. Le TLS est terminé localement
 * (cert auto-signé faux, généré par le webServer API), puis les octets LDAP
 * naviguent en clair vers le noeud ldapjs interne.
 *
 * Expose aussi un healthcheck HTTP sur :1289 (playwright webServer n'accepte que
 * des probe HTTP).
 */

import ldapjs from "ldapjs"
import fs from "node:fs"
import net from "node:net"
import tls from "node:tls"
import { execSync } from "node:child_process"
import { createServer as createHttpServer } from "node:http"

const { createServer: createLdapServer, InvalidCredentialsError } = ldapjs

const LDAP_PORT = Number(process.env.FAKE_LDAP_PORT ?? 1389)
const INTERNAL_LDAP_PORT = Number(process.env.FAKE_LDAP_INTERNAL_PORT ?? 1390)
const HTTP_PORT = Number(process.env.FAKE_LDAP_HTTP_PORT ?? 1289)

const BASE = "dc=e2e,dc=local"
const PEOPLE = "ou=people,dc=e2e,dc=local"
const ADMIN_DN = "cn=admin,dc=e2e,dc=local"
const ADMIN_PASSWORD = "admin-secret"
const USER_DN = "uid=jdoe,ou=people,dc=e2e,dc=local"
const USER_PASSWORD = "jdoe-secret"
const USER_MAIL = "jdoe@e2e.local"

// objectGUID Active Directory : 16 octets arbitraires (l'API en calcule la forme canonique).
const OBJECT_GUID = Buffer.from([
  0x9f, 0x1e, 0x29, 0x4c, 0x5a, 0x2b, 0x4f, 0x00,
  0x8f, 0x3a, 0x2e, 0x7c, 0x60, 0x4b, 0x91, 0x12,
])

// Cert auto-signé de test — généré par le webServer API ; ici on s'assure
// seulement qu'il existe (exécution standalone possible).
const CERT_DIR = "/tmp/hullbay-e2e-ldap"
const CERT = `${CERT_DIR}/cert.pem`
const KEY = `${CERT_DIR}/key.pem`
if (!fs.existsSync(CERT)) {
  fs.mkdirSync(CERT_DIR, { recursive: true })
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes -keyout "${KEY}" -out "${CERT}" -days 1 -subj "/CN=hullbay-e2e" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null`,
  )
}

const ldap = createLdapServer()

// Fake jetable : jamais de crash sur une liaison socket atypique (EOF en plein
// BER, abandons ldapts, gardes d'énumération…) — on journalise et on continue.
ldap.on("error", (err: unknown) => {
  console.error(`[fake-ldap] erreur ignorée : ${(err as Error).message}`)
})
ldap.on("connection", (socket: import("node:net").Socket) => {
  socket.on("error", () => {})
})

// Bind (suffix route : auteurs de dc=e2e,dc=local) : distinction appli dans le
// handler — compte de service (testConnection) OU utilisateur final jdoe.
ldap.bind(`dc=${BASE.slice(3)}`, (req, res, next) => {
  const dn = req.dn.toString().toLowerCase()
  if (dn === ADMIN_DN && req.credentials === ADMIN_PASSWORD) {
    res.end()
    return next()
  }
  if (dn === USER_DN && req.credentials === USER_PASSWORD) {
    res.end()
    return next()
  }
  return next(new InvalidCredentialsError())
})

// Recherche utilisateur (searchFilter de la config : {{username}}).
ldap.search(BASE, (req, res, next) => {
  const filter = String(req.filter.toString())
  const isPersonSearch = /uid=|mail=|sAMAccountName=|cn=/i.test(filter)
  if (isPersonSearch && /jdoe/i.test(filter)) {
    res.send({
      dn: USER_DN,
      attributes: {
        objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
        uid: "jdoe",
        cn: "Jane Doe",
        sn: "Doe",
        givenName: "Jane",
        mail: USER_MAIL,
        objectGUID: OBJECT_GUID,
        userAccountControl: 512,
      },
    })
  }
  res.end()
  return next()
})

// Ldapjs « réel » en clair sur le port interne.
ldap.listen(INTERNAL_LDAP_PORT, "127.0.0.1", () =>
  console.log(`fake LDAP server (plain, interne) → ldap://127.0.0.1:${INTERNAL_LDAP_PORT}`),
)

// Terminaison TLS : le client de l'API est TOUJOURS chiffré (tlsOptions) →
// le port LDAP exposé parle ldaps, on pipe les octets vers le noeud interne.
const tlsLdap = tls.createServer(
  { key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) },
  (secure) => {
    const upstream = net.connect(INTERNAL_LDAP_PORT, "127.0.0.1")
    secure.pipe(upstream)
    upstream.pipe(secure)
    secure.on("error", () => upstream.destroy())
    upstream.on("error", () => secure.destroy())
  },
)
tlsLdap.on("error", (err: unknown) => console.error(`[fake-ldap] erreur TLS ignorée : ${(err as Error).message}`))
tlsLdap.listen(LDAP_PORT, "127.0.0.1", () => console.log(`fake LDAP server (TLS) → ldaps://127.0.0.1:${LDAP_PORT}`))

createHttpServer((_req, res) => {
  res.writeHead(200)
  res.end("ok")
}).listen(HTTP_PORT, "127.0.0.1", () => console.log(`fake LDAP health → http://127.0.0.1:${HTTP_PORT}`))