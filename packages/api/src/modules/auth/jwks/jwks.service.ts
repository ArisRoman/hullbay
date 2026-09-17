import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import jwt from "jsonwebtoken"

export interface Jwk {
  kty: string
  kid: string
  use: string
  n: string
  e: string
}

export interface Jwks {
  keys: Jwk[]
}

interface SigningKey {
  kid: string
  privatePem: string
  publicPem: string
  createdAt: number
  active: boolean
}

export interface JwksServiceOptions {
  /** Fichier de persistance du keyring (sinon clés éphémères en mémoire). */
  keyringPath?: string
}

export interface SignPayloadOptions {
  /** Durée de vie (secondes ou string ms/vercel). Ajoute le claim `exp`. */
  expiresIn?: number | string
  /** Audience du token (claim `aud`), vérifiée à la lecture. */
  audience?: string
}

const ALG = "RS256"
/** Fenêtre de grâce des anciennes clés : au-delà, un token signé est expiré. */
const KEY_GRACE_MS = 24 * 60 * 60 * 1000
/** Borne dure du keyring (l'active + 3 anciennes) même en rotations rapprochées. */
const MAX_KEYS = 4

function jwkFromPem(publicPem: string, kid: string): Jwk {
  const pub = Buffer.from(publicPem)
  const der = crypto.createPublicKey(pub).export({ type: "spki", format: "der" })
  const n = der.subarray(28).toString("base64url")
  const e = Buffer.from([0x01, 0x00, 0x01]).toString("base64url")
  return { kty: "RSA", kid, use: "sig", n, e }
}

function generateKid(): string {
  return crypto.randomUUID().slice(0, 8)
}

/**
 * Clés de signature RS256 du panel, avec rotation sans coupure.
 *
 * Durabilité : le keyring est persisté sur disque (option `keyringPath`) pour
 * qu'un redémarrage du process (ex. `tsx watch`) ne régénère pas les clés et
 * n'invalide pas les tokens en vol. La vérification refuse désormais tout
 * `kid` inconnu ; le fallback HMAC (HS256) n'est appliqué qu'aux tokens sans
 * `kid` ET si `JWT_SECRET` est explicitement défini — jamais avec un secret
 * par défaut codé en dur.
 */
export class JwksService {
  private keys: SigningKey[] = []
  private readonly legacySecret: string | undefined
  private readonly keyringPath?: string

  constructor(options: JwksServiceOptions = {}) {
    this.legacySecret = process.env.JWT_SECRET
    this.keyringPath = options.keyringPath
    if (this.keyringPath && this.loadKeyring()) return
    this.keys.push(this.generateKey(true))
    this.persist()
  }

  private generateKey(active: boolean, kid = generateKid()): SigningKey {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    return {
      kid,
      privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
      createdAt: Date.now(),
      active,
    }
  }

  private loadKeyring(): boolean {
    if (!this.keyringPath) return false
    let raw: string
    try {
      raw = fs.readFileSync(this.keyringPath, "utf8")
    } catch {
      // Absence de fichier est normale (premier démarrage).
      return false
    }
    try {
      const parsed = JSON.parse(raw) as SigningKey[]
      if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("keyring vide")
      const valid = parsed.filter((k) => {
        if (typeof k?.kid !== "string" || typeof k?.privatePem !== "string" || typeof k?.publicPem !== "string") {
          return false
        }
        try {
          crypto.createPrivateKey(k.privatePem)
          crypto.createPublicKey(k.publicPem)
          return true
        } catch {
          return false
        }
      })
      if (valid.length === 0) throw new Error("aucune clé PEM valide")
      this.keys = valid.map((k) => ({ ...k, active: false }))
      this.keys[0]!.active = true
      return true
    } catch (error) {
      // Fichier corrompu/tronqué : on préserve une copie avant de régénérer,
      // pour ne pas écraser silencieusement un keyring lisible par erreur.
      try {
        fs.renameSync(this.keyringPath, `${this.keyringPath}.corrupt-${Date.now()}`)
      } catch {
        // best-effort
      }
      console.error(
        `[jwks] keyring illisible (${(error as Error).message}) — sauvegarde puis régénération`,
      )
      return false
    }
  }

  private persist(): void {
    if (!this.keyringPath) return
    try {
      fs.mkdirSync(path.dirname(this.keyringPath), { recursive: true })
      fs.writeFileSync(this.keyringPath, JSON.stringify(this.keys), { mode: 0o600 })
    } catch {
      // Persistance best-effort : sans elle on retombe sur des clés éphémères.
    }
  }

  getActiveKid(): string {
    const active = this.keys.find((k) => k.active)
    return active ? active.kid : (this.keys[0]!.kid)
  }

  signPayload(payload: object, options: SignPayloadOptions = {}): string {
    const kid = this.getActiveKid()
    const signingKey = this.keys.find((k) => k.kid === kid)?.privatePem ?? this.keys[0]!.privatePem
    const signOptions: jwt.SignOptions = { algorithm: ALG, header: { kid, alg: ALG } }
    if (options.expiresIn !== undefined) signOptions.expiresIn = options.expiresIn as jwt.SignOptions["expiresIn"]
    if (options.audience !== undefined) signOptions.audience = options.audience
    return jwt.sign(payload, signingKey, signOptions)
  }

  verifyToken(token: string, audience?: string): jwt.JwtPayload {
    const decoded = jwt.decode(token, { complete: true })
    if (!decoded || typeof decoded === "string") throw new Error("token invalide")
    const kid = decoded.header.kid as string | undefined

    if (kid) {
      const key = this.keys.find((k) => k.kid === kid)
      if (!key) throw new Error("kid inconnu")
      const opts: jwt.VerifyOptions = { algorithms: [ALG] }
      if (audience) opts.audience = audience
      return jwt.verify(token, key.publicPem, opts) as jwt.JwtPayload
    }

    // Fallback historique : uniquement des tokens HMAC sans kid et un secret
    // explicitement configuré (pas de secret par défaut en dur). Les tokens de
    // session d'avant le fix n'ayant pas d'audience `session`, ils restent
    // rejetés par verifySession — cut d'upgrade volontaire.
    if (!this.legacySecret) throw new Error("key inconnue")
    const opts: jwt.VerifyOptions = { algorithms: ["HS256"] }
    if (audience) opts.audience = audience
    try {
      return jwt.verify(token, this.legacySecret, opts) as jwt.JwtPayload
    } catch {
      throw new Error("key inconnue")
    }
  }

  rotate(): string {
    const oldActive = this.keys.find((k) => k.active)
    if (oldActive) oldActive.active = false
    const newKey = this.generateKey(true)
    this.keys.unshift(newKey)
    // Élagage par âge (borné par MAX_KEYS) : une clé n'est conservée que si un
    // token signé avec elle peut encore être dans sa fenêtre de validité.
    const cutoff = Date.now() - KEY_GRACE_MS
    const kept = this.keys.filter((k) => k.active || k.createdAt >= cutoff)
    this.keys = kept.length > MAX_KEYS ? kept.slice(0, MAX_KEYS) : kept
    this.persist()
    return newKey.kid
  }

  getJwks(): Jwks {
    return {
      keys: this.keys.map((k) => jwkFromPem(k.publicPem, k.kid)),
    }
  }

  getKey(kid: string): string | undefined {
    return this.keys.find((k) => k.kid === kid)?.publicPem
  }
}

/** Chemin de persistance par défaut : désactivé en test, fichier sinon. */
function defaultKeyringPath(): string | undefined {
  if (process.env.NODE_ENV === "test") return undefined
  if (process.env.JWKS_KEYRING_FILE) return process.env.JWKS_KEYRING_FILE
  return path.join(process.cwd(), "data", "jwks-keyring.json")
}

export const jwksService = new JwksService({ keyringPath: defaultKeyringPath() })
