import crypto from "node:crypto"
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

const ALG = "RS256"

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

export class JwksService {
  private keys: SigningKey[] = []
  private legacySecret: string

  constructor() {
    this.legacySecret = process.env.JWT_SECRET ?? "fallback-jwt-secret-change-me"
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string
    const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string
    const firstKid = generateKid()
    this.keys.push({ kid: firstKid, privatePem, publicPem, createdAt: Date.now(), active: true })
  }

  getActiveKid(): string {
    const active = this.keys.find((k) => k.active)
    return active ? active.kid : (this.keys[0]!.kid)
  }

  signPayload(payload: object): string {
    const kid = this.getActiveKid()
    const signingKey = this.keys.find((k) => k.kid === kid)?.privatePem ?? this.keys[0]!.privatePem
    return jwt.sign(payload, signingKey, { algorithm: ALG, header: { kid, alg: ALG } })
  }

  verifyToken(token: string, audience?: string): jwt.JwtPayload {
    const decoded = jwt.decode(token, { complete: true })
    if (!decoded || typeof decoded === "string") throw new Error("token invalide")
    const kid = decoded.header.kid as string | undefined

    if (kid) {
      const key = this.keys.find((k) => k.kid === kid)?.publicPem
      if (key) {
        const opts: jwt.VerifyOptions = { algorithms: [ALG] }
        if (audience) opts.audience = audience
        return jwt.verify(token, key, opts) as jwt.JwtPayload
      }
    }

    try {
      const opts: jwt.VerifyOptions = { algorithms: ["HS256"], audience }
      return jwt.verify(token, this.legacySecret, opts) as jwt.JwtPayload
    } catch {
      throw new Error("key inconnue")
    }
  }

  rotate(): string {
    const oldActive = this.keys.find((k) => k.active)
    if (oldActive) oldActive.active = false
    const newKid = generateKid()
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string
    const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string
    this.keys.unshift({ kid: newKid, privatePem, publicPem, createdAt: Date.now(), active: true })
    return newKid
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

export const jwksService = new JwksService()