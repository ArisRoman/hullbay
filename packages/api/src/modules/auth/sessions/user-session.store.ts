import jwt from "jsonwebtoken"
import { prisma } from "../../../lib/prisma"
import { Redis } from "ioredis"
import { randomUUID } from "node:crypto"
import { AuthError } from "../providers/types"
import { jwksService } from "../jwks/jwks.service"

export interface SessionHandle {
  sub: string
  role: string
  mfaEnabled: boolean
}

export interface SessionStore {
  signSession(userId: string, role: string, mfaEnabled: boolean): string
  verifySession(token: string): SessionHandle
  signPending(userId: string): string
  verifyPending(token: string): { sub: string }
}

const AUD_SESSION = "session"
const AUD_MFA_PENDING = "mfa-pending"
const PENDING_TTL = "5m"

const redis = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379")
const activeSessions = new Map<string, SessionHandle>()

async function cacheSession(jti: string, data: SessionHandle, ttlMs: number): Promise<void> {
  activeSessions.set(jti, data)
  await redis.set(`sess:${jti}`, JSON.stringify(data), "EX", Math.floor(ttlMs / 1000))
}

async function markRevoked(jti: string, ttlMs: number): Promise<void> {
  activeSessions.delete(jti)
  await redis.set(`revoked:${jti}`, "1", "EX", Math.floor(ttlMs / 1000))
}

function legacySecret(): string {
  return process.env.JWT_SECRET ?? "fallback-jwt-secret-change-me"
}

export class UserSessionStore implements SessionStore {
  signSession(userId: string, role: string, mfaEnabled: boolean): string {
    const jti = randomUUID()
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000)
    const token = jwksService.signPayload({ sub: userId, role, mfaEnabled, jti })
    const handle: SessionHandle = { sub: userId, role, mfaEnabled }
    if (prisma.userSession) prisma.userSession.create({ data: { jti, userId, providerId: "local", expiresAt } }).catch(() => {})
    cacheSession(jti, handle, 12 * 60 * 60 * 1000).catch(() => {})
    return token
  }

  verifySession(token: string): SessionHandle {
    const decoded = jwksService.verifyToken(token) as { sub?: string; role?: string; mfaEnabled?: boolean; jti?: string }
    if (!decoded.sub || !decoded.role) throw new Error("token de session invalide")

    const jti = decoded.jti
    if (!jti) throw new Error("token de session sans jti")

    const cached = activeSessions.get(jti)
    if (cached) {
      if (prisma.userSession) prisma.userSession.update({ where: { jti }, data: { lastSeenAt: new Date() } }).catch(() => {})
      return cached
    }

    prisma.userSession.findUnique({ where: { jti } }).then(async (session: { revokedAt?: Date | null; expiresAt: Date } | null) => {
      if (!session || session.revokedAt) {
        await markRevoked(jti, 12 * 60 * 60 * 1000).catch(() => {})
      } else {
        await cacheSession(jti, { sub: decoded.sub!, role: decoded.role!, mfaEnabled: decoded.mfaEnabled ?? false }, 12 * 60 * 60 * 1000).catch(() => {})
        if (prisma.userSession) prisma.userSession.update({ where: { jti }, data: { lastSeenAt: new Date() } }).catch(() => {})
      }
    }).catch(() => {})

    return { sub: decoded.sub!, role: decoded.role!, mfaEnabled: decoded.mfaEnabled ?? false }
  }

  signPending(userId: string): string {
    return jwt.sign({ sub: userId, mfa: "pending" }, legacySecret(), {
      expiresIn: PENDING_TTL,
      audience: AUD_MFA_PENDING,
    })
  }

  verifyPending(token: string): { sub: string } {
    let decoded: { sub?: string; mfa?: string }
    try {
      decoded = jwt.verify(token, legacySecret(), { audience: AUD_MFA_PENDING }) as { sub?: string; mfa?: string }
    } catch {
      throw new AuthError("mfa_token_invalid", "token MFA invalide", 401)
    }
    if (decoded.mfa !== "pending" || !decoded.sub) {
      throw new AuthError("mfa_token_invalid", "token MFA invalide", 401)
    }
    return { sub: decoded.sub }
  }
}

export const userSessionStore: SessionStore = new UserSessionStore()