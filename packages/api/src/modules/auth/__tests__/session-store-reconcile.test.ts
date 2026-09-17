import { describe, it, expect, beforeEach, vi } from "vitest"
import jwt from "jsonwebtoken"

vi.mock("../../../lib/prisma", () => ({
  prisma: {
    userSession: { create: vi.fn(), update: vi.fn(), findUnique: vi.fn() },
    user: { findUnique: vi.fn() },
  },
}))

import { prisma } from "../../../lib/prisma"
import { jwksService } from "../jwks/jwks.service"
import { UserSessionStore } from "../sessions/user-session.store"
import { securityPolicy } from "../policies/security-policy.service"

const flush = () => new Promise((r) => setTimeout(r, 30))

function issue(jti: string, sub = "u-1") {
  return jwksService.signPayload(
    { sub, role: "owner", mfaEnabled: true, jti },
    { audience: "session", expiresIn: 3600 },
  )
}

describe("UserSessionStore — sécurité des tokens", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(prisma.userSession.create).mockResolvedValue({} as never)
    vi.mocked(prisma.userSession.update).mockResolvedValue({} as never)
  })

  it("signSession émet un token avec audience 'session' et un exp", () => {
    const store = new UserSessionStore()
    const decoded = jwt.decode(store.signSession("u-1", "owner", true)) as {
      aud?: string
      exp?: number
      jti?: string
    }
    expect(decoded.aud).toBe("session")
    expect(typeof decoded.exp).toBe("number")
    expect(decoded.jti).toBeTruthy()
  })

  it("backfill la row manquante au lieu de révoquer un token légitime", async () => {
    vi.mocked(prisma.userSession.findUnique).mockResolvedValue(null as never)
    const store = new UserSessionStore()
    const token = issue("jti-backfill")

    expect(store.verifySession(token).sub).toBe("u-1")
    await flush()

    expect(prisma.userSession.create).toHaveBeenCalled()
    // Toujours valide après réconciliation (pas de révocation à tort).
    expect(store.verifySession(token).sub).toBe("u-1")
  })

  it("révoque une session dont la row porte revokedAt", async () => {
    vi.mocked(prisma.userSession.findUnique).mockResolvedValue({
      revokedAt: new Date(),
      expiresAt: new Date(Date.now() + 3_600_000),
    } as never)
    const store = new UserSessionStore()
    const token = issue("jti-revoked")

    store.verifySession(token)
    await flush()

    expect(() => store.verifySession(token)).toThrow("session révoquée")
  })

  it("ne backfill PAS et révoque si l'utilisateur n'existe plus", async () => {
    vi.mocked(prisma.userSession.findUnique).mockResolvedValue(null as never)
    vi.mocked(prisma.user.findUnique).mockResolvedValue(null as never)
    const store = new UserSessionStore()
    const token = issue("jti-user-gone")

    store.verifySession(token)
    await flush()

    expect(prisma.userSession.create).not.toHaveBeenCalled()
    expect(() => store.verifySession(token)).toThrow("session révoquée")
  })

  it("respecte le sessionTtlMs de la policy live à la signature", () => {
    securityPolicy.override({ sessionTtlMs: 1000 })
    try {
      const store = new UserSessionStore()
      const decoded = jwt.decode(store.signSession("u-1", "owner", true)) as { exp: number; iat: number }
      expect(decoded.exp - decoded.iat).toBe(1)
    } finally {
      securityPolicy.override({ sessionTtlMs: 43_200_000 })
    }
  })

  it("révoque une session dont la row est expirée", async () => {
    vi.mocked(prisma.userSession.findUnique).mockResolvedValue({
      revokedAt: null,
      expiresAt: new Date(Date.now() - 1000),
    } as never)
    const store = new UserSessionStore()
    const token = issue("jti-expired")

    store.verifySession(token)
    await flush()

    expect(() => store.verifySession(token)).toThrow("session révoquée")
  })
})
