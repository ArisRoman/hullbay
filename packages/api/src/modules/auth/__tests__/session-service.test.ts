import { describe, it, expect, beforeEach, vi } from "vitest"

vi.mock("../../../lib/prisma", () => ({
  prisma: { userSession: { findMany: vi.fn(), update: vi.fn() } },
}))

import { prisma } from "../../../lib/prisma"
import { listSessions, revokeSession } from "../sessions/session.service"

function row(jti: string) {
  return {
    id: `id-${jti}`,
    jti,
    providerId: "local",
    createdAt: new Date(),
    expiresAt: new Date(),
    lastSeenAt: new Date(),
    ip: null,
    userAgent: null,
  }
}

describe("session.service.listSessions", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("marque la session courante via currentJti", async () => {
    vi.mocked(prisma.userSession.findMany).mockResolvedValue([
      row("aaa"),
      row("bbb"),
    ] as never)

    const { sessions } = await listSessions("u-1", "bbb")

    expect(sessions.find((s) => s.jti === "bbb")?.current).toBe(true)
    expect(sessions.find((s) => s.jti === "aaa")?.current).toBe(false)
  })

  it("aucune session courante si currentJti absent (admin/autre utilisateur)", async () => {
    vi.mocked(prisma.userSession.findMany).mockResolvedValue([row("aaa")] as never)

    const { sessions } = await listSessions("u-1")

    expect(sessions.every((s) => s.current === false)).toBe(true)
  })
})

describe("session.service.revokeSession", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("invalide le cache et persiste la révocation (revokedAt)", async () => {
    vi.mocked(prisma.userSession.update).mockResolvedValue({} as never)
    const res = await revokeSession("some-jti")
    expect(res).toEqual({ revoked: true })
    expect(prisma.userSession.update).toHaveBeenCalledWith({
      where: { jti: "some-jti" },
      data: { revokedAt: expect.any(Date) },
    })
  })
})
