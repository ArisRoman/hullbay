import { prisma } from "../../../lib/prisma"
import { authService } from "../service"

export async function listSessions(userId: string) {
  const sessions = await prisma.userSession.findMany({
    where: { userId, revokedAt: null },
    orderBy: { lastSeenAt: "desc" },
    select: { id: true, jti: true, providerId: true, createdAt: true, expiresAt: true, lastSeenAt: true, ip: true, userAgent: true },
  })
  return { sessions }
}

export async function revokeSession(jti: string) {
  const session = await prisma.userSession.update({ where: { jti }, data: { revokedAt: new Date() } }).catch(() => null)
  return session ? { revoked: true } : { revoked: false }
}
