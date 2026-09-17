import type { FastifyInstance, FastifyRequest } from "fastify"
import { prisma } from "../../../lib/prisma"

export async function registerSessionsRoutes(app: FastifyInstance) {
  app.get(
    "/api/auth/sessions",
    { schema: { tags: ["auth"], summary: "Lister les sessions actives" } },
    async (req: FastifyRequest) => {
      const user = (req as FastifyRequest & { user?: { sub: string } }).user
      const userId = user?.sub
      if (!userId) return { sessions: [] }
      const sessions = await prisma.userSession.findMany({
        where: { userId, revokedAt: null },
        orderBy: { lastSeenAt: "desc" },
        select: { id: true, jti: true, providerId: true, createdAt: true, expiresAt: true, lastSeenAt: true, ip: true, userAgent: true },
      })
      return { sessions }
    },
  )

  app.delete(
    "/api/auth/sessions/:jti",
    { schema: { tags: ["auth"], summary: "Révoquer une session" } },
    async (req, reply) => {
      const { jti } = req.params as { jti: string }
      await prisma.userSession.update({ where: { jti }, data: { revokedAt: new Date() } }).catch(() => null)
      return reply.code(204).send()
    },
  )
}
