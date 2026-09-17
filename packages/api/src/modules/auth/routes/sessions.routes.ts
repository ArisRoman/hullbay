import type { FastifyInstance, FastifyRequest } from "fastify"
import { prisma } from "../../../lib/prisma"
import { listSessions, revokeSession } from "../sessions/session.service"

type SessionUser = { sub?: string; jti?: string }

function currentUser(req: FastifyRequest): SessionUser {
  return ((req as FastifyRequest & { user?: SessionUser }).user ?? {}) as SessionUser
}

export async function registerSessionsRoutes(app: FastifyInstance) {
  app.get(
    "/api/auth/sessions",
    { schema: { tags: ["auth"], summary: "Lister les sessions actives" } },
    async (req: FastifyRequest) => {
      const { sub: userId, jti } = currentUser(req)
      if (!userId) return { sessions: [] }
      return listSessions(userId, jti)
    },
  )

  app.delete(
    "/api/auth/sessions/:jti",
    { schema: { tags: ["auth"], summary: "Révoquer une session" } },
    async (req, reply) => {
      const { jti } = req.params as { jti: string }
      const { sub: userId } = currentUser(req)
      if (!userId) return reply.code(401).send({ error: "non authentifié" })

      // Contrôle de propriété : un utilisateur ne peut révoquer que SES sessions.
      // Réponse 404 uniforme (pas de 403) pour ne pas révéler l'existence du jti.
      const session = await prisma.userSession.findUnique({ where: { jti }, select: { userId: true } })
      if (!session || session.userId !== userId) {
        return reply.code(404).send({ error: "session introuvable" })
      }

      await revokeSession(jti)
      return reply.code(204).send()
    },
  )
}
