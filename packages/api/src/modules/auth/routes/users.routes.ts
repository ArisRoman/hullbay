/**
 * Routes de gestion des utilisateurs (owner uniquement) — extraites de routes.ts.
 * Opérations auditées via eventBus (user.created / user.role.changed / user.deleted).
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify"
import { z } from "zod"
import { requireRole, currentUser } from "../authorization/rbac"
import { eventBus } from "../../../lib/event-bus"
import { authService } from "../service"

const owner = { preHandler: requireRole("owner") }

export async function registerUsersRoutes(app: FastifyInstance) {
  app.get(
    "/api/users",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Liste des utilisateurs (owner uniquement)",
        security: [{ bearerAuth: [] }],
      },
    },
    async () => authService.listUsers(),
  )

  const createUserBody = z.object({
    email: z.string().email(),
    password: z.string().min(8, "8 caractères minimum"),
    role: z.enum(["operator", "viewer"]),
  })

  app.post(
    "/api/users",
    {
      ...owner,
      schema: {
        body: createUserBody,
        tags: ["auth"],
        summary: "Création d'un utilisateur (owner uniquement)",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      try {
        const body = createUserBody.parse(req.body)
        const u = await authService.createUser(body.email, body.password, body.role)
        await eventBus.emit("user.created", {
          userId: currentUser(req)?.sub,
          targetUserId: u.id,
          email: u.email,
          role: u.role,
        })
        return u
      } catch (err) {
        return reply
          .code(400)
          .send({ error: err instanceof Error ? err.message : String(err) })
      }
    },
  )

  const setRoleBody = z.object({
    role: z.enum(["owner", "operator", "viewer"]),
  })

  app.post(
    "/api/users/:id/role",
    {
      ...owner,
      schema: {
        body: setRoleBody,
        tags: ["auth"],
        summary: "Changement de rôle d'un utilisateur (owner uniquement) — audité",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      try {
        const body = setRoleBody.parse(req.body)
        const u = await authService.setRole(id, body.role)
        await eventBus.emit("user.role.changed", {
          userId: currentUser(req)?.sub,
          targetUserId: id,
          role: u.role,
        })
        return u
      } catch (err) {
        return reply
          .code(400)
          .send({ error: err instanceof Error ? err.message : String(err) })
      }
    },
  )

  app.delete(
    "/api/users/:id",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Suppression d'un utilisateur (owner uniquement) — audité",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const acting = currentUser(req)?.sub
      if (!acting) return reply.code(401).send({ error: "non authentifié" })
      try {
        const r = await authService.deleteUser(id, acting)
        await eventBus.emit("user.deleted", {
          userId: acting,
          targetUserId: id,
        })
        return r
      } catch (err) {
        return reply
          .code(400)
          .send({ error: err instanceof Error ? err.message : String(err) })
      }
    },
  )
}
