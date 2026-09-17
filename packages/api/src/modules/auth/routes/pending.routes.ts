/**
 * Routes d'administration des identités externes en attente d'approbation
 * (owner uniquement, Phase 5A1 / correction N°20).
 *
 * GET  /api/auth/admin/pendings              → liste des demandes
 * POST /api/auth/admin/pendings/:id/approve  → {tenantId, role} → User+AuthIdentity+Membership
 * POST /api/auth/admin/pendings/:id/reject   → marque rejected
 *
 * Anti-énumération : id inconnu OU demande déjà traitée → 404 uniforme.
 * Le role du User mirror V1 et la Membership reçoivent le rôle demandé.
 */

import type { FastifyInstance } from "fastify"
import { z } from "zod"
import { requireRole, currentUser } from "../authorization/rbac"
import { prisma } from "../../../lib/prisma"
import {
  listPendingIdentities,
  getPendingIdentity,
  approvePendingIdentity,
  rejectPendingIdentity,
  PendingApprovalError,
} from "../identity/pending-approval.service"

const owner = { preHandler: requireRole("owner") }

export async function registerPendingRoutes(app: FastifyInstance) {
  // Tenants disponibles pour l'approbation (owner). Le tenant de rattachement
  // (Membership) est un choix de l'owner au moment d'approuver — on liste ici
  // les cibles possibles pour alimenter l'UI, jamais les membres.
  app.get(
    "/api/auth/admin/tenants",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Liste des tenants (owner) pour l'approbation d'identités",
        security: [{ bearerAuth: [] }],
      },
    },
    async () =>
      prisma.tenant.findMany({
        select: { id: true, name: true, slug: true },
        orderBy: { createdAt: "asc" },
      }),
  )

  app.get(
    "/api/auth/admin/pendings",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Liste des identités externes en attente d'approbation (owner)",
        security: [{ bearerAuth: [] }],
      },
    },
    async () => listPendingIdentities(),
  )

  const approveBody = z.object({
    tenantId: z.string().min(1, "tenant requis"),
    role: z.enum(["owner", "operator", "viewer"]),
  })

  app.post(
    "/api/auth/admin/pendings/:id/approve",
    {
      ...owner,
      schema: {
        body: approveBody,
        tags: ["auth"],
        summary: "Approuve une identité : crée User + AuthIdentity + Membership (owner)",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const body = approveBody.parse(req.body)
      const pending = await getPendingIdentity(id)
      if (!pending) return reply.code(404).send({ error: "demande introuvable ou déjà traitée" })
      try {
        const result = await approvePendingIdentity(pending, currentUser(req)?.sub, {
          tenantId: body.tenantId,
          role: body.role,
        })
        return {
          ok: true,
          user: result,
          message: "identité approuvée — compte provisionné",
        }
      } catch (err) {
        if (err instanceof PendingApprovalError) {
          return reply.code(400).send({ error: err.message })
        }
        throw err
      }
    },
  )

  const rejectBody = z.object({
    reason: z.string().max(500).optional(),
  })

  app.post(
    "/api/auth/admin/pendings/:id/reject",
    {
      ...owner,
      schema: {
        body: rejectBody,
        tags: ["auth"],
        summary: "Rejette une identité en attente (owner) — trace conservée",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const body = rejectBody.parse(req.body)
      const pending = await getPendingIdentity(id)
      if (!pending) return reply.code(404).send({ error: "demande introuvable ou déjà traitée" })
      await rejectPendingIdentity(pending, currentUser(req)?.sub, body.reason)
      return { ok: true, message: "demande rejetée" }
    },
  )
}