/**
 * Routes d'authentification — extraites de routes.ts (comportements identiques).
 * Appelle auth-core.ts (façade métier) + authRateLimiter pour la protection brute-force.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify"
import { z } from "zod"
import { createHash } from "node:crypto"
import { prisma } from "../../../lib/prisma"
import { requireRole, currentUser } from "../authorization/rbac"
import type { TenantScopedRequest } from "../tenancy/tenant-resolver"
import { authRateLimiter } from "../rate-limit"
import { registerUsersRoutes } from "./users.routes"
import { authService } from "../service"
import { securityPolicy } from "../policies/security-policy.service"

function serializeError(err: unknown, fallbackStatus = 400) {
  const message = err instanceof Error ? err.message : String(err)
  const code =
    err && typeof err === "object" && "code" in err && typeof (err as { code?: unknown }).code === "string"
      ? (err as { code: string }).code
      : undefined

  const payload: { error: string; code?: string } = { error: message }
  if (code) payload.code = code

  return { status: fallbackStatus, payload }
}

function rateLimited(reply: FastifyReply, retryAfterSec: number) {
  return reply
    .code(429)
    .header("retry-after", String(retryAfterSec))
    .send({
      error: "trop de tentatives, réessayez dans quelques secondes",
      code: "rate_limited",
    })
}

export async function registerAuthRoutes(app: FastifyInstance) {
  // Routes users (owner CRUD)
  await registerUsersRoutes(app)

  const credBody = z.object({
    email: z.string().email(),
    password: z.string().min(8),
  })

  // ── Bootstrap : crée le compte owner si aucun n'existe ──
  app.post(
    "/api/auth/bootstrap",
    {
      schema: {
        body: credBody,
        tags: ["auth"],
        summary: "Création du 1er compte owner (bootstrap)",
      },
    },
    async (req, reply) => {
      const body = req.body as { email: string; password: string }
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/bootstrap")
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)
      try {
        const user = await authService.createOwner(body.email, body.password)
        authRateLimiter.reset(key)
        return { ok: true, id: user.id }
      } catch (err) {
        authRateLimiter.recordFailure(key)
        const { status, payload } = serializeError(err, 409)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Onboarding : le front interroge ceci pour le mode "créer 1er compte" ──
  app.get(
    "/api/auth/needs-bootstrap",
    {
      schema: { tags: ["auth"] },
    },
    async () => {
      // Pas de rate-limit ici : la route est un simple read public et le bucket
      // n'était jamais armé (aucun recordFailure) — check() était un no-op.
      return { needsBootstrap: (await authService.countUsers()) === 0 }
    },
  )

  // ── Login ──
  app.post(
    "/api/auth/login",
    {
      schema: {
        body: credBody,
        tags: ["auth"],
        summary: "Connexion (email + mot de passe)",
      },
    },
    async (req, reply) => {
      const body = req.body as { email: string; password: string }
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/login", body.email)
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)
      try {
        const result = await authService.login(body.email, body.password)
        authRateLimiter.reset(key)
        return result
      } catch (err) {
        authRateLimiter.recordFailure(key)
        const { status, payload } = serializeError(err, 401)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── MFA / verify ──
  const verifyMfa = z.object({
    pendingToken: z.string(),
    code: z.string(),
  })

  app.post(
    "/api/auth/mfa/verify",
    {
      schema: {
        body: verifyMfa,
        tags: ["auth"],
        summary: "Vérification MFA (code + pendingToken)",
      },
    },
    async (req, reply) => {
      const body = req.body as { pendingToken: string; code: string }
      // Clé de rate-limit dérivée du token BRUT (hashé), jamais d'un claim
      // décodé sans vérification : sinon un attaquant forgerait `sub` pour
      // échapper au throttle par compte et brute-forcer le TOTP.
      const account = createHash("sha256").update(body.pendingToken).digest("hex").slice(0, 32)
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/mfa/verify", account)
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)
      try {
        const result = await authService.verifyMfa(body.pendingToken, body.code)
        authRateLimiter.reset(key)
        return result
      } catch (err) {
        authRateLimiter.recordFailure(key)
        const { status, payload } = serializeError(err, 401)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Enrôlement MFA (authentifié) ──
  app.post(
    "/api/auth/mfa/enroll",
    {
      schema: { tags: ["auth"] },
    },
    async (req) => {
      const user = (req as FastifyRequest & { user: { sub: string } }).user
      return authService.startMfaEnrollment(user.sub)
    },
  )

  const confirmMfa = z.object({ code: z.string() })

  app.post(
    "/api/auth/mfa/confirm",
    {
      schema: {
        body: confirmMfa,
        tags: ["auth"],
        summary: "Confirmation de l'authentification MFA",
      },
    },
    async (req, reply) => {
      const user = (req as FastifyRequest & { user: { sub: string } }).user
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/mfa/confirm", user.sub)
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)
      try {
        const body = req.body as { code: string }
        const result = await authService.confirmMfaEnrollment(user.sub, body.code)
        authRateLimiter.reset(key)
        return result
      } catch (err) {
        authRateLimiter.recordFailure(key)
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Me ──
  app.get(
    "/api/auth/me",
    { schema: { tags: ["auth"], security: [{ bearerAuth: [] }] } },
    async (req) => {
      const user = (req as FastifyRequest & { user: { sub: string } }).user
      const u = await prisma.user.findUnique({ where: { id: user.sub } })
      // mfaEnabled vit sur les AuthIdentity ; on reste sur prisma.user pour
      // id/email/role (compat), identities en lookup best-effort.
      const identities =
        (await prisma.authIdentity?.findMany?.({
          where: { userId: user.sub },
          select: { kind: true, mfaEnabled: true },
        })) ?? []
      const local = identities.find((i) => i.kind === "local")
      // Repli sur User.mfaEnabled (colonnes legacy) si la table identities n'est
      // pas interrogeable (mocks/tests) — sinon on resterait bloqué à false.
      const mfaEnabled = identities.length
        ? identities.some((i) => i.mfaEnabled)
        : ((u as { mfaEnabled?: boolean } | null)?.mfaEnabled ?? false)
      // Compte local : enrôlement obligatoire. Compte externe (LDAP/OIDC/SAML) :
      // pas de 2e MFA locale, sauf si la politique cible le rôle.
      const policyRequires =
        securityPolicy.getPolicy().mfaRequireRoles.includes((u?.role ?? "").toLowerCase())
      const mfaRequired = local
        ? !local.mfaEnabled
        : Boolean(u) && policyRequires && !mfaEnabled
      return {
        id: u?.id,
        email: u?.email,
        role: u?.role,
        mfaEnabled,
        mfaRequired,
      }
    },
  )

  // ── Changement de mot de passe ──
  const changePwBody = z.object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(8, "8 caractères minimum"),
  })

  app.post(
    "/api/auth/password",
    {
      schema: {
        body: changePwBody,
        tags: ["auth"],
        summary: "Changement de mot de passe (authentifié)",
      },
    },
    async (req, reply) => {
      const user = (req as FastifyRequest & { user: { sub: string } }).user
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/password", user.sub)
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)
      try {
        const body = req.body as { currentPassword: string; newPassword: string }
        const result = await authService.changePassword(user.sub, body.currentPassword, body.newPassword)
        authRateLimiter.reset(key)
        return result
      } catch (err) {
        authRateLimiter.recordFailure(key)
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Journal d'audit (operator+) ──
  app.get(
    "/api/audit",
    {
      preHandler: requireRole("operator"),
      schema: {
        tags: ["auth"],
        summary: "Journal d'audit (operator+) — paginé, filtrable par action",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req) => {
      const q = req.query as {
        limit?: string
        offset?: string
        action?: string
      }
      const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200)
      const offset = Math.max(Number(q.offset) || 0, 0)
      const tenantId = (req as TenantScopedRequest).tenantId
      const where = { tenantId, ...(q.action ? { action: q.action } : {}) }
      const [rows, total] = await Promise.all([
        prisma.auditLog.findMany({
          where,
          orderBy: { createdAt: "desc" },
          skip: offset,
          take: limit,
          include: { user: { select: { email: true } } },
        }),
        prisma.auditLog.count({ where }),
      ])
      return {
        total,
        limit,
        offset,
        entries: rows.map((r) => ({
          id: r.id,
          action: r.action,
          userEmail: r.user?.email ?? null,
          projectId: r.projectId,
          serverId: r.serverId,
          nodeId: r.nodeId,
          ip: r.ip,
          payload: r.payload,
          createdAt: r.createdAt,
        })),
      }
    },
  )
}
