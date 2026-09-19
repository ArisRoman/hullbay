/**
 * Routes de gestion et d'authentification WebAuthn / Passkeys (Phase 5A3).
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify"
import { z } from "zod"
import { createHash } from "node:crypto"
import { prisma } from "../../../lib/prisma"
import { authService } from "../service"
import { sessionManager } from "../core/session-manager"
import { resolveRoleForUser, resolveTenantIdForUser } from "../identity/auth-identity.service"
import { authRateLimiter, rateLimitTenant } from "../rate-limit"
import { AuthError } from "../providers/types"
import {
  generateWebauthnRegistrationOptions,
  verifyWebauthnRegistration,
  generateWebauthnAuthenticationOptions,
  verifyWebauthnAuthentication,
  listUserWebauthnCredentials,
  deleteUserWebauthnCredential,
} from "../mfa/webauthn"

function serializeError(err: unknown, fallbackStatus = 400) {
  const message = err instanceof Error ? err.message : String(err)
  const code =
    err && typeof err === "object" && "code" in err && typeof (err as { code?: unknown }).code === "string"
      ? (err as { code: string }).code
      : undefined
  const status =
    err && typeof err === "object" && "status" in err && typeof (err as { status?: unknown }).status === "number"
      ? (err as { status: number }).status
      : fallbackStatus

  const payload: { error: string; code?: string } = { error: message }
  if (code) payload.code = code

  return { status, payload }
}

function rateLimited(reply: FastifyReply, retryAfterSec: number) {
  return reply
    .code(429)
    .header("retry-after", String(retryAfterSec))
    .send({
      error: "Too many attempts, please retry in a few seconds",
      code: "rate_limited",
    })
}

/**
 * Discriminant de challenge isolé par token : empêche qu'une cérémonie en cours
 * soit écrasée par une autre requête (self-DoS / TOCTOU). Ne dérive jamais le
 * token lui-même vers le store (hash seul).
 */
function challengeKeyFromRequest(req: FastifyRequest, pendingToken?: string): string | undefined {
  const authHeader = req.headers.authorization
  const raw =
    pendingToken ??
    (authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined)
  if (!raw) return undefined
  return createHash("sha256").update(raw).digest("hex").slice(0, 32)
}

function resolveUserIdFromTokenOrSession(req: FastifyRequest, pendingToken?: string): string {
  if (pendingToken) {
    const { sub } = sessionManager.verifyPending(pendingToken)
    return sub
  }

  const authHeader = req.headers.authorization
  if (authHeader?.startsWith("Bearer ")) {
    const decoded = sessionManager.verifySession(authHeader.slice(7))
    return decoded.sub
  }

  throw new AuthError("session_invalid", "Unauthorized session", 401)
}

export async function registerWebauthnRoutes(app: FastifyInstance) {
  // ── Enrôlement / Options (authentifié) ──
  app.post(
    "/api/auth/mfa/webauthn/register/options",
    {
      schema: {
        tags: ["auth"],
        summary: "Génère les options d'enregistrement d'une clé WebAuthn",
      },
    },
    async (req, reply) => {
      try {
        const userId = (req as FastifyRequest & { user: { sub: string } }).user?.sub
        if (!userId) return reply.code(401).send({ error: "non authentifié" })

        const clientOrigin = (req.headers.origin as string) || undefined
        const options = await generateWebauthnRegistrationOptions(
          userId,
          clientOrigin,
          challengeKeyFromRequest(req),
        )
        return options
      } catch (err) {
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Enrôlement / Vérification (authentifié) ──
  const registerVerifyBody = z.object({
    response: z.any(),
    name: z.string().optional(),
  })

  app.post(
    "/api/auth/mfa/webauthn/register/verify",
    {
      schema: {
        body: registerVerifyBody,
        tags: ["auth"],
        summary: "Vérifie et enregistre une clé WebAuthn",
      },
    },
    async (req, reply) => {
      try {
        const userId = (req as FastifyRequest & { user: { sub: string } }).user?.sub
        if (!userId) return reply.code(401).send({ error: "Unauthorized", code: "session_invalid" })

        const body = req.body as { response: any; name?: string }
        const clientOrigin = (req.headers.origin as string) || undefined
        const res = await verifyWebauthnRegistration(
          userId,
          body,
          clientOrigin,
          challengeKeyFromRequest(req),
        )
        return res
      } catch (err) {
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Authentification / Options (MFA pending ou session) ──
  const authOptionsBody = z.object({
    pendingToken: z.string().optional(),
  })

  app.post(
    "/api/auth/mfa/webauthn/auth/options",
    {
      schema: {
        body: authOptionsBody,
        tags: ["auth"],
        summary: "Génère les options d'authentification pour clé WebAuthn",
      },
    },
    async (req, reply) => {
      const body = (req.body as { pendingToken?: string }) ?? {}
      try {
        const userId = resolveUserIdFromTokenOrSession(req, body.pendingToken)
        const clientOrigin = (req.headers.origin as string) || undefined
        const options = await generateWebauthnAuthenticationOptions(
          userId,
          clientOrigin,
          challengeKeyFromRequest(req, body.pendingToken),
        )
        return options
      } catch (err) {
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Authentification / Vérification (MFA pending ou step-up) ──
  const authVerifyBody = z.object({
    pendingToken: z.string().optional(),
    response: z.any(),
  })

  app.post(
    "/api/auth/mfa/webauthn/auth/verify",
    {
      schema: {
        body: authVerifyBody,
        tags: ["auth"],
        summary: "Vérifie la signature WebAuthn et émet la session",
      },
    },
    async (req, reply) => {
      const body = req.body as { pendingToken?: string; response: any }
      const throttleKey = body.pendingToken
        ? createHash("sha256").update(body.pendingToken).digest("hex").slice(0, 32)
        : req.ip
      const key = authRateLimiter.keyFor(req.ip, "/api/auth/mfa/webauthn/auth/verify", throttleKey, rateLimitTenant(req))
      const before = authRateLimiter.check(key, rateLimitTenant(req))
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)

      try {
        const userId = resolveUserIdFromTokenOrSession(req, body.pendingToken)
        const clientOrigin = (req.headers.origin as string) || undefined
        await verifyWebauthnAuthentication(
          userId,
          { response: body.response },
          clientOrigin,
          challengeKeyFromRequest(req, body.pendingToken),
        )

        authRateLimiter.reset(key, rateLimitTenant(req))

        const user = await prisma.user.findUnique({
          where: { id: userId },
          select: { id: true, role: true },
        })
        if (!user) return reply.code(404).send({ error: "User not found", code: "user_not_found" })

        const tenantId = await resolveTenantIdForUser(user.id)
        const role = await resolveRoleForUser(user.id, tenantId, user.role)
        return {
          ok: true,
          token: sessionManager.signSession(user.id, role, true, "local", tenantId),
        }
      } catch (err) {
        authRateLimiter.recordFailure(key, rateLimitTenant(req))
        const { status, payload } = serializeError(err, 401)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Liste des credentials de l'utilisateur (authentifié) ──
  app.get(
    "/api/auth/mfa/webauthn/credentials",
    {
      schema: {
        tags: ["auth"],
        summary: "Liste les clés de sécurité de l'utilisateur",
      },
    },
    async (req, reply) => {
      try {
        const userId = (req as FastifyRequest & { user: { sub: string } }).user?.sub
        if (!userId) return reply.code(401).send({ error: "Unauthorized", code: "session_invalid" })

        const credentials = await listUserWebauthnCredentials(userId)
        return credentials
      } catch (err) {
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )

  // ── Révocation d'un credential (authentifié) ──
  app.delete(
    "/api/auth/mfa/webauthn/credentials/:id",
    {
      schema: {
        tags: ["auth"],
        summary: "Supprime une clé de sécurité",
      },
    },
    async (req, reply) => {
      try {
        const userId = (req as FastifyRequest & { user: { sub: string } }).user?.sub
        if (!userId) return reply.code(401).send({ error: "Unauthorized", code: "session_invalid" })

        const { id } = req.params as { id: string }
        await deleteUserWebauthnCredential(userId, id)
        return reply.code(204).send()
      } catch (err) {
        const { status, payload } = serializeError(err, 400)
        return reply.code(status).send(payload)
      }
    },
  )
}
