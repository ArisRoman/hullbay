/**
 * Routes d'authentification LDAP / LDAPS (Phase 5A3).
 */

import type { FastifyInstance, FastifyReply } from "fastify"
import { z } from "zod"
import { providerRegistry } from "../registry/provider-registry"
import { sessionManager } from "../core/session-manager"
import { resolveTenantIdForUser } from "../identity/auth-identity.service"
import { userHasMfaFactor } from "../core/auth-core"
import { eventBus } from "../../../lib/event-bus"
import { AUTH_AUDIT_EVENTS } from "../audit-events"
import { authRateLimiter } from "../rate-limit"
import { IdentityPendingError } from "../core/identity-mapping"

function serializeError(err: unknown, fallbackStatus = 400) {
  const message = err instanceof Error ? err.message : String(err)
  const code =
    err && typeof err === "object" && "code" in err && typeof (err as { code?: unknown }).code === "string"
      ? (err as { code: string }).code
      : undefined
  // Un AuthError porte son propre status (401, 403…) ; on ne le remplace pas par
  // le fallback, sinon un 403 serait rapporté à tort comme un 401.
  const status =
    err && typeof err === "object" && typeof (err as { status?: unknown }).status === "number"
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
      error: "trop de tentatives, réessayez dans quelques secondes",
      code: "rate_limited",
    })
}

function traceLdapFailed(providerId: string, username: string, code: string | undefined): void {
  void eventBus
    .emit(AUTH_AUDIT_EVENTS.ldapFailed, { providerId, username, reason: code ?? "invalid_credentials" })
    .catch(() => {})
}

export async function registerLdapRoutes(app: FastifyInstance) {
  const loginBody = z.object({
    username: z.string().min(1),
    password: z.string().min(1),
  })

  app.post(
    "/api/auth/ldap/:id/login",
    {
      schema: {
        body: loginBody,
        tags: ["auth"],
        summary: "Connexion via un provider LDAP / LDAPS",
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const body = req.body as { username: string; password: string }

      const key = authRateLimiter.keyFor(req.ip, `/api/auth/ldap/${id}/login`, body.username)
      const before = authRateLimiter.check(key)
      if (before.blocked) return rateLimited(reply, before.retryAfterSec ?? 1)

      try {
        // Pas de `require()` : son message interne (FR) ne doit jamais fuiter tel
        // quel. On répond un 404 uniforme (même anti-énumération que les SSO).
        const provider = providerRegistry.get(id)
        if (!provider || provider.kind !== "ldap" || !provider.enabled) {
          return reply.code(404).send({ error: "provider LDAP introuvable ou désactivé", code: "provider_not_found" })
        }

        const result = await provider.authenticate({
          kind: "ldap",
          ldapUsername: body.username,
          ldapPassword: body.password,
        })

        authRateLimiter.reset(key)

        // Audit de succès au niveau credentials (miroir des logins local/SSO) :
        // la décision MFA qui suit est un état intermédiaire, pas un échec.
        void eventBus
          .emit(AUTH_AUDIT_EVENTS.loginSuccess, { providerId: id, userId: result.userId, method: "ldap" })
          .catch(() => {})

        // Politique MFA : par défaut l'IdP fournit la 2e MFA (comme les SSO), donc
        // la session est valide. Si la politique exige une MFA locale :
        //  - un facteur est déjà enrôlé → token pending, vérification TOTP/WebAuthn ;
        //  - aucun facteur → session "setup" (mfaEnabled=false) : la garde limite
        //    l'accès aux routes d'enrôlement et /me force l'activation.
        if (result.mfaRequired) {
          if (await userHasMfaFactor(result.userId)) {
            return {
              mfaRequired: true as const,
              pendingToken: sessionManager.signPending(result.userId),
            }
          }
          return {
            mfaRequired: false as const,
            token: sessionManager.signSession(result.userId, result.role, false, id, await resolveTenantIdForUser(result.userId)),
          }
        }

        return {
          mfaRequired: false as const,
          token: sessionManager.signSession(result.userId, result.role, true, id, await resolveTenantIdForUser(result.userId)),
        }
      } catch (err) {
        authRateLimiter.recordFailure(key)

        if (err instanceof IdentityPendingError) {
          return reply.code(403).send({
            error: "Cette identité est en attente d'approbation par un administrateur.",
            code: "identity_pending_approval",
          })
        }

        const { status, payload } = serializeError(err, 401)
        traceLdapFailed(id, body.username, payload.code)
        return reply.code(status).send(payload)
      }
    },
  )
}
