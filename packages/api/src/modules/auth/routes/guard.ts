/**
 * Garde d'authentification sur /api/* (déplacée depuis routes.ts, comportement identique).
 * Tout /api/* est protégé SAUF les routes publiques (login, mfa/verify, bootstrap,
 * needs-bootstrap) et les routes MFA_SETUP qui acceptent un token mfa-pending valide
 * ou un token de session.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify"
import { authService } from "../service"
import { sessionManager } from "../core/session-manager"

const PUBLIC_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/mfa/verify",
  "/api/auth/bootstrap",
  "/api/auth/needs-bootstrap",
  // Liste des providers activés (login sans token).
  "/api/auth/providers",
  "/api/system/environment",
])

// Flux SSO (initiateLogin + callback) : routes à préfixe dynamique.
const PUBLIC_PATH_PREFIXES = ["/api/auth/sso/"]

function isPublicPath(path: string): boolean {
  if (PUBLIC_PATHS.has(path)) return true
  return PUBLIC_PATH_PREFIXES.some((prefix) => path.startsWith(prefix))
}

const MFA_SETUP_PATHS = new Set([
  "/api/auth/mfa/enroll",
  "/api/auth/mfa/confirm",
  "/api/auth/me",
])

export function registerAuthGuard(app: FastifyInstance) {
  app.addHook("onRequest", async (req, reply) => {
    if (!req.url.startsWith("/api/")) return

    const path = req.url.split("?")[0] ?? ""
    if (isPublicPath(path)) return

    const header = req.headers.authorization
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined
    if (!token) return reply.code(401).send({ error: "non authentifié" })

    try {
      // Session authentifiée — vérifie via la façade authService (mockable en tests).
      const decoded = authService.verifyToken(token) as {
        sub: string
        role: string
        mfaEnabled: boolean
      }
      ;(req as FastifyRequest & { user?: unknown }).user = decoded

      // MFA non activée : seules les routes de setup sont accessibles
      if (!decoded.mfaEnabled && !MFA_SETUP_PATHS.has(path)) {
        return reply.code(403).send({
          error: "MFA non activée — active la MFA avant de continuer.",
          code: "mfa_not_enabled",
        })
      }
    } catch {
      // Comportement Phase 1 : un pendingToken (audience mfa-pending) ou un token
      // invalide est rejeté partout, y compris sur les routes de setup MFA. Les
      // routes MFA_SETUP acceptent exclusivement un token de session valide.
      return reply.code(401).send({ error: "token invalide" })
    }
  })
}
