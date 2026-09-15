/**
 * Routes SSO publiques (Phase 3) : initiateLogin + callback OIDC/OAuth2.
 * Le callback répond en HTML (même origine via proxy Vite/Caddy) : range le
 * token dans localStorage puis redirige vers la SPA. Côté pending/erreur,
 * redirige vers /login avec des paramètres lisibles par LoginPage.
 * GET /api/auth/providers liste les providers activés (id/kind/name, AUCUN secret).
 */

import type { FastifyInstance, FastifyRequest } from "fastify"
import { providerRegistry } from "../registry/provider-registry"
import { processSsoCallback } from "../core/sso-callback"
import { AuthError } from "../providers/types"
import type { AuthProviderContract } from "../providers/types"

const REDIRECT_TTL = 6_000

function ssoRedirectPage(payload: Record<string, unknown>): string {
  // `</script>` est allégé pour empêcher toute injection depuis le payload.
  const json = JSON.stringify(payload).replace(/</g, "\\u003c")
  return [
    "<!doctype html>",
    '<html lang="fr"><head><meta charset="utf-8"><title>Redirection…</title></head>',
    '<body><script>',
    `const p=${json};`,
    "if(p.token&&typeof localStorage!=='undefined'){localStorage.setItem('hullbay_token',p.token);location.replace('/');}",
    "else if(p.pending){const q=new URLSearchParams({pending:'1'});if(p.email)q.set('email',p.email);if(p.provider)q.set('provider',p.provider);location.replace('/login?'+q.toString());}",
    "else{location.replace('/login?error='+encodeURIComponent(p.error||'sso_failed'));}",
    "</script></body></html>",
  ].join("")
}

function redirectToLogin(reply: { code: (n: number) => { send: (b: unknown) => void } }, error: string) {
  reply.code(400).send(ssoRedirectPage({ error }))
}

function isRedirectProvider(provider: AuthProviderContract): boolean {
  return typeof provider.callback === "function" && typeof provider.initiateLogin === "function"
}

export async function registerSsoRoutes(app: FastifyInstance) {
  // Liste publique des providers activés (LoginPage). Jamais de secret.
  app.get(
    "/api/auth/providers",
    { schema: { tags: ["auth"], summary: "Providers de connexion activés (public)" } },
    async () => {
      return providerRegistry
        .list()
        .filter((p) => p.enabled)
        .map((p) => p.getConfig())
    },
  )

  // initiateLogin : fork vers l'IdP (302). Publique.
  app.get(
    "/api/auth/sso/:id/login",
    { schema: { tags: ["auth"], summary: "Lancement du SSO vers un provider (public)" } },
    async (req, reply) => {
      const id = (req as FastifyRequest<{ Params: { id: string } }>).params.id
      const provider = providerRegistry.get(id)
      if (!provider || !provider.enabled) {
        return reply.code(404).send({ error: "provider inconnu ou désactivé" })
      }
      if (!isRedirectProvider(provider)) {
        return reply.code(400).send({ error: "ce provider ne supporte pas le flux redirect" })
      }

      await provider.initiateLogin!(req as never, reply as never)
      const url = (req as { ssoAuthorizeUrl?: string }).ssoAuthorizeUrl
      if (!url) {
        return reply.code(500).send({ error: "la redirection SSO n'a pas pu être construite" })
      }
      return reply.redirect(url)
    },
  )

  // callback : l'IdP nous renvoie ici (code + state). Publique.
  app.get(
    "/api/auth/sso/:id/callback",
    { schema: { tags: ["auth"], summary: "Callback SSO du provider (public)" } },
    async (req, reply) => {
      const id = (req as FastifyRequest<{ Params: { id: string } }>).params.id
      const provider = providerRegistry.get(id)
      if (!provider || !provider.enabled || !provider.callback) {
        return redirectToLogin(reply, "sso_provider_unknown")
      }

      // Cache des autorisations : page HTML éphémère, jamais stockée en cache.
      reply.header("cache-control", `no-store, max-age=0`)
      reply.header("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'")
      reply.type("text/html")

      let identity
      try {
        identity = await provider.callback(req as never, (req as { query?: Record<string, unknown> }).query ?? {})
      } catch (err) {
        const code = err instanceof AuthError ? err.code : "sso_failed"
        return redirectToLogin(reply, code)
      }

      try {
        const result = await processSsoCallback(identity)
        if (result.pending) {
          return reply
            .code(202)
            .header("retry-after", String(REDIRECT_TTL))
            .send(
              ssoRedirectPage({
                pending: true,
                provider: identity.providerId,
                email: identity.email ?? "",
              }),
            )
        }
        return reply.send(ssoRedirectPage({ token: result.token }))
      } catch (err) {
        return redirectToLogin(reply, "sso_internal")
      }
    },
  )
}