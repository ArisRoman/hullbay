/**
 * Routes SAML publiques : login + ACS + metadata.
 * GET /api/auth/saml/:id/login      → 302 vers l'IdP (AuthnRequest redirect)
 * POST /api/auth/saml/:id/acs       → traite la SAMLResponse (info)
 * GET /api/auth/saml/:id/metadata   → XML SP metadata (entity ID, ACS, certs)
 *
 * Le ACS répond en HTML (même pattern que SSO OIDC/OAuth2) : token → localStorage
 * puis redirection vers la SPA ; pending/erreur → /login?… paramétrage LoginPage.
 * GET /api/auth/providers (déjà dans sso.routes) liste tous les providers activés.
 */

import type { FastifyInstance, FastifyRequest } from "fastify"
import { providerRegistry } from "../registry/provider-registry"
import { processSsoCallback } from "../core/sso-callback"
import { AuthError } from "../providers/types"
import { SamlProvider } from "../providers/saml/saml-provider"
import { AUTH_AUDIT_EVENTS } from "../audit-events"
import { eventBus } from "../../../lib/event-bus"

const REDIRECT_TTL = 6_000

function ssoRedirectPage(payload: Record<string, unknown>): string {
  // `</script>` allégé pour empêcher toute injection depuis le payload.
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

/**
 * Lit le body de la POST ACS. node-saml attend `SAMLResponse` (base64) +
 * `RelayState` en application/x-www-form-urlencoded (binding HTTP-POST).
 * Fastify peut donner `req.body` parsé (objet/string) ou un Buffer brut si
 * aucun content-type parser n'est déclaré pour le POST form.
 */
function readAcsBody(req: unknown): { SAMLResponse?: string; RelayState?: string } {
  const body = (req as { body?: unknown }).body
  if (typeof body === "string") {
    // application/x-www-form-urlencoded brut — on parse manuellement.
    const params = new URLSearchParams(body)
    return {
      SAMLResponse: params.get("SAMLResponse") ?? undefined,
      RelayState: params.get("RelayState") ?? undefined,
    }
  }
  if (body instanceof Buffer) {
    const params = new URLSearchParams(body.toString("utf8"))
    return {
      SAMLResponse: params.get("SAMLResponse") ?? undefined,
      RelayState: params.get("RelayState") ?? undefined,
    }
  }
  const record = (body ?? {}) as Record<string, unknown>
  return {
    SAMLResponse: typeof record.SAMLResponse === "string" ? record.SAMLResponse : undefined,
    RelayState: typeof record.RelayState === "string" ? record.RelayState : undefined,
  }
}

export async function registerSamlRoutes(app: FastifyInstance) {
  // Parser local pour les POST form du binding SAML HTTP-POST (zero-dep,
  // pas besoin du plugin @fastify/formbody). Scopé sur ce module.
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "buffer" },
    (_req, body: Buffer, done: (err: Error | null, value?: unknown) => void) => {
      const params = new URLSearchParams(body.toString("utf8"))
      done(null, Object.fromEntries(params.entries()))
    },
  )

  // Seul un provider SAML est accepté ; inconnu → 404.
  function samlOrNull(id: string): SamlProvider | null {
    const provider = providerRegistry.get(id)
    if (!provider || !provider.enabled) return null
    if (!(provider instanceof SamlProvider)) return null
    return provider
  }

  // initiateLogin : génère l'AuthnRequest et 302 vers l'IdP. Publique.
  app.get(
    "/api/auth/saml/:id/login",
    { schema: { tags: ["auth"], summary: "Lancement SSO SAML (public)" } },
    async (req, reply) => {
      const id = (req as FastifyRequest<{ Params: { id: string } }>).params.id
      const provider = samlOrNull(id)
      if (!provider) {
        return reply.code(404).send({ error: "provider SAML inconnu ou désactivé" })
      }

      try {
        await provider.initiateLogin(req as never, reply as never)
      } catch {
        return reply.code(502).send({ error: "AuthnRequest SAML injoignable" })
      }

      const url = (req as { ssoAuthorizeUrl?: string }).ssoAuthorizeUrl
      if (!url) {
        return reply.code(500).send({ error: "la redirection SAML n'a pas pu être construite" })
      }
      return reply.redirect(url)
    },
  )

  // ACS : l'IdP POST la SAMLResponse ici. Publique.
  app.post(
    "/api/auth/saml/:id/acs",
    { schema: { tags: ["auth"], summary: "ACS SAML — reçoit la SAMLResponse (public)" } },
    async (req, reply) => {
      const id = (req as FastifyRequest<{ Params: { id: string } }>).params.id
      const provider = samlOrNull(id)
      if (!provider) {
        return reply.code(404).send({ error: "provider SAML inconnu ou désactivé" })
      }

      reply.header("cache-control", `no-store, max-age=0`)
      reply.header("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'")
      reply.type("text/html")

      let identity
      try {
        identity = await provider.callback(req as never, readAcsBody(req))
      } catch (err) {
        const code = err instanceof AuthError ? err.code : "sso_failed"
        void eventBus.emit(AUTH_AUDIT_EVENTS.samlFailed, { providerId: id }).catch(() => {})
        return reply.code(400).send(ssoRedirectPage({ error: code }))
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
      } catch {
        return reply.code(400).send(ssoRedirectPage({ error: "sso_internal" }))
      }
    },
  )

  // SP metadata : XML exposition (entity ID SP, ACS URL, certs). Publique.
  app.get(
    "/api/auth/saml/:id/metadata",
    { schema: { tags: ["auth"], summary: "SP metadata SAML (public — XML)" } },
    async (req, reply) => {
      const id = (req as FastifyRequest<{ Params: { id: string } }>).params.id
      const provider = samlOrNull(id)
      if (!provider) {
        return reply.code(404).send({ error: "provider SAML inconnu ou désactivé" })
      }
      reply.type("application/xml")
      return reply.send(provider.getMetadata())
    },
  )
}