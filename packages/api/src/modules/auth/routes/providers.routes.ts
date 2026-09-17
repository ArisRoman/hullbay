/**
 * Routes d'administration des providers d'authentification (owner uniquement).
 * Phase 5A1 : AuthProvider = source de vérité (§4.2 §8 du plan).
 *
 * SÉCURITÉ :
 * - jamais de secret renvoyé : la liste masque les champs sensibles (marqueur
 *   de présence, pas la valeur) ;
 * - à l'écriture, les champs sensibles sont chiffrés individuellement
 *   (encryptObject, scope "provider") avant stockage en base ;
 * - le marqueur "••••••••" envoyé en PUT sur un champ sensible signifie
 *   "conserver la valeur actuelle" (jamais d'écrasement par un placeholder) ;
 * - schema zod par kind (whitelist stricte : toute clé inconnue rejetée) ;
 * - anti-énumération : id inconnu → 404 uniforme.
 *
 * Chaque mutation re-hydrate le ProviderRegistry depuis la DB (loadFromDb).
 */

import type { FastifyInstance } from "fastify"
import { z } from "zod"
import { requireRole } from "../authorization/rbac"
import { prisma } from "../../../lib/prisma"
import { eventBus } from "../../../lib/event-bus"
import { encryptObject, encryptSecret } from "../secrets/secret-encryption-service"
import { SENSITIVE_FIELDS_BY_KIND } from "../registry/seeds"
import { providerRegistry } from "../registry/provider-registry"
import type { ProviderKind } from "../providers/types"

const owner = { preHandler: requireRole("owner") }

/** Marqueur renvoyé à la place d'un secret (présence, jamais la valeur). */
const SECRET_MASK = "••••••••"

const oidcConfigSchema = z.object({
  issuer: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().optional(),
  redirectUri: z.string().url(),
  scopes: z.string().optional(),
  discoveryUrl: z.string().url().optional(),
  jwksUri: z.string().url().optional(),
}).strict()

const oauth2ConfigSchema = z.object({
  authorizationUri: z.string().url(),
  tokenUri: z.string().url(),
  userinfoUri: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().optional(),
  redirectUri: z.string().url(),
  scopes: z.string().optional(),
  groupAttr: z.string().optional(),
}).strict()

const samlConfigSchema = z.object({
  idpCert: z.string().min(1),
  idpIssuer: z.string().min(1),
  spIssuer: z.string().min(1),
  entryPoint: z.string().url(),
  callbackUrl: z.string().url(),
  audience: z.string().optional(),
  acceptedClockSkewMs: z.number().int().positive().optional(),
}).strict()

const CONFIG_SCHEMAS: Record<Exclude<ProviderKind, "local" | "ldap">, z.ZodType<Record<string, unknown>>> = {
  oidc: oidcConfigSchema,
  oauth2: oauth2ConfigSchema,
  saml: samlConfigSchema,
}

function kindToSchema(kind: string) {
  if (kind === "local" || kind === "ldap") return null
  return CONFIG_SCHEMAS[kind as keyof typeof CONFIG_SCHEMAS] ?? null
}

function maskConfig(config: Record<string, unknown>, kind: string): Record<string, unknown> {
  const masked = { ...config }
  for (const field of SENSITIVE_FIELDS_BY_KIND[kind as ProviderKind] ?? []) {
    if (typeof masked[field] === "string") masked[field] = SECRET_MASK
  }
  return masked
}

function dto(row: {
  id: string
  kind: string
  name: string
  enabled: boolean
  config?: unknown
}) {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    enabled: row.enabled,
    config: maskConfig((row.config as Record<string, unknown>) ?? {}, row.kind),
  }
}

export async function registerProvidersRoutes(app: FastifyInstance) {
  // Liste (secrets masqués).
  app.get(
    "/api/auth/admin/providers",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Liste des providers d'authentification (owner) — secrets masqués",
        security: [{ bearerAuth: [] }],
      },
    },
    async () => {
      const rows = await prisma.authProvider.findMany({
        orderBy: { kind: "asc" },
        select: { id: true, kind: true, name: true, enabled: true, config: true },
      })
      return rows.map(dto)
    },
  )

  const createBody = z.object({
    id: z.string().regex(/^[a-z0-9-]{3,64}$/, "id : a-z0-9 et tirets (3-64)").optional(),
    kind: z.enum(["oidc", "oauth2", "saml"]),
    name: z.string().min(1, "nom requis").max(120),
    enabled: z.boolean().default(false),
    config: z.record(z.string(), z.any()).default({}),
  })

  // Création.
  app.post(
    "/api/auth/admin/providers",
    {
      ...owner,
      schema: {
        body: createBody,
        tags: ["auth"],
        summary: "Création d'un provider (owner) : config whitelist par kind, secrets chiffrés",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const body = createBody.parse(req.body)
      const schema = kindToSchema(body.kind)
      if (!schema) {
        return reply.code(400).send({ error: `kind ${body.kind} non géré via l'API` })
      }
      const parsed = schema.safeParse(body.config)
      if (!parsed.success) {
        const details = parsed.error.flatten().fieldErrors
        return reply.code(400).send({ error: "config invalide", details })
      }
      const config = encryptObject(parsed.data, SENSITIVE_FIELDS_BY_KIND[body.kind])
      try {
        const row = await prisma.authProvider.create({
          data: {
            kind: body.kind,
            name: body.name,
            enabled: body.enabled,
            config: config as never,
            ...(body.id ? { id: body.id } : {}),
          },
        })
        await providerRegistry.loadFromDb()
        await eventBus.emit("auth.provider.created", { providerId: row.id, kind: row.kind })
        return reply.code(201).send(dto(row))
      } catch (err) {
        if (err instanceof Error && /unique/i.test(err.message) && body.id) {
          return reply.code(409).send({ error: "un provider porte déjà cet id" })
        }
        throw err
      }
    },
  )

  const updateBody = z.object({
    name: z.string().min(1).max(120).optional(),
    enabled: z.boolean().optional(),
    config: z.record(z.string(), z.any()).optional(),
  })

  // Mise à jour (partielle). Secrets : le marqueur conserve la valeur existante.
  app.put(
    "/api/auth/admin/providers/:id",
    {
      ...owner,
      schema: {
        body: updateBody,
        tags: ["auth"],
        summary: "Mise à jour d'un provider (owner) — secrets conservés si marqueur envoyé",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const body = updateBody.parse(req.body)
      const row = await prisma.authProvider.findUnique({ where: { id } })
      if (!row) return reply.code(404).send({ error: "provider introuvable" })

      // Garde anti-lockout : on ne peut jamais désactiver le dernier provider
      // actif (plus aucun moyen de connecter un compte ⇒ verrouillage total).
      if (body.enabled === false && row.enabled) {
        const otherEnabled = await prisma.authProvider.count({
          where: { id: { not: id }, enabled: true },
        })
        if (otherEnabled === 0) {
          return reply.code(400).send({
            error: "au moins un provider doit rester actif",
            code: "last_active_provider",
          })
        }
      }

      const schema = kindToSchema(row.kind)
      const currentConfig = (row.config as Record<string, unknown>) ?? {}
      let encryptedConfig = currentConfig
      if (body.config !== undefined) {
        if (!schema) {
          return reply.code(400).send({ error: `kind ${row.kind} non géré via l'API` })
        }
        const parsed = schema.safeParse(body.config)
        if (!parsed.success) {
          const details = parsed.error.flatten().fieldErrors
          return reply.code(400).send({ error: "config invalide", details })
        }
        // Fusionne avec la config existante. Le marqueur sentinelle signifie
        // "conserver la valeur actuelle" : les champs sensibles déjà chiffrés
        // en base restent intacts (pas de double-chiffrement — decryptObject
        // doit retrouver le secret en clair). Seul le delta fourni est
        // chiffré ; les champs sensibles non fournis gardent leur blob stocké.
        const sensitive = SENSITIVE_FIELDS_BY_KIND[row.kind as ProviderKind] ?? []
        const merged: Record<string, unknown> = { ...currentConfig }
        for (const [key, value] of Object.entries(parsed.data)) {
          if (value === SECRET_MASK) continue
          merged[key] = sensitive.includes(key) ? encryptSecret(value as string) : value
        }
        encryptedConfig = merged
      }

      const updated = await prisma.authProvider.update({
        where: { id },
        data: {
          ...(body.name !== undefined ? { name: body.name } : {}),
          ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
          ...(body.config !== undefined ? { config: encryptedConfig as never } : {}),
        },
      })
      await providerRegistry.loadFromDb()
      await eventBus.emit("auth.provider.updated", { providerId: updated.id, kind: updated.kind })
      return dto(updated)
    },
  )

  // Suppression — refus si des identités existent déjà (on n'orpheline jamais).
  app.delete(
    "/api/auth/admin/providers/:id",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Suppression d'un provider (owner) — refus si des identités existent",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const row = await prisma.authProvider.findUnique({ where: { id }, select: { id: true, kind: true, enabled: true } })
      if (!row) return reply.code(404).send({ error: "provider introuvable" })
      if (row.id === "local") {
        return reply.code(400).send({ error: "le provider local ne peut pas être supprimé" })
      }
      if (row.enabled) {
        const otherEnabled = await prisma.authProvider.count({
          where: { id: { not: id }, enabled: true },
        })
        if (otherEnabled === 0) {
          return reply.code(400).send({
            error: "au moins un provider doit rester actif",
            code: "last_active_provider",
          })
        }
      }
      const identities = await prisma.authIdentity.count({ where: { providerId: id } })
      if (identities > 0) {
        return reply.code(409).send({
          error: `provider utilisé par ${identities} identité(s) — supprime d'abord les utilisateurs`,
        })
      }
      const pendings = await prisma.pendingIdentity.count({ where: { providerId: id } })
      if (pendings > 0) {
        return reply.code(409).send({ error: "des approbations en attente référencent ce provider" })
      }
      await prisma.authProvider.delete({ where: { id } })
      await providerRegistry.loadFromDb()
      await eventBus.emit("auth.provider.deleted", { providerId: id })
      return reply.code(204).send()
    },
  )

  // Test de connexion (validation config + joignabilité si possible).
  app.post(
    "/api/auth/admin/providers/:id/test",
    {
      ...owner,
      schema: {
        tags: ["auth"],
        summary: "Test de configuration d'un provider (owner) — sans secret renvoyé",
        security: [{ bearerAuth: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string }
      const row = await prisma.authProvider.findUnique({ where: { id }, select: { id: true, kind: true, config: true, enabled: true, name: true } })
      if (!row) return reply.code(404).send({ error: "provider introuvable" })

      const schema = kindToSchema(row.kind)
      if (!schema) {
        return reply.code(400).send({ error: `kind ${row.kind} non testable via l'API` })
      }
      const current = (row.config as Record<string, unknown>) ?? {}
      const config = schema.safeParse(maskConfig(current, row.kind))
      if (!config.success) {
        return reply.code(200).send({
          ok: false,
          message: "config incomplète ou invalide — complète les champs requis",
          details: config.error.flatten().fieldErrors,
        })
      }
      try {
        // Tente la joignabilité OIDC (discovery) si renseignée — annulé après 5 s.
        let connectivity: string | null = null
        if (row.kind === "oidc" && typeof current.discoveryUrl === "string") {
          const controller = new AbortController()
          const timer = setTimeout(() => controller.abort(), 5000)
          try {
            const res = await fetch(current.discoveryUrl, { signal: controller.signal })
            if (res.ok) connectivity = `discovery joignable (HTTP ${res.status})`
            else connectivity = `discovery répond HTTP ${res.status}`
          } catch {
            connectivity = "discovery injoignable"
          } finally {
            clearTimeout(timer)
          }
        }
        return {
          ok: true,
          message: connectivity ?? "config valide",
          connectivity,
        }
      } catch (err) {
        return reply.code(200).send({
          ok: false,
          message: err instanceof Error ? err.message : "échec inconnu",
        })
      }
    },
  )
}