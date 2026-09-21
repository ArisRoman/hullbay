import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest"
import Fastify from "fastify"
import type { FastifyInstance, FastifyRequest } from "fastify"
import { validatorCompiler, serializerCompiler } from "fastify-type-provider-zod"
import { registerProvidersRoutes } from "../routes/providers.routes"
import { registerPendingRoutes } from "../routes/pending.routes"
import { prisma } from "../../../lib/prisma"
import { providerRegistry } from "../registry/provider-registry"

/**
 * CRUD providers + workflow d'approbation (owner).
 *
 * SÉCURITÉ couverte :
 * - jamais de secret en clair en réponse (champs sensibles masqués par marqueur)
 * - jamais de secret en clair EN BASE (chiffré individuellement)
 * - zod par kind : toute clé inconnue dans la config rejetée (anti-injection)
 * - anti-énumération : id inconnu → 404 uniforme
 * - approve : pas d'auto-provision (un pending doit être approuvé par un owner)
 */

vi.mock("../../../lib/prisma", () => {
  const authProvider = {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  }
  const tenant = { findUnique: vi.fn() }
  const authIdentity = { count: vi.fn(), create: vi.fn() }
  const pendingIdentity = { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn() }
  const user = { findUnique: vi.fn(), create: vi.fn() }
  const membership = { upsert: vi.fn() }
  const auditLog = { create: vi.fn(() => Promise.resolve({ id: "audit-1" })) }
  return {
    prisma: {
      authProvider,
      tenant,
      authIdentity,
      pendingIdentity,
      user,
      membership,
      auditLog,
      $transaction: vi.fn(),
    },
  }
})

const emitMock = vi.fn(async (...args: unknown[]) => undefined)
vi.mock("../../../lib/event-bus", () => ({
  eventBus: {
    on: () => () => {},
    emit: (...args: unknown[]) => emitMock(...args),
  },
}))

const PENDING_ALICE = {
  id: "pending-1",
  providerId: "oidc-test",
  issuer: "https://idp.example.org",
  subject: "sub-1",
  email: "alice@hullbay.local",
  name: "Alice",
  requestedForTenantId: null,
  status: "pending",
}

async function buildApp(role: "owner" | "operator" = "owner"): Promise<FastifyInstance> {
  const app = Fastify({ logger: false })
  app.setValidatorCompiler(validatorCompiler)
  app.setSerializerCompiler(serializerCompiler)
  app.addHook("preHandler", async (req) => {
    const r = req as FastifyRequest & { user?: unknown; tenantId?: string }
    r.user = { sub: "u-admin", role, mfaEnabled: true }
    // Tenant effectif posé par la garde en prod (claim/header). En harnais,
    // on simule l'acteur owner appartenant au tenant "t-1".
    r.tenantId = "t-1"
  })
  await registerProvidersRoutes(app)
  await registerPendingRoutes(app)
  await app.ready()
  return app
}

function txMock() {
  return {
    user: {
      findUnique: vi.fn(async () => null),
      create: vi.fn(async (d: { data: Record<string, unknown> }) => ({
        id: "u-new",
        email: d.data.email ?? null,
        name: d.data.name ?? null,
        role: d.data.role,
      })),
    },
    authIdentity: { create: vi.fn(async () => ({ id: "i-new" })) },
    membership: {
      upsert: vi.fn(async (d: { update: { role: string } }) => ({ id: "m-new", role: d.update.role })),
    },
    pendingIdentity: { update: vi.fn() },
  }
}

beforeAll(() => {
  process.env.JWT_SECRET = "providers-test-secret"
})

beforeEach(() => {
  vi.clearAllMocks()
  providerRegistry.clear()
})

describe("Providers admin (owner) — CRUD", () => {
  it("GET — champs sensibles masqués, jamais en clair dans la réponse", async () => {
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([
      { id: "oidc-corp", kind: "oidc", name: "Corp", enabled: false, config: { issuer: "https://idp.example.org", clientSecret: "k1234:iv:tag:data" } },
    ] as never)
    const app = await buildApp()
    const res = await app.inject({ method: "GET", url: "/api/auth/admin/providers" })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body[0].config.clientSecret).toBe("••••••••")
    expect(JSON.stringify(body)).not.toContain("k1234")
    await app.close()
  })

  it("GET — non-owner → 403", async () => {
    const app = await buildApp("operator")
    const res = await app.inject({ method: "GET", url: "/api/auth/admin/providers" })
    expect(res.statusCode).toBe(403)
    await app.close()
  })

  it("POST valide — config chiffrée en base, secret jamais en clair dans AuthProvider", async () => {
    vi.mocked(prisma.authProvider.create).mockResolvedValue({ id: "oidc-new", kind: "oidc", name: "New", enabled: true, config: {} } as never)
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([] as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/providers",
      payload: {
        kind: "oidc",
        name: "New",
        enabled: true,
        config: { issuer: "https://idp.example.org", clientId: "client-1", clientSecret: "super-secret", redirectUri: "https://sp.example.org/cb" },
      },
    })
    expect(res.statusCode).toBe(201)
    const call = vi.mocked(prisma.authProvider.create).mock.calls[0]?.[0] as { data: { config: Record<string, unknown> } }
    const stored = call.data.config as Record<string, unknown>
    expect(stored.clientSecret).not.toBe("super-secret")
    expect(String(stored.clientSecret)).toContain(":")
    expect(JSON.stringify(stored)).not.toContain("super-secret")
    await app.close()
  })

  it("POST — config avec clé inconnue rejetée (whitelist zod, anti-injection)", async () => {
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/providers",
      payload: {
        kind: "oidc",
        name: "Hack",
        config: { issuer: "https://idp.example.org", clientId: "c", redirectUri: "https://sp.example.org/cb", extraFieldScript: "rm -rf /" },
      },
    })
    expect(res.statusCode).toBe(400)
    expect(prisma.authProvider.create).not.toHaveBeenCalled()
    await app.close()
  })

  it("POST — kind non géré (ldap) → 400", async () => {
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/providers",
      payload: { kind: "ldap", name: "LDAP", config: {} },
    })
    expect(res.statusCode).toBe(400)
    await app.close()
  })

  it("PUT — marqueur secret conserve la valeur chiffrée existante", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({
      id: "oidc-corp", kind: "oidc", name: "Corp", enabled: false, tenantId: "t-1",
      config: { issuer: "https://idp.example.org", clientSecret: "k9988:iv:tag:data" },
    } as never)
    vi.mocked(prisma.authProvider.update).mockImplementation((async () => ({ id: "oidc-corp", kind: "oidc", name: "Corp", enabled: true, config: {} })) as never)
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([] as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "PUT",
      url: "/api/auth/admin/providers/oidc-corp",
      payload: { enabled: true, config: { issuer: "https://idp.example.org", clientId: "client-1", redirectUri: "https://sp.example.org/cb", clientSecret: "••••••••" } },
    })
    expect(res.statusCode).toBe(200)
    const call = vi.mocked(prisma.authProvider.update).mock.calls[0]?.[0] as { data: { config: Record<string, unknown> } }
    expect(call.data.config.clientSecret).toBe("k9988:iv:tag:data")
    await app.close()
  })

  it("PUT — id inconnu → 404 (anti-énumération)", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue(null as never)
    const app = await buildApp()
    const res = await app.inject({ method: "PUT", url: "/api/auth/admin/providers/nope", payload: { name: "X" } })
    expect(res.statusCode).toBe(404)
    await app.close()
  })

  it("PUT — enabled uniquement (toggle) réussit et change le statut sans toucher la config", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({
      id: "oidc-corp", kind: "oidc", name: "Corp", enabled: false, tenantId: "t-1",
      config: { issuer: "https://idp.example.org", clientSecret: "k9988:iv:tag:data" },
    } as never)
    vi.mocked(prisma.authProvider.update).mockResolvedValue({
      id: "oidc-corp", kind: "oidc", name: "Corp", enabled: true, config: {},
    } as never)
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([] as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "PUT",
      url: "/api/auth/admin/providers/oidc-corp",
      payload: { enabled: true },
    })
    expect(res.statusCode).toBe(200)
    const call = vi.mocked(prisma.authProvider.update).mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(call.data.enabled).toBe(true)
    expect(call.data.config).toBeUndefined()
    await app.close()
  })

  it("DELETE — provider local impossible", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({ id: "local", kind: "local", tenantId: "t-1" } as never)
    const app = await buildApp()
    const res = await app.inject({ method: "DELETE", url: "/api/auth/admin/providers/local" })
    expect(res.statusCode).toBe(400)
    await app.close()
  })

  it("DELETE — provider utilisé par des identités → 409", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({ id: "oidc-corp", kind: "oidc", tenantId: "t-1" } as never)
    vi.mocked(prisma.authIdentity.count).mockResolvedValue(3 as never)
    const app = await buildApp()
    const res = await app.inject({ method: "DELETE", url: "/api/auth/admin/providers/oidc-corp" })
    expect(res.statusCode).toBe(409)
    expect(prisma.authProvider.delete).not.toHaveBeenCalled()
    await app.close()
  })

  it("DELETE — id inconnu → 404", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue(null as never)
    const app = await buildApp()
    const res = await app.inject({ method: "DELETE", url: "/api/auth/admin/providers/nope" })
    expect(res.statusCode).toBe(404)
    await app.close()
  })

  it("POST /test — config incomplète → ok:false sans détail exposé", async () => {
vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({
      id: "oidc-corp", kind: "oidc", name: "Corp", enabled: false, tenantId: "t-1",
      config: { issuer: "https://idp.example.org", clientSecret: "k9988:iv:tag:data" },
    } as never)
    const app = await buildApp()
    const res = await app.inject({ method: "POST", url: "/api/auth/admin/providers/oidc-corp/test" })
    expect(res.statusCode).toBe(200)
    expect(res.json().ok).toBe(false)
    await app.close()
  })

  it("GET — liste restreinte au tenant effectif : tenant courant + globaux", async () => {
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([] as never)
    const app = await buildApp()
    await app.inject({ method: "GET", url: "/api/auth/admin/providers" })
    const call = vi.mocked(prisma.authProvider.findMany).mock.calls[0]?.[0] as { where: Record<string, unknown> }
    // Le filtrage est porté par le where transmis à la DB : jamais de fuite d'un
    // provider d'un autre tenant dans la réponse (l'isolation tient en base).
    expect(call.where).toEqual({ OR: [{ tenantId: "t-1" }, { tenantId: null }] })
    await app.close()
  })

  it("PUT — provider d'un AUTRE tenant → 404 (anti-fuite cross-tenant)", async () => {
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({
      id: "oidc-other", kind: "oidc", name: "Other", enabled: true, tenantId: "tenant-other",
      config: { issuer: "https://idp.example.org", clientId: "c" },
    } as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "PUT",
      url: "/api/auth/admin/providers/oidc-other",
      payload: { enabled: false },
    })
    expect(res.statusCode).toBe(404)
    expect(prisma.authProvider.update).not.toHaveBeenCalled()
    await app.close()
  })

  it("POST — sans tenantId explicite → provider global (tenantId null) dans le dto", async () => {
    vi.mocked(prisma.authProvider.create).mockResolvedValue({
      id: "oidc-global", kind: "oidc", name: "Global", enabled: true, tenantId: null, config: {},
    } as never)
    vi.mocked(prisma.authProvider.findMany).mockResolvedValue([] as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/providers",
      payload: { kind: "oidc", name: "Global", enabled: true, config: { issuer: "https://idp.example.org", clientId: "c", redirectUri: "https://sp.example.org/cb" } },
    })
    expect(res.statusCode).toBe(201)
    const call = vi.mocked(prisma.authProvider.create).mock.calls[0]?.[0] as { data: { tenantId: string | null } }
    expect(call.data.tenantId).toBeNull()
    expect(res.json().tenantId).toBeNull()
    await app.close()
  })
})

describe("Workflow d'approbation (owner)", () => {
  it("GET — liste les identités en attente", async () => {
    vi.mocked(prisma.pendingIdentity.findMany).mockResolvedValue([PENDING_ALICE] as never)
    const app = await buildApp()
    const res = await app.inject({ method: "GET", url: "/api/auth/admin/pendings" })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toHaveLength(1)
    await app.close()
  })

  it("approve — User + AuthIdentity + Membership en transaction, pending → approved, event émis", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue(PENDING_ALICE as never)
    vi.mocked(prisma.tenant.findUnique).mockResolvedValue({ id: "t-1", name: "Default" } as never)
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({ id: "oidc-test", kind: "oidc" } as never)
    const tx = txMock()
    vi.mocked(prisma.$transaction).mockImplementation((async (fn: (t: unknown) => Promise<unknown>) => fn(tx as never)) as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-1/approve",
      payload: { tenantId: "t-1", role: "operator" },
    })
    expect(res.statusCode).toBe(200)
    expect(tx.user.create).toHaveBeenCalled()
    expect(tx.authIdentity.create).toHaveBeenCalled()
    expect(tx.membership.upsert).toHaveBeenCalledTimes(1)
    expect(tx.pendingIdentity.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: "approved", requestedForTenantId: "t-1" }),
      }),
    )
    await vi.waitFor(() => expect(emitMock).toHaveBeenCalledWith("auth.pending.approved", expect.any(Object)))
    await app.close()
  })

  it("approve — demande absente → 404 (anti-énumération)", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue(null as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/nope/approve",
      payload: { tenantId: "t-1", role: "viewer" },
    })
    expect(res.statusCode).toBe(404)
    await app.close()
  })

  it("approve — compte existant + email NON vérifié → 409, identité jamais liée", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue({ ...PENDING_ALICE, id: "pending-1", emailVerified: false } as never)
    vi.mocked(prisma.tenant.findUnique).mockResolvedValue({ id: "t-1", name: "Default" } as never)
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({ id: "oidc-test", kind: "oidc" } as never)
    const tx = txMock()
    tx.user.findUnique.mockResolvedValue({ id: "u-existant", email: "alice@hullbay.local", role: "viewer" } as never)
    vi.mocked(prisma.$transaction).mockImplementation((async (fn: (t: unknown) => Promise<unknown>) => fn(tx as never)) as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-1/approve",
      payload: { tenantId: "t-1", role: "viewer" },
    })
    expect(res.statusCode).toBe(409)
    expect(res.json().code).toBe("email_not_verified")
    expect(tx.user.create).not.toHaveBeenCalled()
    expect(tx.authIdentity.create).not.toHaveBeenCalled()
    await app.close()
  })

  it("approve — compte existant + email VÉRIFIÉ → réutilise le User, ne le recrée pas", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue({ ...PENDING_ALICE, id: "pending-2", emailVerified: true } as never)
    vi.mocked(prisma.tenant.findUnique).mockResolvedValue({ id: "t-1", name: "Default" } as never)
    vi.mocked(prisma.authProvider.findUnique).mockResolvedValue({ id: "oidc-test", kind: "oidc" } as never)
    const tx = txMock()
    tx.user.findUnique.mockResolvedValue({ id: "u-existant", email: "alice@hullbay.local", role: "viewer" } as never)
    vi.mocked(prisma.$transaction).mockImplementation((async (fn: (t: unknown) => Promise<unknown>) => fn(tx as never)) as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-2/approve",
      payload: { tenantId: "t-1", role: "viewer" },
    })
    expect(res.statusCode).toBe(200)
    expect(tx.user.create).not.toHaveBeenCalled()
    expect(tx.authIdentity.create).toHaveBeenCalled()
    await app.close()
  })

  it("approve — tenant inconnu (tenant de l'acteur) → 400, aucun User créé", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue({ ...PENDING_ALICE, id: "pending-2" } as never)
    vi.mocked(prisma.tenant.findUnique).mockResolvedValue(null as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-2/approve",
      payload: { tenantId: "t-1", role: "viewer" },
    })
    expect(res.statusCode).toBe(400)
    await app.close()
  })

  it("approve — tenant AUTRE que celui de l'acteur → 403 (escalade cross-tenant, A5)", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue({ ...PENDING_ALICE, id: "pending-3" } as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-3/approve",
      payload: { tenantId: "tenant-autre", role: "owner" },
    })
    // Bloqué AVANT toute lecture pending (pas d'oracle d'existence).
    expect(res.statusCode).toBe(403)
    expect(prisma.pendingIdentity.findFirst).not.toHaveBeenCalled()
    await app.close()
  })

  it("approve — non-owner → 403 (pas d'auto-approbation)", async () => {
    const app = await buildApp("operator")
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-1/approve",
      payload: { tenantId: "t-1", role: "viewer" },
    })
    expect(res.statusCode).toBe(403)
    await app.close()
  })

  it("reject — marque rejected + event émis, aucune provision", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue(PENDING_ALICE as never)
    vi.mocked(prisma.pendingIdentity.update).mockResolvedValue({ ...PENDING_ALICE, status: "rejected" } as never)
    const app = await buildApp()
    const res = await app.inject({
      method: "POST",
      url: "/api/auth/admin/pendings/pending-1/reject",
      payload: { reason: "compte non désiré" },
    })
    expect(res.statusCode).toBe(200)
    expect(prisma.pendingIdentity.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: "rejected" }) }),
    )
    await vi.waitFor(() => expect(emitMock).toHaveBeenCalledWith("auth.pending.rejected", expect.any(Object)))
    await app.close()
  })

  it("reject — demande absente → 404", async () => {
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValue(null as never)
    const app = await buildApp()
    const res = await app.inject({ method: "POST", url: "/api/auth/admin/pendings/nope/reject", payload: {} })
    expect(res.statusCode).toBe(404)
    await app.close()
  })
})