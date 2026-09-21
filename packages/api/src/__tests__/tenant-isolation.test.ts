/**
 * Isolation multi-tenant (matrix) : un utilisateur ne voit et ne
 * modifie QUE les ressources de son tenant.
 *
 * Deux tenants fictifs : tenant-a / tenant-b. Le token émet le claim tenantId ;
 * on vérifie (1) la garde (claim → req.tenantId, override header validé par
 * membership, 403 sinon) et (2) le filtrage EFFECTIF par les services + routes
 * (404 sur une ressource d'un autre tenant, où par tenant dans les queries).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest"
import { buildTestApp } from "./helpers/build-test-app"
import { authService } from "../modules/auth/service"
import { registerAuthGuard } from "../modules/auth/routes"
import { registerAuthRoutes } from "../modules/auth/routes"
import { registerClustersRoutes } from "../modules/clusters/routes"
import { registerProjectRoutes } from "../modules/projects/routes"
import { registerRegistryRoutes } from "../modules/registry/routes"
import { registerServersRoutes } from "../modules/servers/routes"
import { registerReconcilerRoutes } from "../modules/reconciler/routes"

const TENANT_A = "tenant-a"
const TENANT_B = "tenant-b"

// ── Données simulées (dataset par tenant) ──
const db = {
  clusters: [
    { id: "c-a", name: "cluster-a", tenantId: TENANT_A, isDefault: true, status: "ready", dockerHost: "ssh://a", caddyAdminUrl: "", createdAt: new Date(), updatedAt: new Date() },
    { id: "c-b", name: "cluster-b", tenantId: TENANT_B, isDefault: false, status: "ready", dockerHost: "ssh://b", caddyAdminUrl: "", createdAt: new Date(), updatedAt: new Date() },
  ],
  projects: [
    { id: "p-a", name: "Projet A", slug: "projet-a", clusterId: "c-a", status: "draft", tenantId: TENANT_A, description: null, createdAt: new Date(), updatedAt: new Date(), nodes: [], edges: [] },
    { id: "p-b", name: "Projet B", slug: "projet-b", clusterId: "c-b", status: "draft", tenantId: TENANT_B, description: null, createdAt: new Date(), updatedAt: new Date(), nodes: [], edges: [] },
  ],
  nodes: [
    { id: "n-a1", projectId: "p-a", type: "container", name: "web", posX: 0, posY: 0, config: {}, createdAt: new Date(), updatedAt: new Date() },
    { id: "n-b1", projectId: "p-b", type: "container", name: "web", posX: 0, posY: 0, config: {}, createdAt: new Date(), updatedAt: new Date() },
  ],
  edges: [
    { id: "e-a1", projectId: "p-a", sourceNodeId: "n-a1", targetNodeId: "n-a1", kind: "network", config: null, createdAt: new Date(), updatedAt: new Date() },
    { id: "e-b1", projectId: "p-b", sourceNodeId: "n-b1", targetNodeId: "n-b1", kind: "network", config: null, createdAt: new Date(), updatedAt: new Date() },
  ],
  servers: [
    { id: "s-a1", name: "srv-a", host: "10.0.0.1", port: 22, user: "root", role: "manager", status: "ready", clusterId: "c-a", tenantId: TENANT_A, createdAt: new Date(), updatedAt: new Date() },
    { id: "s-b1", name: "srv-b", host: "10.0.0.2", port: 22, user: "root", role: "manager", status: "ready", clusterId: "c-b", tenantId: TENANT_B, createdAt: new Date(), updatedAt: new Date() },
  ],
  credentials: [
    { id: "r-a", registry: "ghcr.io", username: "keeper-a", tenantId: TENANT_A, createdAt: new Date(), updatedAt: new Date() },
    { id: "r-b", registry: "ghcr.io", username: "keeper-b", tenantId: TENANT_B, createdAt: new Date(), updatedAt: new Date() },
  ],
  audit: [
    { id: "log-a1", action: "deploy.success", userId: "u-a", projectId: "p-a", nodeId: null, serverId: null, ip: null, payload: {}, tenantId: TENANT_A, createdAt: new Date() },
    { id: "log-b1", action: "deploy.success", userId: "u-b", projectId: "p-b", nodeId: null, serverId: null, ip: null, payload: {}, tenantId: TENANT_B, createdAt: new Date() },
  ],
}

const byTenant =
  <T extends { tenantId: string }>(rows: T[]) =>
  (args: any) => {
    const where = args?.where ?? {}
    if (where.tenantId) return rows.filter((r) => r.tenantId === where.tenantId)
    return rows
  }

const matchesWhere = (row: any, where: any) => {
  if (!where) return true
  if (where.tenantId && row.tenantId !== where.tenantId) return false
  if (where.id && row.id !== where.id) return false
  // Filtre relation (node/edge → project.tenantId).
  if (where.project?.tenantId) {
    const proj = db.projects.find((p) => p.id === row.projectId)
    if (!proj || proj.tenantId !== where.project.tenantId) return false
  }
  return true
}

const mockPrisma = vi.hoisted(() => ({
  membership: {
    findUnique: vi.fn(),
    findFirst: vi.fn(),
  },
  cluster: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    findUniqueOrThrow: vi.fn(),
    create: vi.fn(),
  },
  project: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn(),
    create: vi.fn(),
  },
  node: {
    findUnique: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn(),
    create: vi.fn(),
  },
  edge: {
    findFirst: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn(),
    create: vi.fn(),
  },
  server: {
    findMany: vi.fn(),
    create: vi.fn(),
  },
  registryCredential: {
    findMany: vi.fn(),
  },
  auditLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
  },
}))
vi.mock("../lib/prisma", () => ({ prisma: mockPrisma }))

vi.mock("../modules/auth/service", () => ({
  authService: { verifyToken: vi.fn() },
}))

const fakeEngine = {
  listProjectServices: vi.fn(async () => []),
  listNodes: vi.fn(async () => []),
  listManagedNetworks: vi.fn(async () => []),
  listManagedVolumes: vi.fn(async () => []),
  removeService: vi.fn(),
  removeNetwork: vi.fn(),
  removeVolume: vi.fn(),
  listServiceTasks: vi.fn(async () => []),
  listManagedContainers: vi.fn(async () => []),
  listManagedServices: vi.fn(async () => []),
  managerHealth: vi.fn(async () => ({ total: 1, reachable: 1, quorumOk: true })),
}
vi.mock("../modules/docker-engine/service", () => ({
  DockerEngineService: { forCluster: vi.fn(async () => fakeEngine) },
}))

function token(tenantId: string, role = "operator") {
  vi.mocked(authService.verifyToken).mockImplementation(() => ({
    sub: "user-" + tenantId,
    role,
    mfaEnabled: true,
    tenantId,
  }))
}

describe("Isolation multi-tenant (matrix)", () => {
  let app: Awaited<ReturnType<typeof buildTestApp>>

  beforeAll(async () => {
    app = await buildTestApp({
      routes: async (app) => {
        registerAuthGuard(app)
        await registerAuthRoutes(app)
        await registerClustersRoutes(app)
        await registerProjectRoutes(app)
        await registerRegistryRoutes(app)
        await registerServersRoutes(app)
        await registerReconcilerRoutes(app)
      },
    })
  }, 60000)

  afterAll(async () => {
    if (app) await app.close()
  })

  beforeEach(() => {
    vi.clearAllMocks()
    // Comportement par défaut des mocks : filtrage par tenant (miroir BD).
    mockPrisma.cluster.findMany.mockImplementation(byTenant(db.clusters))
    mockPrisma.cluster.findUnique.mockImplementation(async ({ where }) =>
      db.clusters.find((c) => matchesWhere(c, where)) ?? null)
    mockPrisma.cluster.findUniqueOrThrow.mockImplementation(async ({ where }) =>
      db.clusters.find((c) => matchesWhere(c, where)) ?? null)
    mockPrisma.project.findMany.mockImplementation(byTenant(db.projects))
    mockPrisma.project.findUnique.mockImplementation(async ({ where }) => {
      const p = db.projects.find((x) => x.id === where.id)
      if (p && where.tenantId && p.tenantId !== where.tenantId) return null
      return p ?? null
    })
    mockPrisma.project.updateMany.mockImplementation(async ({ where }) => ({
      count: db.projects.filter((p) => matchesWhere(p, where)).length,
    }))
    mockPrisma.project.deleteMany.mockImplementation(async ({ where }) => ({
      count: db.projects.filter((p) => matchesWhere(p, where)).length,
    }))
    mockPrisma.node.findUnique.mockImplementation(async ({ where }) => {
      const n = db.nodes.find((x) => x.id === where.id)
      return n && matchesWhere(n, where) ? n : null
    })
    mockPrisma.node.updateMany.mockImplementation(async ({ where }) => ({
      count: db.nodes.filter((n) => matchesWhere(n, where)).length,
    }))
    mockPrisma.node.deleteMany.mockImplementation(async ({ where }) => ({
      count: db.nodes.filter((n) => matchesWhere(n, where)).length,
    }))
    mockPrisma.edge.updateMany.mockImplementation(async ({ where }) => ({
      count: db.edges.filter((e) => matchesWhere(e, where)).length,
    }))
    mockPrisma.edge.deleteMany.mockImplementation(async ({ where }) => ({
      count: db.edges.filter((e) => matchesWhere(e, where)).length,
    }))
    mockPrisma.server.findMany.mockImplementation(byTenant(db.servers))
    mockPrisma.registryCredential.findMany.mockImplementation(byTenant(db.credentials))
    mockPrisma.auditLog.findMany.mockImplementation(async ({ where }) =>
      db.audit.filter((a) => matchesWhere(a, where)).map((a) => ({ ...a, user: null })))
    mockPrisma.auditLog.count.mockImplementation(async ({ where }) =>
      db.audit.filter((a) => matchesWhere(a, where)).length)
    mockPrisma.membership.findUnique.mockImplementation(async ({ where }) =>
      db.clusters.some((c) => c.tenantId === where.userId_tenantId?.tenantId)
        ? { tenantId: where.userId_tenantId?.tenantId, role: "owner" }
        : null)
    mockPrisma.membership.findFirst.mockImplementation(async () => ({ tenantId: TENANT_A }))
  })

  const get = (url: string, headers: Record<string, string> = {}) =>
    app!.inject({ method: "GET", url, headers: { authorization: "Bearer tok", ...headers } })

  // ── A. Garde de tenancy ────────────────────────────────────────────────────
  describe("A. garde : claim + override header", () => {
    it("A1: req.tenantId dérive du claim du token (liste projets filtrée)", async () => {
      token(TENANT_A, "operator")
      const res = await get("/api/projects")
      expect(res.statusCode).toBe(200)
      const body = res.json()
      expect(body).toHaveLength(1)
      expect(body[0].id).toBe("p-a")
      expect(mockPrisma.project.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: TENANT_A } }),
      )
    })

    it("A2: header x-tenant-id override autorisé si membership → tenant cible", async () => {
      token(TENANT_A, "owner")
      const res = await get("/api/clusters", { "x-tenant-id": TENANT_B })
      expect(res.statusCode).toBe(200)
      const body = res.json()
      expect(body).toHaveLength(1)
      expect(body[0].id).toBe("c-b")
      expect(mockPrisma.membership.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId_tenantId: { userId: "user-" + TENANT_A, tenantId: TENANT_B } },
        }),
      )
    })

    it("A3: header x-tenant-id sans membership → 403 (fail-closed), aucun filtrage", async () => {
      token(TENANT_A, "owner")
      mockPrisma.membership.findUnique.mockResolvedValue(null)
      const res = await get("/api/clusters", { "x-tenant-id": "tenant-inconnu" })
      expect(res.statusCode).toBe(403)
      expect(res.json()).toMatchObject({ code: "tenant_forbidden" })
      expect(mockPrisma.cluster.findMany).not.toHaveBeenCalled()
    })

    it("A4: owner tenant-B + header tenant-default SANS membership default → 403 (escalade A2)", async () => {
      // La garde exige une membership RÉELLE dans le tenant par défaut (plus de
      // court-circuit DEFAULT_TENANT_ID) : un owner d'un autre tenant ne peut pas
      // enrober le tenant par défaut via le header. (users/pendings/providers
      // sont derrière la même garde → 403 systématique.)
      token(TENANT_B, "owner")
      const res = await get("/api/clusters", { "x-tenant-id": "tenant-default" })
      expect(res.statusCode).toBe(403)
      expect(res.json()).toMatchObject({ code: "tenant_forbidden" })
      expect(mockPrisma.cluster.findMany).not.toHaveBeenCalled()
    })
  })

  // ── B. Isolation projects (reading + mutations) ────────────────────────────
  describe("B. projets : 404 cross-tenant, 200 intra-tenant", () => {
    beforeEach(() => token(TENANT_A, "operator"))

    it("B1: GET /api/projects/:id d'un autre tenant → 404", async () => {
      const res = await get("/api/projects/p-b")
      expect(res.statusCode).toBe(404)
    })

    it("B2: GET /api/projects/:id du même tenant → 200", async () => {
      const res = await get("/api/projects/p-a")
      expect(res.statusCode).toBe(200)
      expect(res.json().id).toBe("p-a")
    })

    it("B3: PATCH /api/projects/:id d'un autre tenant → 404 (where scopé, 0 ligne)", async () => {
      const res = await app!.inject({
        method: "PATCH",
        url: "/api/projects/p-b",
        headers: { authorization: "Bearer tok" },
        payload: { name: "piraté" },
      })
      expect(res.statusCode).toBe(404)
      // L'écriture tente mais est scopée au tenant : 0 ligne matcher → jamais de fuite.
      expect(mockPrisma.project.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: "p-b", tenantId: TENANT_A } }),
      )
    })

    it("B4: DELETE /api/projects/:id d'un autre tenant → 404 (where scopé, 0 ligne)", async () => {
      const res = await app!.inject({
        method: "DELETE",
        url: "/api/projects/p-b",
        headers: { authorization: "Bearer tok" },
      })
      expect(res.statusCode).toBe(404)
      expect(mockPrisma.project.deleteMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: "p-b", tenantId: TENANT_A } }),
      )
    })

    it("B5: création de node sur projet d'un autre tenant → 404", async () => {
      const res = await app!.inject({
        method: "POST",
        url: "/api/projects/p-b/nodes",
        headers: { authorization: "Bearer tok" },
        payload: { type: "container", name: "evil", posX: 0, posY: 0, config: {} },
      })
      expect(res.statusCode).toBe(404)
      expect(mockPrisma.node.create).not.toHaveBeenCalled()
    })

    it("B6: maj de node appartenant à un autre tenant → 404", async () => {
      const res = await app!.inject({
        method: "POST",
        url: "/api/nodes/n-b1",
        headers: { authorization: "Bearer tok" },
        payload: { name: "evil" },
      })
      expect(res.statusCode).toBe(404)
      expect(mockPrisma.node.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: "n-b1", project: { tenantId: TENANT_A } },
        }),
      )
    })

    it("B7: maj de edge appartenant à un autre tenant → 404", async () => {
      const res = await app!.inject({
        method: "POST",
        url: "/api/edges/e-b1",
        headers: { authorization: "Bearer tok" },
        payload: { config: { evil: true } },
      })
      expect(res.statusCode).toBe(404)
      expect(mockPrisma.edge.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: "e-b1", project: { tenantId: TENANT_A } },
        }),
      )
    })
  })

  // ── C. Reconciler ───────────────────────────────────────────────────────────
  describe("C. reconciler : plan/destroy cross-tenant → 404", () => {
    beforeEach(() => token(TENANT_A, "operator"))

    it("C1: GET /api/projects/:id/plan d'un autre tenant → 404", async () => {
      const res = await get("/api/projects/p-b/plan")
      expect(res.statusCode).toBe(404)
    })

    it("C2: POST /api/projects/:id/destroy d'un autre tenant → 404", async () => {
      const res = await app!.inject({
        method: "POST",
        url: "/api/projects/p-b/destroy",
        headers: { authorization: "Bearer tok" },
      })
      expect(res.statusCode).toBe(404)
    })
  })

  // ── D. Registry / servers / audit filtrés par tenant ───────────────────────
  describe("D. registry, servers, audit : where tenantId", () => {
    it("D1: GET /api/registry ne renvoie que le tenant du token", async () => {
      token(TENANT_A, "owner")
      const res = await get("/api/registry")
      expect(res.statusCode).toBe(200)
      const body = res.json()
      expect(body).toHaveLength(1)
      // list() ne sérialise que {id, registry, username} — l'isolation est au where.
      expect(body[0].id).toBe("r-a")
      expect(mockPrisma.registryCredential.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: TENANT_A } }),
      )
    })

    it("D2: GET /api/servers filtre par tenant et health sur le cluster du tenant", async () => {
      token(TENANT_A, "owner")
      const res = await get("/api/servers")
      expect(res.statusCode).toBe(200)
      expect(res.json().servers).toHaveLength(1)
      expect(res.json().servers[0].id).toBe("s-a1")
      expect(mockPrisma.server.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: TENANT_A } }),
      )
    })

    it("D3: GET /api/audit filtre les entrées par tenant du token", async () => {
      token(TENANT_A, "operator")
      const res = await get("/api/audit")
      expect(res.statusCode).toBe(200)
      expect(res.json().entries).toHaveLength(1)
      expect(res.json().entries[0].id).toBe("log-a1")
      expect(mockPrisma.auditLog.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: TENANT_A } }),
      )
    })
  })
})