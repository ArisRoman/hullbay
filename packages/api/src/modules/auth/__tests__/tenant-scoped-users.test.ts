/**
 * Correction A4/A6 — scoping tenant des opérations users (auth-core).
 *
 * Un owner ne pilote QUE son tenant :
 * - `listUsers(tenantId)` liste les membres du tenant, rôle depuis membership ;
 * - `setRole/deleteUser(..., tenantId)` n'agissent que DANS le tenant demandé ;
 * - la garde « dernier owner » est scopée AU TENANT (un owner tenant-B ne
 *   protège pas le dernier owner de tenant-A et réciproquement) ;
 * - `deleteUser` ne supprime le User global que si PLUS AUCUNE membership ne
 *   référence ce compte (pas de suppression cross-tenant).
 */

import { describe, it, expect, beforeEach, vi } from "vitest"
import { prisma } from "../../../lib/prisma"
import { listUsers, setRole, deleteUser } from "../core/auth-core"

const TENANT_A = "tenant-a"
const TENANT_B = "tenant-b"
const DEFAULT = "tenant-default"

const tx = {
  membership: {
    updateMany: vi.fn(async () => ({ count: 1 })),
    deleteMany: vi.fn(async () => ({ count: 1 })),
  },
  user: {
    update: vi.fn(async (a: { where: { id: string }; data: { role: string } }) => ({ id: a.where.id, email: "u@h", role: a.data.role })),
    findUniqueOrThrow: vi.fn(async (a: { where: { id: string } }) => ({ id: a.where.id, email: "u@h", role: "viewer" })),
    delete: vi.fn(),
  },
}

const mockPrisma = vi.hoisted(() => ({
  membership: {
    findUnique: vi.fn(),
    count: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn(),
    findMany: vi.fn(),
  },
  user: {
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    findUniqueOrThrow: vi.fn(),
    findFirst: vi.fn(),
  },
  authIdentity: {
    findMany: vi.fn(async () => []),
    findFirst: vi.fn(),
  },
  $transaction: vi.fn(),
}))

vi.mock("../../../lib/prisma", () => ({ prisma: mockPrisma }))
vi.mock("../../../lib/event-bus", () => ({
  eventBus: { on: () => () => {}, emit: vi.fn(async () => undefined) },
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockPrisma.$transaction.mockImplementation(async (fn: (t: unknown) => Promise<unknown>) => fn(tx as never) as never)
  // deleteUser agit sur le client GLOBAL (pas la tx) : défauts cohérents.
  mockPrisma.membership.deleteMany.mockResolvedValue({ count: 1 })
  mockPrisma.membership.count.mockResolvedValue(0)
  mockPrisma.user.delete.mockResolvedValue({ id: "u-x", email: "u@h", role: "operator" })
})

describe("listUsers(tenantId) — scoping tenant", () => {
  it("liste les membres du tenant CIBLE, rôle effectif depuis leur membership", async () => {
    mockPrisma.membership.findMany.mockResolvedValue([
      { userId: "u-1", role: "owner" },
      { userId: "u-2", role: "viewer" },
    ])
    mockPrisma.user.findMany.mockResolvedValue([
      { id: "u-1", email: "a@h", createdAt: new Date(), updatedAt: new Date() },
      { id: "u-2", email: "b@h", createdAt: new Date(), updatedAt: new Date() },
    ])
    mockPrisma.authIdentity.findMany.mockResolvedValue([{ userId: "u-2", mfaEnabled: true } as never])

    const users = await listUsers(TENANT_B)

    expect(mockPrisma.membership.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ tenantId: TENANT_B }) }),
    )
    expect(users.map((u) => `${u.id}:${u.role}`)).toEqual(["u-1:owner", "u-2:viewer"])
  })

  it("liste VIDE si aucun membre dans le tenant (l'owner d'un autre tenant n'énumère pas)", async () => {
    mockPrisma.membership.findMany.mockResolvedValue([])
    mockPrisma.user.findMany.mockResolvedValue([])
    const users = await listUsers(TENANT_B)
    expect(users).toEqual([])
    expect(mockPrisma.user.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ id: { in: [] } }) }),
    )
  })
})

describe("setRole(..., tenantId) — garde dernier-owner scopée tenant", () => {
  it("REFUSE de rétrograder le DERNIER owner du tenant B, même si tenant-A a d'autres owners", async () => {
    // Membership tenant-B = owner ; tenant-A compte 2 owners — ne doit PAS compter.
    mockPrisma.membership.findUnique.mockResolvedValue({ role: "owner" })
    mockPrisma.membership.count.mockResolvedValue(1)

    await expect(setRole("u-owner-b", "viewer", TENANT_B)).rejects.toThrow("impossible de rétrograder le dernier owner")
    expect(mockPrisma.membership.count).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ role: "owner", tenantId: TENANT_B }) }),
    )
  })

  it("autorise la rétrogradation quand le tenant B a un 2e owner (scopé)", async () => {
    mockPrisma.membership.findUnique.mockResolvedValue({ role: "owner" })
    mockPrisma.membership.count.mockResolvedValue(2)

    await setRole("u-owner-b", "viewer", TENANT_B)
    expect(tx.membership.updateMany).toHaveBeenCalledWith({
      where: { userId: "u-owner-b", tenantId: TENANT_B },
      data: { role: "viewer" },
    })
  })

  it("refuse si l'utilisateur n'a pas de membership dans le tenant cible (0 ligne dans la transaction)", async () => {
    mockPrisma.membership.findUnique.mockResolvedValue(null)
    mockPrisma.user.findUniqueOrThrow.mockResolvedValue({ id: "u-x", email: "u@h", role: "viewer" })
    tx.membership.updateMany.mockResolvedValue({ count: 0 })

    await expect(setRole("u-x", "viewer", TENANT_B)).rejects.toThrow("pas de membership dans ce tenant")
  })
})

describe("deleteUser(..., tenantId) — scoping tenant + suppression globale conditionnée", () => {
  it("REFUSE de supprimer le DERNIER owner de B malgré des owners ailleurs", async () => {
    mockPrisma.membership.findUnique.mockResolvedValue({ role: "owner" })
    mockPrisma.membership.count.mockResolvedValue(1)

    await expect(deleteUser("u-owner-b", "u-acting", TENANT_B)).rejects.toThrow("impossible de supprimer le dernier owner")
  })

  it("retire la membership du tenant CIBLE sans supprimer le User (memberships restantes ailleurs)", async () => {
    mockPrisma.membership.findUnique.mockResolvedValue({ role: "operator" })
    // deleteMany dans le tenant demandé → 1 ligne ; une membership restante ailleurs.
    mockPrisma.membership.deleteMany.mockResolvedValue({ count: 1 })
    mockPrisma.membership.count.mockResolvedValue(1)

    const res = await deleteUser("u-cross", "u-acting", TENANT_B)

    expect(res).toEqual({ ok: true })
    expect(mockPrisma.membership.deleteMany).toHaveBeenCalledWith({ where: { userId: "u-cross", tenantId: TENANT_B } })
    expect(mockPrisma.membership.count).toHaveBeenCalledWith({ where: { userId: "u-cross" } })
    expect(mockPrisma.user.delete).not.toHaveBeenCalled()
  })

  it("supprime le User global si plus AUCUNE membership (plus de lien ailleurs)", async () => {
    mockPrisma.membership.findUnique.mockResolvedValue({ role: "operator" })
    mockPrisma.membership.deleteMany.mockResolvedValue({ count: 1 })
    mockPrisma.membership.count.mockResolvedValue(0)

    await deleteUser("u-seul", "u-acting", TENANT_B)

    expect(mockPrisma.user.delete).toHaveBeenCalledWith({ where: { id: "u-seul" } })
  })

  it("interdit de supprimer son propre compte (inchangé)", async () => {
    await expect(deleteUser("u-me", "u-me", DEFAULT)).rejects.toThrow("impossible de supprimer son propre compte")
    expect(mockPrisma.membership.findUnique).not.toHaveBeenCalled()
  })
})