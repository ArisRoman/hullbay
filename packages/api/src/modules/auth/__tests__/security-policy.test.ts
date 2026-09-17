import { describe, it, expect, beforeEach, vi } from "vitest"
import { SecurityPolicyService } from "../policies/security-policy.service"

vi.mock("../../../../lib/prisma", () => ({ prisma: {} }))

describe("SecurityPolicyService", () => {
  let service: SecurityPolicyService

  beforeEach(() => {
    service = new SecurityPolicyService()
    vi.clearAllMocks()
  })

  it("getPolicy retourne une politique par défaut", () => {
    const policy = service.getPolicy()
    expect(policy.mfaRequireRoles).toEqual([])
    expect(policy.loginFailLimit).toBe(5)
    expect(policy.sessionTtlMs).toBe(43_200_000)
  })

  it("override met à jour la politique", () => {
    service.override({ loginFailLimit: 10, sessionTtlMs: 3600_000 })
    const policy = service.getPolicy()
    expect(policy.loginFailLimit).toBe(10)
    expect(policy.sessionTtlMs).toBe(3600_000)
  })

  it("override conserve les champs non spécifiés", () => {
    service.override({ loginFailLimit: 3 })
    const policy = service.getPolicy()
    expect(policy.loginFailLimit).toBe(3)
    expect(policy.sessionTtlMs).toBe(43_200_000)
  })

  it("mfaRequireRoles par défaut est vide", () => {
    const policy = service.getPolicy()
    expect(policy.mfaRequireRoles).toEqual([])
  })

  it("providerAllowlist par défaut est vide", () => {
    const policy = service.getPolicy()
    expect(policy.providerAllowlist).toEqual([])
  })
})
