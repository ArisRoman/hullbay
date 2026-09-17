import { describe, it, expect, beforeEach, vi } from "vitest"
import { JwksService } from "../jwks/jwks.service"

vi.mock("../../../../lib/prisma", () => ({ prisma: {} }))

describe("JwksService", () => {
  let service: JwksService

  beforeEach(() => {
    service = new JwksService()
    vi.clearAllMocks()
  })

  it("signPayload retourne un token JWT", () => {
    const token = service.signPayload({ sub: "u-1", role: "owner" })
    expect(typeof token).toBe("string")
  })

  it("verifyToken décode un token signé par signPayload", () => {
    const token = service.signPayload({ sub: "u-1", role: "owner" })
    const decoded = service.verifyToken(token)
    expect(decoded.sub).toBe("u-1")
  })

  it("verifyToken avec audience filtre", () => {
    const token = service.signPayload({ sub: "u-1", mfa: "pending", aud: "mfa-pending" })
    const decoded = service.verifyToken(token, "mfa-pending")
    expect(decoded).toBeDefined()
  })

  it("verifyToken rejette un token avec mauvaise audience", () => {
    const token = service.signPayload({ sub: "u-1" })
    expect(() => service.verifyToken(token, "wrong-audience")).toThrow()
  })

  it("rotation génère un nouveau kid sans couper les anciennes sessions", () => {
    const oldKid = service.getActiveKid()
    const newKid = service.rotate()
    expect(newKid).not.toBe(oldKid)
    const keys = service.getJwks().keys
    expect(keys.length).toBe(2)
    expect(keys[0].kid).toBe(newKid)
    expect(keys[1].kid).toBe(oldKid)
  })

  it("verifyToken après rotation valide les tokens signés avec l'ancien kid", () => {
    const token = service.signPayload({ sub: "u-1", role: "owner" })
    const kid = service.getActiveKid()
    service.rotate()
    const decoded = service.verifyToken(token)
    expect(decoded.sub).toBe("u-1")
  })

  it("getJwks retourne un keyset non vide", () => {
    const jwks = service.getJwks()
    expect(jwks.keys.length).toBeGreaterThan(0)
    expect(jwks.keys[0].kty).toBe("RSA")
  })
})
