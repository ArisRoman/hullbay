import { describe, it, expect, beforeEach, vi } from "vitest"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import jwt from "jsonwebtoken"
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
    expect(keys[0]!.kid).toBe(newKid)
    expect(keys[1]!.kid).toBe(oldKid)
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
    expect(jwks.keys[0]!.kty).toBe("RSA")
  })

  // ── Durcissement ──

  it("rejette un token dont le kid est inconnu SANS fallback HS256", () => {
    const forged = jwt.sign(
      { sub: "attacker", role: "owner", mfaEnabled: true },
      process.env.JWT_SECRET ?? "fallback-jwt-secret-change-me",
      { algorithm: "HS256", header: { kid: "unknown-kid", alg: "HS256" } },
    )
    expect(() => service.verifyToken(forged)).toThrow()
  })

  it("accepte les anciens tokens HMAC sans kid quand JWT_SECRET est défini", () => {
    process.env.JWT_SECRET = "legacy-test-secret"
    try {
      const svc = new JwksService()
      const legacy = jwt.sign({ sub: "u-1", role: "owner" }, "legacy-test-secret", { algorithm: "HS256" })
      const decoded = svc.verifyToken(legacy)
      expect(decoded.sub).toBe("u-1")
    } finally {
      delete process.env.JWT_SECRET
    }
  })

  it("persiste le keyring sur disque et le recharge à l'identique", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jwks-"))
    const file = path.join(dir, "keyring.json")
    try {
      const a = new JwksService({ keyringPath: file })
      const kid = a.getActiveKid()
      const token = a.signPayload({ sub: "u-1", role: "owner" })

      const b = new JwksService({ keyringPath: file })
      expect(b.getActiveKid()).toBe(kid)
      expect(b.verifyToken(token).sub).toBe("u-1")
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  it("borne le keyring après plusieurs rotations", () => {
    for (let i = 0; i < 6; i++) service.rotate()
    expect(service.getJwks().keys.length).toBeLessThanOrEqual(4)
  })

  it("régénère un keyring corrompu sans throw et sauvegarde le fichier", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jwks-corrupt-"))
    const file = path.join(dir, "keyring.json")
    try {
      fs.writeFileSync(file, "{ not json")
      const svc = new JwksService({ keyringPath: file })
      expect(svc.getJwks().keys.length).toBeGreaterThan(0)
      expect(fs.readdirSync(dir).some((f) => f.includes(".corrupt-"))).toBe(true)
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  it("régénère quand les clés PEM du keyring sont invalides", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jwks-badpem-"))
    const file = path.join(dir, "keyring.json")
    try {
      fs.writeFileSync(
        file,
        JSON.stringify([{ kid: "x", privatePem: "not-a-pem", publicPem: "not-a-pem", createdAt: Date.now(), active: true }]),
      )
      const svc = new JwksService({ keyringPath: file })
      expect(svc.getJwks().keys.length).toBeGreaterThan(0)
      expect(svc.getActiveKid()).not.toBe("x")
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })
})
