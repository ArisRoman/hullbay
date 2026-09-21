import { describe, it, expect, beforeEach, beforeAll, afterAll } from "vitest"
import { UserSessionStore } from "../sessions/user-session.store"
import { jwksService } from "../jwks/jwks.service"

const TEST_JWT_SECRET = "session-store-test-secret"
const savedJwtSecret = process.env.JWT_SECRET

describe("UserSessionStore", () => {
  let store: UserSessionStore

  beforeAll(() => {
    process.env.JWT_SECRET = TEST_JWT_SECRET
  })

  afterAll(() => {
    if (savedJwtSecret === undefined) {
      delete process.env.JWT_SECRET
    } else {
      process.env.JWT_SECRET = savedJwtSecret
    }
  })

  beforeEach(() => {
    store = new UserSessionStore()
  })

  it("signSession retourne un token valide avec jti", () => {
    const token = store.signSession("u-1", "owner", true)
    expect(typeof token).toBe("string")
    expect(token.length).toBeGreaterThan(0)
  })

  it("verifySession valide un token signé par signSession", () => {
    const token = store.signSession("u-1", "owner", true)
    const handle = store.verifySession(token)
    expect(handle.sub).toBe("u-1")
    expect(handle.role).toBe("owner")
    expect(handle.mfaEnabled).toBe(true)
  })

  it("verifySession rejette un token sans jti", () => {
    const token = jwksService.signPayload({ sub: "u-1", role: "owner" }, { audience: "session" })
    expect(() => store.verifySession(token)).toThrow("sans jti")
  })

  it("signPending retourne un token mfa-pending", () => {
    const token = store.signPending("u-1")
    expect(typeof token).toBe("string")
  })

  it("verifyPending valide un token mfa-pending", () => {
    const token = store.signPending("u-1")
    const result = store.verifyPending(token)
    expect(result.sub).toBe("u-1")
  })

  it("verifyPending rejette un token non-pending", () => {
    const token = jwksService.signPayload({ sub: "u-1" })
    expect(() => store.verifyPending(token as unknown as string)).toThrowError(
      expect.objectContaining({ code: "mfa_token_invalid" }),
    )
  })

  it("revoke invalide immédiatement le token (fast-path cache compris)", async () => {
    const token = store.signSession("u-1", "owner", true)
    const { jti } = jwksService.verifyToken(token) as { jti: string }
    await store.revoke(jti)
    expect(() => store.verifySession(token)).toThrow("session révoquée")
  })

  it("revoke d'une session n'affecte pas les autres sessions de l'utilisateur", async () => {
    const tokenA = store.signSession("u-1", "owner", true)
    const tokenB = store.signSession("u-1", "owner", true)
    const { jti } = jwksService.verifyToken(tokenA) as { jti: string }
    await store.revoke(jti)
    expect(() => store.verifySession(tokenA)).toThrow()
    expect(store.verifySession(tokenB).sub).toBe("u-1")
  })

  it("revokeUserSessions révoque TOUTES les sessions de l'utilisateur", async () => {
    const tokenA = store.signSession("u-1", "viewer", false)
    const tokenB = store.signSession("u-1", "viewer", false)
    await store.revokeUserSessions("u-1")
    expect(() => store.verifySession(tokenA)).toThrow("session révoquée")
    expect(() => store.verifySession(tokenB)).toThrow("session révoquée")
  })

  it("revokeUserSessions(notJti) préserve la session courante", async () => {
    const tokenA = store.signSession("u-1", "viewer", false)
    const tokenB = store.signSession("u-1", "viewer", false)
    const { jti } = jwksService.verifyToken(tokenA) as { jti: string }
    await store.revokeUserSessions("u-1", jti)
    expect(store.verifySession(tokenA).sub).toBe("u-1")
    expect(() => store.verifySession(tokenB)).toThrow("session révoquée")
  })

  it("revokeUserSessions n'affecte pas les sessions des autres utilisateurs", async () => {
    const tokenA = store.signSession("u-1", "viewer", false)
    const tokenB = store.signSession("u-2", "viewer", false)
    await store.revokeUserSessions("u-1")
    expect(() => store.verifySession(tokenA)).toThrow("session révoquée")
    expect(store.verifySession(tokenB).sub).toBe("u-2")
  })
})
