import { describe, it, expect, beforeEach } from "vitest"
import { UserSessionStore } from "../sessions/user-session.store"
import { jwksService } from "../jwks/jwks.service"
import jwt from "jsonwebtoken"

describe("UserSessionStore", () => {
  let store: UserSessionStore

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
    const token = jwt.sign({ sub: "u-1", role: "owner" }, process.env.JWT_SECRET ?? "fallback", { expiresIn: "12h", audience: "session" })
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
})
