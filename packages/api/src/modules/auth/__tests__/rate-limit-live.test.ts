import { describe, it, expect } from "vitest"
import { CompositeRateLimiter, type RateLimitConfig } from "../rate-limit"

describe("CompositeRateLimiter — config dynamique", () => {
  it("relit la config à chaque échec (changement de politique sans redémarrage)", () => {
    let config: RateLimitConfig = {
      maxFailures: 5,
      windowMs: 60_000,
      baseBackoffMs: 1000,
      maxBackoffMs: 5000,
    }
    const limiter = new CompositeRateLimiter(() => config)

    for (let i = 0; i < 4; i++) limiter.recordFailure("k")
    expect(limiter.check("k").blocked).toBe(false)

    // La politique devient plus stricte : le seuil est relu immédiatement.
    config = { ...config, maxFailures: 2 }
    limiter.recordFailure("k")
    expect(limiter.check("k").blocked).toBe(true)
  })

  it("conserve le comportement d'une config statique (tests)", () => {
    const limiter = new CompositeRateLimiter({ maxFailures: 2 })
    limiter.recordFailure("k")
    limiter.recordFailure("k")
    expect(limiter.check("k").blocked).toBe(true)
  })

  it("transmet le tenant effectif au provider de config (seuils par tenant)", () => {
    const seen: (string | undefined)[] = []
    const limiter = new CompositeRateLimiter((tenantId) => {
      seen.push(tenantId)
      return { maxFailures: 2, windowMs: 1000, baseBackoffMs: 10, maxBackoffMs: 20 }
    })
    limiter.recordFailure("k|tenant:tenant-a", "tenant-a")
    limiter.check("k|tenant:tenant-b", "tenant-b")
    limiter.recordFailure("k|tenant:tenant-c", "tenant-c")
    // La config (donc les seuils/backoff) est relue pour le tenant de la requête,
    // pas sur le singleton par défaut (recordFailure → config(tenantId)).
    expect(seen).toEqual(["tenant-a", "tenant-c"])
    expect(limiter.check("k|tenant:tenant-b").blocked).toBe(false)
  })

  it("le tenant par défaut s'applique quand la requête n'en a pas (pré-auth)", () => {
    const seen: (string | undefined)[] = []
    const limiter = new CompositeRateLimiter((tenantId) => {
      seen.push(tenantId)
      return { maxFailures: 5, windowMs: 60_000, baseBackoffMs: 1000, maxBackoffMs: 5000 }
    })
    limiter.recordFailure("k")
    expect(seen[0]).toBe(undefined)
  })
})
