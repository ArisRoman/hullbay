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
})
