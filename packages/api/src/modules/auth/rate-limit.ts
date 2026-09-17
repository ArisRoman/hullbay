/**
 * Rate limiting composé des routes d'authentification : clé = IP + compte
 * (identifiant de connexion quand il existe) + endpoint, fenêtre glissante +
 * backoff exponentiel. Le blocage est armé sur échecs répétés et le compteur est
 * remis à zéro sur succès.
 *
 * Réponse de blocage uniforme : ni le statut ni le délai ne distinguent un compte
 * existant d'un compte inexistant (anti-énumération).
 *
 * Persistance en mémoire process-local — seuils configurés par la politique de
 * sécurité (5A1 : env ; 5A2 : par tenant). `clear()` sert aux tests.
 */

import { securityPolicy } from "./policies/security-policy.service"

export interface RateLimitConfig {
  maxFailures: number
  windowMs: number
  baseBackoffMs: number
  maxBackoffMs: number
}

const DEFAULT_CONFIG: RateLimitConfig = {
  maxFailures: 5,
  windowMs: 60_000,
  baseBackoffMs: 30_000,
  maxBackoffMs: 600_000,
}

/** Config initiale depuis la politique de sécurité (env en 5A1, tenant en 5A2). */
function configFromPolicy(): RateLimitConfig {
  const p = securityPolicy.getPolicy()
  return {
    maxFailures: p.loginFailLimit,
    windowMs: p.loginFailWindowMs,
    baseBackoffMs: p.rateBaseBackoffMs,
    maxBackoffMs: p.rateMaxBackoffMs,
  }
}

interface Bucket {
  failures: number[]
  blockedUntil: number
  backoffMs: number
}

export interface RateLimitDecision {
  blocked: boolean
  retryAfterSec?: number
}

export class CompositeRateLimiter {
  private readonly configSource: () => RateLimitConfig
  private buckets = new Map<string, Bucket>()

  /**
   * `config` peut être un objet statique (tests) ou un provider relu à chaque
   * appel — indispensable pour que les changements de politique (5A2, par
   * tenant) s'appliquent sans redémarrage.
   */
  constructor(config: Partial<RateLimitConfig> | (() => Partial<RateLimitConfig>) = {}) {
    if (typeof config === "function") {
      this.configSource = () => ({ ...DEFAULT_CONFIG, ...config() })
    } else {
      const staticConfig = { ...DEFAULT_CONFIG, ...config }
      this.configSource = () => staticConfig
    }
  }

  private config(): RateLimitConfig {
    return this.configSource()
  }

  keyFor(ip: string, endpoint: string, account?: string): string {
    const accountPart = account ? `|${account.trim().toLowerCase()}` : ""
    return `${ip}|${endpoint}${accountPart}`
  }

  /** Vérifie avant tentative : si bloqué, renvoie le délai restant à respecter. */
  check(key: string): RateLimitDecision {
    this.evict()
    const bucket = this.buckets.get(key)
    if (!bucket) return { blocked: false }
    const now = Date.now()
    if (bucket.blockedUntil > now) {
      return { blocked: true, retryAfterSec: this.remaining(bucket.blockedUntil, now) }
    }
    return { blocked: false }
  }

  /**
   * Enregistre un échec (après une tentative rejetée). Quand le seuil de la
   * fenêtre glissante est atteint, arme un blocage avec backoff exponentiel.
   */
  recordFailure(key: string): void {
    this.evict()
    const config = this.config()
    const now = Date.now()
    let bucket = this.buckets.get(key)
    if (!bucket) {
      bucket = { failures: [], blockedUntil: 0, backoffMs: config.baseBackoffMs }
      this.buckets.set(key, bucket)
    }
    if (bucket.blockedUntil > now) return
    bucket.failures.push(now)
    bucket.failures = bucket.failures.filter((t) => now - t < config.windowMs)
    if (bucket.failures.length >= config.maxFailures) {
      bucket.blockedUntil = now + bucket.backoffMs
      bucket.backoffMs = Math.min(bucket.backoffMs * 2, config.maxBackoffMs)
      bucket.failures = []
    }
  }

  /** Succès d'authentification : efface l'historique du compteur. */
  reset(key: string): void {
    this.buckets.delete(key)
  }

  /** Réinitialise tous les compteurs (tests). */
  clear(): void {
    this.buckets.clear()
  }

  private remaining(blockedUntil: number, now: number): number {
    return Math.max(1, Math.ceil((blockedUntil - now) / 1000))
  }

  // Prévention fuite mémoire : au-delà d'un seuil de buckets, purge les buckets
  // sans activité après windowMs + maxBackoffMs.
  private evict(): void {
    if (this.buckets.size < 4096) return
    const now = Date.now()
    const config = this.config()
    const stale = config.windowMs + config.maxBackoffMs
    for (const [key, bucket] of this.buckets) {
      const lastActivity =
        bucket.failures[bucket.failures.length - 1] ?? bucket.blockedUntil
      if (now - lastActivity > stale) this.buckets.delete(key)
    }
  }
}

/** Instance partagée process-local, utilisée par les routes d'authentification. */
export const authRateLimiter = new CompositeRateLimiter(configFromPolicy)