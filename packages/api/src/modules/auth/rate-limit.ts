/**
 * Rate limiting composé des routes d'authentification : clé = IP + compte
 * (identifiant de connexion quand il existe) + endpoint, fenêtre glissante +
 * backoff exponentiel. Le blocage est armé sur échecs répétés et le compteur est
 * remis à zéro sur succès.
 *
 * Réponse de blocage uniforme : ni le statut ni le délai ne distinguent un compte
 * existant d'un compte inexistant (anti-énumération).
 *
 * Persistance en mémoire process-local — seuils par défaut jusqu'à la
 * configuration dynamique (SecurityPolicy). `clear()` sert aux tests.
 */

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
  private readonly config: RateLimitConfig
  private buckets = new Map<string, Bucket>()

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
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
    const now = Date.now()
    let bucket = this.buckets.get(key)
    if (!bucket) {
      bucket = { failures: [], blockedUntil: 0, backoffMs: this.config.baseBackoffMs }
      this.buckets.set(key, bucket)
    }
    if (bucket.blockedUntil > now) return
    bucket.failures.push(now)
    bucket.failures = bucket.failures.filter((t) => now - t < this.config.windowMs)
    if (bucket.failures.length >= this.config.maxFailures) {
      bucket.blockedUntil = now + bucket.backoffMs
      bucket.backoffMs = Math.min(bucket.backoffMs * 2, this.config.maxBackoffMs)
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
    const stale = this.config.windowMs + this.config.maxBackoffMs
    for (const [key, bucket] of this.buckets) {
      const lastActivity =
        bucket.failures[bucket.failures.length - 1] ?? bucket.blockedUntil
      if (now - lastActivity > stale) this.buckets.delete(key)
    }
  }
}

/** Instance partagée process-local, utilisée par les routes d'authentification. */
export const authRateLimiter = new CompositeRateLimiter()