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
 * sécurité du tenant (relue à chaque appel). `clear()` sert aux tests.
 *
 * CONTRAINTE DE DÉPLOIEMENT : buckets process-local. En multi-instance, le
 * compteur d'échecs est par instance (répartition des tentatives) ; un attaquant
 * distribué peut diviser le budget. Single-instance requis pour une anti-force
 * stricte ; en cluster, compléter par une cage au niveau du proxy/edge.
 */

import type { FastifyRequest } from "fastify"
import { securityPolicy } from "./policies/security-policy.service"
import { DEFAULT_TENANT_ID } from "./identity/auth-identity.service"

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

/** Config depuis la politique de sécurité du tenant, relue à chaque appel.
 *  Le tenant est relu par appel (seuils par tenant) — `getPolicyCached`
 *  synchronise le cache tenant, pas seulement le défaut. */
function configFromPolicy(tenantId?: string): RateLimitConfig {
  const p = securityPolicy.getPolicyCached(tenantId ?? DEFAULT_TENANT_ID)
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
  private readonly configSource: (tenantId?: string) => RateLimitConfig
  private buckets = new Map<string, Bucket>()

  /**
   * `config` peut être un objet statique (tests) ou un provider relu à chaque
   * appel — indispensable pour que les changements de politique (par
   * tenant) s'appliquent sans redémarrage. Le provider prend le tenantId
   * effectif de la requête (seuils par tenant, B2).
   */
  constructor(config: Partial<RateLimitConfig> | ((tenantId?: string) => Partial<RateLimitConfig>) = {}) {
    if (typeof config === "function") {
      this.configSource = (tenantId) => ({ ...DEFAULT_CONFIG, ...config(tenantId) })
    } else {
      const staticConfig = { ...DEFAULT_CONFIG, ...config }
      this.configSource = () => staticConfig
    }
  }

  private config(tenantId?: string): RateLimitConfig {
    return this.configSource(tenantId)
  }

  keyFor(ip: string, endpoint: string, account?: string, tenantId?: string): string {
    const accountPart = account ? `|${account.trim().toLowerCase()}` : ""
    const tenantPart = tenantId ? `|tenant:${tenantId}` : ""
    return `${ip}|${endpoint}${accountPart}${tenantPart}`
  }

  /** Vérifie avant tentative : si bloqué, renvoie le délai restant à respecter. */
  check(key: string, tenantId?: string): RateLimitDecision {
    this.evict(tenantId)
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
  recordFailure(key: string, tenantId?: string): void {
    this.evict(tenantId)
    const config = this.config(tenantId)
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
  reset(key: string, _tenantId?: string): void {
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
  private evict(tenantId?: string): void {
    if (this.buckets.size < 4096) return
    const now = Date.now()
    const config = this.config(tenantId)
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

/**
 * Tenant à engager dans la clé de rate-limit : post-auth → tenant de session
 * (claim) sinon tenant de requête ; pré-auth (login, bootstrap) → aucun contexte,
 * tenant par défaut. Isole les buckets par tenant — un compte du tenant A ne
 * sature pas le bucket du même compte/email au tenant B.
 */
export function rateLimitTenant(req: FastifyRequest): string {
  const scoped = req as FastifyRequest & { user?: { tenantId?: string }; tenantId?: string }
  return scoped.user?.tenantId ?? scoped.tenantId ?? DEFAULT_TENANT_ID
}