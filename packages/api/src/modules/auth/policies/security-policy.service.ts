/**
 * SecurityPolicyService (Phase 5A1 : stub → réel, singleton conservé).
 *
 * Politique de sécurité centralisée, lue au démarrage. En 5A1 la source est
 * l'environnement (variables AUTH_POLICY_*) — le modèle Prisma SecurityPolicy
 * (persistance par tenant) arrive en Phase 5A2. Le singleton garantit une
 * lecture unique par process et des mutations faciles à brancher plus tard.
 *
 * - mfaRequireRoles : rôles pour lesquels une MFA LOCALE est imposée, même si
 *   l'IdP SSO en fournit une (plan §10 — jamais de 2e MFA inutile par défaut).
 * - Seuils de rate-limiting login (anti-énumération / brute-force), cf.
 *   modules/auth/rate-limit.ts.
 * - providerAllowlist : ids de providers autorisés ([] = tous). Restreint les
 *   providers SSO utilisables — protection contre un provider oublié.
 */

const DEFAULTS = {
  mfaRequireRoles: [] as string[],
  loginFailLimit: 5,
  loginFailWindowMs: 60_000,
  rateBaseBackoffMs: 30_000,
  rateMaxBackoffMs: 600_000,
  sessionTtlMs: 30 * 60_000,
  providerAllowlist: [] as string[],
}

export interface SecurityPolicy {
  mfaRequireRoles: string[]
  loginFailLimit: number
  loginFailWindowMs: number
  rateBaseBackoffMs: number
  rateMaxBackoffMs: number
  sessionTtlMs: number
  /** Ids de providers autorisés ; [] = aucun filtre (tous). */
  providerAllowlist: string[]
}

function envCsv(name: string): string[] {
  const raw = process.env[name]
  if (!raw) return []
  return raw
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const n = Number.parseInt(raw, 10)
  return Number.isFinite(n) && n > 0 ? n : fallback
}

export class SecurityPolicyService {
  private policy: SecurityPolicy

  constructor() {
    this.policy = {
      mfaRequireRoles: envCsv("AUTH_POLICY_MFA_REQUIRE_ROLES"),
      loginFailLimit: envInt("AUTH_POLICY_LOGIN_FAIL_LIMIT", DEFAULTS.loginFailLimit),
      loginFailWindowMs: envInt("AUTH_POLICY_LOGIN_FAIL_WINDOW_MS", DEFAULTS.loginFailWindowMs),
      rateBaseBackoffMs: envInt("AUTH_POLICY_RATE_BASE_BACKOFF_MS", DEFAULTS.rateBaseBackoffMs),
      rateMaxBackoffMs: envInt("AUTH_POLICY_RATE_MAX_BACKOFF_MS", DEFAULTS.rateMaxBackoffMs),
      sessionTtlMs: envInt("AUTH_POLICY_SESSION_TTL_MS", DEFAULTS.sessionTtlMs),
      providerAllowlist: envCsv("AUTH_POLICY_PROVIDER_ALLOWLIST"),
    }
  }

  getPolicy(): SecurityPolicy {
    return this.policy
  }

  /** Remplace la politique (surcharge par tenant en 5A2 ; tests par env). */
  override(policy: Partial<SecurityPolicy>): void {
    this.policy = { ...this.policy, ...policy }
  }
}

/** Singleton partagé sur le process. */
export const securityPolicy = new SecurityPolicyService()