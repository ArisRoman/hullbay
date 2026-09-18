import { prisma } from "../../../lib/prisma"
import type { SecurityPolicy as PrismaSecurityPolicy } from "@prisma/client"
import { DEFAULT_TENANT_ID } from "../identity/auth-identity.service"

export interface SecurityPolicy {
  mfaRequireRoles: string[]
  loginFailLimit: number
  loginFailWindowMs: number
  lockoutMs: number
  rateBaseBackoffMs: number
  rateMaxBackoffMs: number
  sessionTtlMs: number
  providerAllowlist: string[]
}

const DEFAULTS: SecurityPolicy = {
  mfaRequireRoles: [],
  loginFailLimit: 5,
  loginFailWindowMs: 60_000,
  lockoutMs: 300_000,
  rateBaseBackoffMs: 30_000,
  rateMaxBackoffMs: 600_000,
  sessionTtlMs: 43_200_000,
  providerAllowlist: [],
}

function parseJsonArray(raw: string | null, fallback: string[]): string[] {
  if (!raw) return fallback
  try {
    return JSON.parse(raw) as string[]
  } catch {
    return fallback
  }
}

function toPolicy(p: PrismaSecurityPolicy): SecurityPolicy {
  return {
    mfaRequireRoles: parseJsonArray(p.mfaRequireRoles, DEFAULTS.mfaRequireRoles),
    loginFailLimit: p.loginFailLimit,
    loginFailWindowMs: p.loginFailWindowMs,
    lockoutMs: p.lockoutMs,
    rateBaseBackoffMs: DEFAULTS.rateBaseBackoffMs,
    rateMaxBackoffMs: DEFAULTS.rateMaxBackoffMs,
    sessionTtlMs: p.sessionTtlMs,
    providerAllowlist: parseJsonArray(p.providerAllowlist, DEFAULTS.providerAllowlist),
  }
}

export class SecurityPolicyService {
  private policiesByTenant = new Map<string, SecurityPolicy>()

  private ensurePolicy(tenantId: string): SecurityPolicy {
    let policy = this.policiesByTenant.get(tenantId)
    if (!policy) {
      policy = { ...DEFAULTS }
      this.policiesByTenant.set(tenantId, policy)
    }
    return policy
  }

  constructor() {
    if (!prisma.securityPolicy) return
    // Phase 5B : une policy PAR tenant (id fixe remplacé par `tenantId` unique).
    // Rétrocompat : la ligne singleton existante est rattachée au tenant par défaut
    // (backfill migration) ; on l'utilise pour amorcer la policy par défaut.
    prisma.securityPolicy.findUnique({ where: { tenantId: DEFAULT_TENANT_ID } })
      .then((p) => { if (p) this.policiesByTenant.set(DEFAULT_TENANT_ID, toPolicy(p)) })
      .catch(() => {})
    prisma.securityPolicy.upsert({
      where: { tenantId: DEFAULT_TENANT_ID },
      create: { tenantId: DEFAULT_TENANT_ID, mfaRequireRoles: "[]", loginFailLimit: 5, loginFailWindowMs: 60000, lockoutMs: 300000, sessionTtlMs: 43200000, providerAllowlist: "[]" },
      update: {},
    }).catch(() => {})
  }

  /** Policy du tenant par défaut (contextes non-requête : TTL session, rate-limit). */
  getPolicy(): SecurityPolicy {
    return this.ensurePolicy(DEFAULT_TENANT_ID)
  }

  /** Policy d'un tenant précis (routes owner). Charge depuis la DB, cache mémoire. */
  async getPolicyForTenant(tenantId: string): Promise<SecurityPolicy> {
    if (tenantId === DEFAULT_TENANT_ID) return this.getPolicy()
    if (!this.policiesByTenant.has(tenantId)) {
      const row = await prisma.securityPolicy.findUnique({ where: { tenantId } })
      this.policiesByTenant.set(tenantId, row ? toPolicy(row) : { ...DEFAULTS })
    }
    return this.policiesByTenant.get(tenantId)!
  }

  /**
   * Remplace partiellement la policy (tenant par défaut si non précisé) et
   * persiste en DB (upsert par tenantId).
   */
  override(policy: Partial<SecurityPolicy>, tenantId = DEFAULT_TENANT_ID): void {
    const current = this.ensurePolicy(tenantId)
    this.policiesByTenant.set(tenantId, { ...current, ...policy })
    const merged = this.policiesByTenant.get(tenantId)!
    const dbData = {
      mfaRequireRoles: JSON.stringify(policy.mfaRequireRoles ?? merged.mfaRequireRoles),
      loginFailLimit: policy.loginFailLimit ?? merged.loginFailLimit,
      loginFailWindowMs: policy.loginFailWindowMs ?? merged.loginFailWindowMs,
      lockoutMs: policy.lockoutMs ?? merged.lockoutMs,
      sessionTtlMs: policy.sessionTtlMs ?? merged.sessionTtlMs,
      providerAllowlist: JSON.stringify(policy.providerAllowlist ?? merged.providerAllowlist),
    }
    if (prisma.securityPolicy) prisma.securityPolicy.upsert({
      where: { tenantId },
      create: { tenantId, ...dbData },
      update: dbData,
    }).catch(() => {})
  }
}

export const securityPolicy = new SecurityPolicyService()
