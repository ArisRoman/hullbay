import { prisma } from "../../../lib/prisma"
import type { SecurityPolicy as PrismaSecurityPolicy } from "@prisma/client"

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
  private policy: SecurityPolicy = { ...DEFAULTS }

  constructor() {
    if (prisma.securityPolicy) {
      prisma.securityPolicy.findUnique({ where: { id: "singleton" } })
        .then((p) => { if (p) this.policy = toPolicy(p) })
        .catch(() => {})
      prisma.securityPolicy.upsert({
        where: { id: "singleton" },
        create: { id: "singleton", mfaRequireRoles: "[]", loginFailLimit: 5, loginFailWindowMs: 60000, lockoutMs: 300000, sessionTtlMs: 43200000, providerAllowlist: "[]" },
        update: {},
      }).catch(() => {})
    }
  }

  getPolicy(): SecurityPolicy {
    return this.policy
  }

  override(policy: Partial<SecurityPolicy>): void {
    this.policy = { ...this.policy, ...policy }
    const dbData = {
      mfaRequireRoles: JSON.stringify(policy.mfaRequireRoles ?? this.policy.mfaRequireRoles),
      loginFailLimit: policy.loginFailLimit ?? this.policy.loginFailLimit,
      loginFailWindowMs: policy.loginFailWindowMs ?? this.policy.loginFailWindowMs,
      lockoutMs: policy.lockoutMs ?? this.policy.lockoutMs,
      sessionTtlMs: policy.sessionTtlMs ?? this.policy.sessionTtlMs,
      providerAllowlist: JSON.stringify(policy.providerAllowlist ?? this.policy.providerAllowlist),
    }
    if (prisma.securityPolicy) prisma.securityPolicy.upsert({
      where: { id: "singleton" },
      create: { id: "singleton", ...dbData },
      update: dbData,
    }).catch(() => {})
  }
}

export const securityPolicy = new SecurityPolicyService()
