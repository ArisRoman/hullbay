/**
 * Phase 5B — tenancy : résolution du tenant courant par requête (§4.2 du plan).
 *
 * Source du tenant (priorité décroissante) :
 *   1. Header `x-tenant-id` (override admin cross-tenant, validé en guard).
 *   2. Claim `tenantId` du token de session (panel attaché à la signature).
 *   3. Fallback : tenant par défaut (données héritées pré-5B).
 */

import type { FastifyRequest } from "fastify"
import { DEFAULT_TENANT_ID } from "../identity/auth-identity.service"

export const TENANT_HEADER = "x-tenant-id"

export interface TenantScopedRequest extends FastifyRequest {
  user?: { sub: string; role: string; mfaEnabled: boolean; tenantId: string }
  tenantId?: string
}

/** Tenant demandé via header (undefined = pas d'override). */
export function tenantFromHeader(req: FastifyRequest): string | undefined {
  const raw = req.headers[TENANT_HEADER]
  return typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : undefined
}

/** Tenant effectif de la requête (header > token > défaut). */
export function effectiveTenantId(req: TenantScopedRequest): string {
  return tenantFromHeader(req) ?? req.user?.tenantId ?? DEFAULT_TENANT_ID
}

/** Tenant effectif pour un usage hors-requête (worker/job) : token ? défaut. */
export function tenantFromToken(token: { tenantId?: string }): string {
  return token.tenantId ?? DEFAULT_TENANT_ID
}