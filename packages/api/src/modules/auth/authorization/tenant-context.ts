/**
 * TenantContext — résolution du tenant courant (Phase 2 : par défaut unique).
 * Phase 5B : résolu par sous-route /:tenantSlug, header, ou claim JWT (§13 du plan).
 */

import { prisma } from "../../../lib/prisma"

/** Retourne le tenant par défaut (compat V1). Lève si absent (runner backfill/bootstrap). */
export async function resolveTenantId(): Promise<string> {
  const tenant = await prisma.tenant.findUnique({ where: { slug: "default" } })
  if (!tenant) {
    throw new Error("tenant par défaut introuvable — lancer backfill ou bootstrap")
  }
  return tenant.id
}
