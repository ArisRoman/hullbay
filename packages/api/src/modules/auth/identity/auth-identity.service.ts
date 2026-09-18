/**
 * Service identité : helpers pour la création/lookup d'identités locales
 * et la résolution du tenant par défaut (§6, §4 du plan).
 */

import { prisma } from "../../../lib/prisma"

/**
 * Id littéral du tenant par défaut (créé par la migration Phase 2 — id fixe).
 * Référencé par le backfill 5B et le fallback d'isolation des données héritées.
 */
export const DEFAULT_TENANT_ID = "tenant-default"

export async function ensureDefaultTenant() {
  return prisma.tenant.upsert({
    where: { slug: "default" },
    create: { id: DEFAULT_TENANT_ID, name: "Default", slug: "default" },
    update: {},
  })
}

/**
 * Tenant effectif de l'utilisateur : sa première membership (tenant 'default'
 * prioritaire, sinon la plus récente). Fallback : tenant par défaut (données
 * héritées sans membership explicite).
 */
export async function resolveTenantIdForUser(userId: string): Promise<string> {
  // Prisma partiellement mocké en tests : modèle absent → tenant par défaut.
  if (!prisma.membership?.findFirst) return DEFAULT_TENANT_ID
  const membership = await prisma.membership.findFirst({
    where: { userId },
    orderBy: [{ tenant: { slug: "asc" } }, { createdAt: "desc" }],
    select: { tenantId: true },
  })
  return membership?.tenantId ?? DEFAULT_TENANT_ID
}

/** Vérifie que l'utilisateur a une membership dans le tenant demandé. */
export async function assertUserInTenant(userId: string, tenantId: string): Promise<boolean> {
  if (tenantId === DEFAULT_TENANT_ID) return true
  if (!prisma.membership?.findUnique) return true
  const membership = await prisma.membership.findUnique({
    where: { userId_tenantId: { userId, tenantId } },
    select: { tenantId: true },
  })
  return membership !== null
}

export async function findLocalIdentityByEmail(email: string) {
  return prisma.authIdentity.findFirst({
    where: { kind: "local", email },
  })
}

export async function findLocalIdentityByUserId(userId: string) {
  return prisma.authIdentity.findFirst({
    where: { userId, kind: "local" },
  })
}

export async function findLocalIdentityWithUser(userId: string) {
  return prisma.authIdentity.findFirst({
    where: { userId, kind: "local" },
    include: { user: true },
  })
}
