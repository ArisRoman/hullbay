/**
 * Service identité : helpers pour la création/lookup d'identités locales
 * et la résolution du tenant par défaut (§6, §4 du plan).
 */

import { prisma } from "../../../lib/prisma"

export async function ensureDefaultTenant() {
  return prisma.tenant.upsert({
    where: { slug: "default" },
    create: { name: "Default", slug: "default" },
    update: {},
  })
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
