/**
 * PendingApprovalService (Phase 5A1, correction N°20 du plan) : workflow
 * d'approbation des identités externes. Une identité inconnue d'un IdP est
 * matérialisée en PendingIdentity par identity-mapping.resolveIdentity — JAMAIS
 * de User créé en auto-provision.
 *
 * approve() crée atomiquement (1 transaction) :
 *   - le User (réutilisé si un compte à cet email existe déjà — email @unique)
 *   - l'AuthIdentity (providerId+issuer+subject, liaison au User)
 *   - la Membership [{tenantId, role}] du tenant demandé
 *   - passe la PendingIdentity à "approved" (requestedForTenantId = tenantId)
 *
 * reject() marque la demande "rejected". Les deux émettent un event d'audit
 * (auth.pending.approved / auth.pending.rejected) journalisé par le subscriber
 * on-deploy-finished (notification : eventBus + AuditLog).
 */

import { prisma } from "../../../lib/prisma"
import type { PendingIdentity } from "@prisma/client"
import { eventBus } from "../../../lib/event-bus"
import { AUTH_AUDIT_EVENTS } from "../audit-events"

export type ApproveTarget = {
  tenantId: string
  role: "owner" | "operator" | "viewer"
}

export class PendingApprovalError extends Error {}

/** Liste les demandes en attente (owner). */
export async function listPendingIdentities(): Promise<PendingIdentity[]> {
  return prisma.pendingIdentity.findMany({
    where: { status: "pending" },
    orderBy: { createdAt: "asc" },
  })
}

/** Recherche une demande précise (owner) — UNDEFINED si absente ou traitée. */
export async function getPendingIdentity(id: string): Promise<PendingIdentity | null> {
  return prisma.pendingIdentity.findFirst({ where: { id, status: "pending" } })
}

/**
 * Approuve une identité externe : crée/réutilise le User, attache l'identité au
 * provider, ajoute la membership [tenantId, role]. Atomicité via transaction.
 * Renvoie { user, membership } pour la réponse (jamais de données sensibles).
 */
export async function approvePendingIdentity<const T extends ApproveTarget>(
  pending: PendingIdentity,
  actorUserId: string | undefined,
  target: T,
): Promise<{ userId: string; tenantId: string; role: T["role"] }> {
  if (!pending.issuer) {
    throw new PendingApprovalError("l'approbation exige une identité avec issuer (SSO) — demandes locales hors workflow")
  }

  const tenant = await prisma.tenant.findUnique({ where: { id: target.tenantId } })
  if (!tenant) {
    throw new PendingApprovalError("tenant introuvable")
  }

  const provider = await prisma.authProvider.findUnique({ where: { id: pending.providerId } })
  if (!provider) {
    throw new PendingApprovalError("provider d'origine introuvable ou supprimé")
  }

  const result = await prisma.$transaction(async (tx) => {
    // Réutilise le User existant sur cet email (email @unique), sinon le crée.
    const existingUser = pending.email
      ? await tx.user.findUnique({ where: { email: pending.email } })
      : null
    const user =
      existingUser ??
      (await tx.user.create({
        data: {
          email: pending.email ?? null,
          name: pending.name ?? undefined,
          role: target.role, // mirror V1 ; le rôle réel vit sur Membership
        },
      }))

    // Anti-doublon : l'identité peut déjà exister (approbation concurrente).
    await tx.authIdentity
      .create({
        data: {
          userId: user.id,
          providerId: pending.providerId,
          kind: provider.kind,
          issuer: pending.issuer,
          subject: pending.subject,
          email: pending.email ?? null,
        },
      })
      .catch((err: unknown) => {
        if (err instanceof Error && /unique|constraint/i.test(err.message)) {
          throw new PendingApprovalError("cette identité est déjà rattachée à un compte")
        }
        throw err
      })

    const membership = await tx.membership.upsert({
      where: { userId_tenantId: { userId: user.id, tenantId: target.tenantId } },
      create: { userId: user.id, tenantId: target.tenantId, role: target.role },
      update: { role: target.role },
    })

    await tx.pendingIdentity.update({
      where: { id: pending.id },
      data: { status: "approved", requestedForTenantId: target.tenantId },
    })

    return { user, membership }
  })

  await eventBus.emit(AUTH_AUDIT_EVENTS.pendingApproved, {
    userId: actorUserId,
    targetUserId: result.user.id,
    email: result.user.email ?? null,
    providerId: pending.providerId,
    tenantId: target.tenantId,
    role: target.role,
  })

  return { userId: result.user.id, tenantId: target.tenantId, role: target.role }
}

/** Rejette une identité en attente (owner) — le pending garde sa trace. */
export async function rejectPendingIdentity(
  pending: PendingIdentity,
  actorUserId: string | undefined,
  reason?: string,
): Promise<void> {
  await prisma.pendingIdentity.update({
    where: { id: pending.id },
    data: { status: "rejected" },
  })
  await eventBus.emit(AUTH_AUDIT_EVENTS.pendingRejected, {
    userId: actorUserId,
    providerId: pending.providerId,
    email: pending.email ?? null,
    reason: reason ?? null,
  })
}