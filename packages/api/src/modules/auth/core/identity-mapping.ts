/**
 * Identity Mapping : résout une ExternalIdentity (iss+sub) vers une identité enregistrée.
 * @@unique([providerId, issuer, subject]) assure l'unicité.
 *
 * - Identité connue → retourne le userId (mapping existant).
 * - Identité inconnue → crée une PendingIdentity (jamais de User en auto) et signale
 *   le besoin d'approbation. La création de User + AuthIdentity + Membership est
 *   effectuée en Phase 5A (correction N°20 du plan).
 *
 * Pour le provider local, les identités sont créées explicitement par
 * createOwner / createUser (Phase 2) : on ne passe jamais par le chemin "pending".
 *
 * NB : `issuer` est NULL pour local/ldap. L'input `findUnique` composé de Prisma
 * exige `issuer: string` — on passe donc par findFirst (filtres acceptant NULL).
 * NB PG : UNIQUE(NULL) ne dédoublonne pas ; un PendingIdentity à issuer NULL est
 * correctement évité ici par findFirst+create. (Chemin real pour oidc/saml : 3+/4.)
 */

import { prisma } from "../../../lib/prisma"
import { eventBus } from "../../../lib/event-bus"
import type { ExternalIdentity } from "../providers/types"
import { AUTH_AUDIT_EVENTS } from "../audit-events"

export interface ResolvedIdentity {
  userId: string
  providerId: string
  subject: string
  email?: string | null
}

/**
 * Résout une identité externe vers un enregistrement AuthIdentity existant,
 * ou crée une PendingIdentity si l'identité est totalement inconnue.
 */
export async function resolveIdentity(
  identity: ExternalIdentity,
): Promise<ResolvedIdentity> {
  const existing = await prisma.authIdentity.findFirst({
    where: {
      providerId: identity.providerId,
      issuer: identity.issuer,
      subject: identity.subject,
    },
  })

  if (existing) {
    return {
      userId: existing.userId,
      providerId: existing.providerId,
      subject: existing.subject,
      email: existing.email,
    }
  }

  // Identité inconnue : pending (pas de User créé en automatique).
  const pending = await prisma.pendingIdentity.findFirst({
    where: {
      providerId: identity.providerId,
      issuer: identity.issuer,
      subject: identity.subject,
    },
  })
  if (!pending) {
    await prisma.pendingIdentity.create({
      data: {
        providerId: identity.providerId,
        issuer: identity.issuer,
        subject: identity.subject,
        email: identity.email,
        name: identity.name,
      },
    })
    // Notifie le workflow d'approbation (5A1 — subscriber on-deploy-finished).
    // Fire-and-forget : la création de pending ne doit pas dépendre de l'audit.
    await eventBus.emit(AUTH_AUDIT_EVENTS.pendingCreated, {
      providerId: identity.providerId,
      email: identity.email ?? null,
      subject: identity.subject,
    })
  }

  // Le front affichera « cette identité est en attente d'approbation ».
  throw new IdentityPendingError(identity)
}

export class IdentityPendingError extends Error {
  readonly identity: ExternalIdentity
  constructor(identity: ExternalIdentity) {
    super("identité en attente d'approbation")
    this.name = "IdentityPendingError"
    this.identity = identity
  }
}
