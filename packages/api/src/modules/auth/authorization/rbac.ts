/**
 * RBAC — autorisation par rôle (déplacé depuis modules/auth/rbac.ts).
 * Phase 2 : rôle résolu depuis User.role (MIRROR temporaire). Phase 5B :
 * résolution via Membership(tenant courant).role (§13 du plan).
 *
 * Rôles : owner (tout) > operator (projets + deploy/destroy) > viewer (lecture).
 */

import type { FastifyRequest, FastifyReply } from "fastify"
import { resolveRoleForUser } from "../identity/auth-identity.service"

export type Role = "owner" | "operator" | "viewer"

// Stand: un rôle inconnu (absent de RANK) est traité comme viewer (fail-closed :
// toute valeur hors enum ne peut PAS dépasser la garde requireRole). Voir note rbac.
const RANK: Record<Role, number> = { viewer: 0, operator: 1, owner: 2 }
const UNKNOWN_ROLE_RANK = 0 // rang le plus bas : un rôle non-enum ne gagne jamais de permission

type AuthedRequest = FastifyRequest & { user?: { sub: string; role: Role } }

/**
 * preHandler Fastify : exige au moins le rôle `min`. À attacher sur les routes
 * sensibles, ex: `{ preHandler: requireRole("operator") }`.
 */
export function requireRole(min: Role) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as AuthedRequest).user
    if (!user) return reply.code(401).send({ error: "non authentifié" })

    let role = user.role
    // Privilège cross-tenant (Phase 5B) : si un header resolv un AUTRE tenant que
    // celui du token, le rôle signé ne vaut pas là-bas → on résout la membership
    // du tenant cible, sinon un owner tenant-A passerait owner partout (tenancy
    // fantôme). Même tenant → le claim signé (issu de membership au sign) est fiable.
    const t = req as unknown as { tenantId?: string; user?: { tenantId?: string } }
    if (t.tenantId && t.user?.tenantId && t.tenantId !== t.user.tenantId) {
      //  fail-closed → "viewer", jamais le rôle signé du tenant
      // d'origine. La résolution (membership du tenant cible) a déjà été
      // validée par la garde (assertUserInTenant) ; en cas d'échec de la
      // résolution, un owner tenant-A ne doit PAS hériter ici d'un rôle élevé.
      role = await resolveRoleForUser(user.sub, t.tenantId, "viewer")
    }

    // Fail-closed : un rôle hors enum (RANK[role] === undefined) est traité au
    // rang le plus bas. `UNKNOWN_ROLE_RANK` est BEU - pas `undefined < min` qui
    // serait évalué `false` et laisserait passer un rôle inconnu (fail-open).
    const rank = RANK[role] ?? UNKNOWN_ROLE_RANK
    if (rank < RANK[min]) {
      return reply.code(403).send({ error: "permission insuffisante" })
    }
  }
}

/** Récupère l'utilisateur courant (après la garde). */
export function currentUser(req: FastifyRequest): { sub: string; role: Role } | undefined {
  return (req as AuthedRequest).user
}
