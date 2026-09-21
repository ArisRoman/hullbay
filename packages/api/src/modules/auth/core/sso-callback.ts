/**
 * Traitement d'un callback SSO (OIDC/OAuth2, SAML, LDAP) :
 * ExternalIdentity → identity-mapping → session OU pending.
 *
 * - Identité connue → session signée (mfaEnabled=true : MFA gérée par l'IdP,
 *   pas de 2e MFA locale par défaut), lastLoginAt mis à jour.
 * - Identité inconnue → PendingIdentity créée par resolveIdentity (jamais de
 *   User en auto) ; on retourne un résultat "pending" pour que la route laisse
 *   le front annoncer l'attente d'approbation.
 */

import { prisma } from "../../../lib/prisma"
import { resolveIdentity, IdentityPendingError } from "./identity-mapping"
import { sessionManager } from "./session-manager"
import { resolveRoleForUser, resolveTenantIdForUser } from "../identity/auth-identity.service"
import type { ExternalIdentity } from "../providers/types"

export interface SsoPendingResult {
  pending: true
  identity: {
    providerId: string
    kind: string
    email?: string | null
    name?: string
  }
}

export interface SsoSessionResult {
  pending: false
  token: string
  userId: string
  role: string
  identity: ExternalIdentity
}

export type SsoCallbackResult = SsoPendingResult | SsoSessionResult

/**
 * Résout l'identité externe issue d'un provider vers une session (mapping
 * existant) ou un état pending. Fail-closed : jamais de création d'User ici,
 * même quand l'email externe ressemble à un compte existant.
 */
export async function processSsoCallback(identity: ExternalIdentity): Promise<SsoCallbackResult> {
  let resolved: Awaited<ReturnType<typeof resolveIdentity>>
  try {
    resolved = await resolveIdentity(identity)
  } catch (err) {
    if (err instanceof IdentityPendingError) {
      return {
        pending: true,
        identity: {
          providerId: err.identity.providerId,
          kind: err.identity.kind,
          email: err.identity.email,
          name: err.identity.name,
        },
      }
    }
    throw err
  }

  const user = await prisma.user.findUnique({ where: { id: resolved.userId } })
  if (!user) {
    throw new Error(`identity ${resolved.providerId}/${resolved.subject} rattachée à un User absent`)
  }

  // lastLoginAt : fire-and-forget, on n'échoue pas sur cette mise à jour.
  void prisma.authIdentity
    .updateMany({
      where: { providerId: identity.providerId, issuer: identity.issuer, subject: identity.subject },
      data: { lastLoginAt: new Date() },
    })
    .catch(() => {})

  // MFA locale : par défaut NON exigée après un SSO validé par l'IdP.
  const tenantId = await resolveTenantIdForUser(user.id)
  const role = await resolveRoleForUser(user.id, tenantId, user.role)
  const token = sessionManager.signSession(user.id, role, true, identity.providerId ?? "local", tenantId)

  return {
    pending: false,
    token,
    userId: user.id,
    role: user.role,
    identity,
  }
}