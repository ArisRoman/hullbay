/**
 * Provider local (authentification email + mot de passe).
 * Authenticate résout AuthIdentity(local) par email ; vérifie le hash scrypt.
 * Retourne une AuthResult enrichie (userId, role) pour la façade — ne leak pas
 * la structure interne en dehors du module auth.
 */

import { prisma } from "../../../../lib/prisma"
import { verifyPassword, DUMMY_HASH } from "./password"
import {
  AuthError,
  type AuthInput,
  type AuthProviderContract,
  type AuthResult,
  type ProviderPublicConfig,
} from "../types"

export class LocalProvider implements AuthProviderContract {
  readonly id: string
  readonly kind = "local" as const
  readonly enabled = true
  private readonly name = "Local"

  constructor(id: string) {
    this.id = id
  }

  getConfig(): ProviderPublicConfig {
    return {
      id: this.id,
      kind: this.kind,
      name: this.name,
      enabled: this.enabled,
    }
  }

  /**
   * Authentifie un compte local : résout l'identité par email, vérifie le hash,
   * met à jour lastLoginAt. Le timing est égalisé par DUMMY_HASH (voir password.ts).
   */
  async authenticate(input: AuthInput): Promise<AuthResult & { userId: string; role: string }> {
    if (!input.email || !input.password) {
      throw new AuthError("invalid_credentials", "identifiants invalides", 401)
    }

    const identity = await prisma.authIdentity.findFirst({
      where: { kind: "local", email: input.email },
      include: { user: { select: { id: true, role: true } } },
    })

    const valid = identity?.passwordHash
      ? verifyPassword(input.password, identity.passwordHash)
      : verifyPassword(input.password, DUMMY_HASH)

    if (!identity || !valid) {
      throw new AuthError("invalid_credentials", "identifiants invalides", 401)
    }

    // lastLoginAt : fire-and-forget, on n'échoue pas sur cette mise à jour
    void prisma.authIdentity
      .update({ where: { id: identity.id }, data: { lastLoginAt: new Date() } })
      .catch(() => {})

    return {
      identity: {
        providerId: identity.providerId,
        kind: "local",
        issuer: null,
        subject: identity.subject,
        email: identity.email,
      },
      mfaRequired: identity.mfaEnabled,
      userId: identity.userId,
      role: identity.user.role,
    }
  }
}
