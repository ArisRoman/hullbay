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

    // Lookup insensible à la casse : cohérent avec la clé de rate-limit
    // (elle-même lowercodée) et évite le contournement par rotation de casse
    // (User@X vs user@x sur le même compte).
    const identity = await prisma.authIdentity.findFirst({
      where: { kind: "local", email: { equals: input.email.trim(), mode: "insensitive" } },
      include: { user: { select: { id: true, role: true } } },
    })

    const valid = identity?.passwordHash
      ? verifyPassword(input.password, identity.passwordHash)
      : verifyPassword(input.password, DUMMY_HASH)

    if (!identity || !valid) {
      // userId renseigné uniquement si le compte existe (audit corrélé), sans
      // changer la réponse renvoyée au client (anti-énumération).
      const err = new AuthError("invalid_credentials", "identifiants invalides", 401)
      if (identity) err.userId = identity.userId
      throw err
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
