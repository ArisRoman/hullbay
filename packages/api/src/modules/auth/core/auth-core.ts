/**
 * AuthCore : cœur métier auth, séparé de la façade AuthService (§13 du plan).
 * Orchestrates le provider local, l'identity mapping, le session-manager et le TOTP.
 * AuthService (service.ts) délègue à ces fonctions en conservant les signatures publiques.
 */

import { prisma } from "../../../lib/prisma"
import { eventBus } from "../../../lib/event-bus"
import { AUTH_AUDIT_EVENTS, type AuthAuditEvent } from "../audit-events"
import { AuthError } from "../providers/types"
import type { Role } from "../authorization/rbac"
import { hashPassword, verifyPassword } from "../providers/local/password"
import { providerRegistry } from "../registry/provider-registry"
import { sessionManager } from "./session-manager"
import { resolveIdentity } from "./identity-mapping"
import { startTotpEnrollment, verifyTotpCode } from "../mfa/totp"
import { ensureDefaultTenant } from "../identity/auth-identity.service"

// ── Trace helper (fire-and-forget) ──

function trace(event: AuthAuditEvent, data: Record<string, unknown>): void {
  void eventBus.emit(event, data).catch((err) => {
    if (process.env.NODE_ENV !== "test") {
      console.warn(`[auth] event ${event} non diffusé : ${err}`)
    }
  })
}

// ── Helpers internes ──

async function findLocalIdentityByUserId(userId: string) {
  return prisma.authIdentity.findFirst({
    where: { userId, kind: "local" },
  })
}

async function getUser(userId: string) {
  return prisma.user.findUniqueOrThrow({ where: { id: userId } })
}

// ── Opérations publiques ──

export async function createOwner(email: string, password: string) {
  const existing = await prisma.user.findFirst({ where: { role: "owner" } })
  if (existing) throw new Error("un compte owner existe déjà")

  const tenant = await ensureDefaultTenant()

  return prisma.$transaction(async () => {
    const user = await prisma.user.create({
      data: { email, role: "owner" },
    })

    await prisma.authIdentity.create({
      data: {
        userId: user.id,
        providerId: "local",
        kind: "local",
        issuer: null,
        subject: `local:${user.id}`,
        email,
        passwordHash: hashPassword(password),
        mfaEnabled: false,
      },
    })

    await prisma.membership.create({
      data: { userId: user.id, tenantId: tenant.id, role: "owner" },
    })

    return user
  })
}

export async function login(email: string, password: string) {
  const provider = providerRegistry.require("local")
  let result: Awaited<ReturnType<typeof provider.authenticate>>

  try {
    result = await provider.authenticate({ kind: "local", email, password })
  } catch (err) {
    if (err instanceof AuthError && err.code === "invalid_credentials") {
      trace(AUTH_AUDIT_EVENTS.loginFailed, { email })
      throw err
    }
    throw err
  }

  trace(AUTH_AUDIT_EVENTS.loginSuccess, { userId: result.userId, email: result.identity.email })

  if (result.mfaRequired) {
    return { mfaRequired: true as const, pendingToken: sessionManager.signPending(result.userId) }
  }

  return {
    mfaRequired: false as const,
    token: sessionManager.signSession(result.userId, result.role, false),
  }
}

export async function verifyMfa(pendingToken: string, code: string) {
  const { sub } = sessionManager.verifyPending(pendingToken)

  const identity = await findLocalIdentityByUserId(sub)
  if (!identity?.mfaSecretEnc) {
    throw new AuthError("mfa_not_configured", "MFA non configurée", 400)
  }

  const { decryptSecret } = await import("../secrets/secret-encryption-service")
  const secret = decryptSecret(identity.mfaSecretEnc)
  const valid = await verifyTotpCode(secret, code)

  if (!valid) {
    trace(AUTH_AUDIT_EVENTS.mfaFailed, { userId: sub })
    throw new AuthError("mfa_code_invalid", "code invalide", 401)
  }

  trace(AUTH_AUDIT_EVENTS.mfaSuccess, { userId: sub })

  const user = await getUser(sub)
  return { token: sessionManager.signSession(sub, user.role, true) }
}

export async function startMfaEnrollment(userId: string) {
  const user = await getUser(userId)
  const { otpauth, secret } = startTotpEnrollment("hullbay", user.email ?? userId)

  const { encryptSecret } = await import("../secrets/secret-encryption-service")
  const identity = await findLocalIdentityByUserId(userId)
  if (!identity) {
    throw new AuthError("mfa_not_configured", "identité locale introuvable", 400)
  }

  await prisma.authIdentity.update({
    where: { id: identity.id },
    data: { mfaSecretEnc: encryptSecret(secret) },
  })

  return { otpauth, secret }
}

export async function confirmMfaEnrollment(userId: string, code: string) {
  const identity = await findLocalIdentityByUserId(userId)
  if (!identity?.mfaSecretEnc) {
    throw new AuthError("mfa_enrollment_missing", "aucun enrôlement en cours", 400)
  }

  const { decryptSecret } = await import("../secrets/secret-encryption-service")
  const secret = decryptSecret(identity.mfaSecretEnc)
  const valid = await verifyTotpCode(secret, code)

  if (!valid) {
    throw new AuthError("mfa_code_invalid", "code invalide", 401)
  }

  await prisma.authIdentity.update({
    where: { id: identity.id },
    data: { mfaEnabled: true },
  })

  const user = await getUser(userId)
  return { ok: true, token: sessionManager.signSession(userId, user.role, true) }
}

export async function changePassword(userId: string, currentPassword: string, newPassword: string) {
  const identity = await findLocalIdentityByUserId(userId)
  if (!identity?.passwordHash) {
    throw new AuthError("password_incorrect", "identité locale introuvable", 400)
  }

  if (!verifyPassword(currentPassword, identity.passwordHash)) {
    throw new AuthError("password_incorrect", "mot de passe actuel incorrect", 400)
  }

  await prisma.authIdentity.update({
    where: { id: identity.id },
    data: { passwordHash: hashPassword(newPassword) },
  })

  trace(AUTH_AUDIT_EVENTS.passwordChanged, { userId })
  return { ok: true }
}

export async function countUsers(): Promise<number> {
  return prisma.user.count()
}

export async function listUsers() {
  const users = await prisma.user.findMany({ orderBy: { createdAt: "asc" } })

  // Batch : UNE requête pour toutes les identités locales au lieu d'un findFirst
  // par user (N+1 → O(1) queries ; évitait `limit` requêtes dans la boucle).
  const identities = await prisma.authIdentity.findMany({
    where: { userId: { in: users.map((u) => u.id) }, kind: "local" },
    select: { userId: true, mfaEnabled: true },
  })
  const byUserId = new Map(identities.map((i) => [i.userId, i.mfaEnabled]))

  return users.map((u) => ({
    id: u.id,
    email: u.email,
    role: u.role,
    mfaEnabled: byUserId.get(u.id) ?? false,
    createdAt: u.createdAt,
  }))
}

export async function createUser(email: string, password: string, role: "operator" | "viewer") {
  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) throw new Error("un compte avec cet email existe déjà")

  const tenant = await ensureDefaultTenant()
  // Même garantie d'atomicité que createOwner : user + identity + membership
  // sont créés dans UNE transaction (aucun user orphelin si une étape échoue).
  return prisma.$transaction(async (tx) => {
    const user = await tx.user.create({ data: { email, role } })
    await tx.authIdentity.create({
      data: {
        userId: user.id,
        providerId: "local",
        kind: "local",
        issuer: null,
        subject: `local:${user.id}`,
        email,
        passwordHash: hashPassword(password),
        mfaEnabled: false,
      },
    })
    await tx.membership.create({
      data: { userId: user.id, tenantId: tenant.id, role },
    })
    return { id: user.id, email: user.email, role: user.role }
  })
}

export async function setRole(userId: string, role: Role) {
  const user = await getUser(userId)
  if (user.role === "owner" && role !== "owner") {
    const owners = await prisma.user.count({ where: { role: "owner" } })
    if (owners <= 1) throw new Error("impossible de rétrograder le dernier owner")
  }

  const tenant = await ensureDefaultTenant()
  // Atomicité : user.role et membership.role changent ENSEMBLE ou pas du tout
  // (sinon un crash entre les deux writes laissait un état miroir incohérent).
  return prisma.$transaction(async () => {
    const u = await prisma.user.update({ where: { id: userId }, data: { role } })

    await prisma.membership.updateMany({
      where: { userId, tenantId: tenant.id },
      data: { role },
    })

    return { id: u.id, email: u.email, role: u.role }
  })
}

export async function deleteUser(userId: string, actingUserId: string) {
  if (userId === actingUserId) {
    throw new Error("impossible de supprimer son propre compte")
  }
  const user = await getUser(userId)
  if (user.role === "owner") {
    const owners = await prisma.user.count({ where: { role: "owner" } })
    if (owners <= 1) throw new Error("impossible de supprimer le dernier owner")
  }
  await prisma.user.delete({ where: { id: userId } })
  return { ok: true as const }
}

export function issueToken(userId: string, role: string, mfaEnabled: boolean): string {
  return sessionManager.signSession(userId, role, mfaEnabled)
}

export function verifyToken(token: string) {
  return sessionManager.verifySession(token)
}
