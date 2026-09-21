/**
 * Facteur WebAuthn / Passkeys 
 * Rattaché directement à l'AuthIdentity locale — jamais un AuthProvider.
 *
 * Fournit l'enrôlement (registration) et la vérification (authentication)
 * de clés de sécurité matérielles (FIDO2 / TouchID / YubiKey / Passkeys).
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server"
import type { Prisma } from "@prisma/client"
import { prisma } from "../../../lib/prisma"
import { eventBus } from "../../../lib/event-bus"
import { AuthError } from "../providers/types"
import { AUTH_AUDIT_EVENTS } from "../audit-events"

/**
 * Relations chargées pour toute résolution de facteur : l'utilisateur (libellés
 * de la cérémonie) et ses passkeys rattachées. Jamais renvoyées telles quelles
 * au client — l'API ne sérialise que les champs publics.
 */
const FACTOR_INCLUDE = {
  user: { select: { id: true, email: true, name: true } },
  webauthnCredentials: true,
} satisfies Prisma.AuthIdentityInclude

/**
 * Résout l'identité porteuse des passkeys : priorité à l'identité locale
 * (facteurs historiques), puis à défaut la première identité de l'utilisateur
 * (LDAP/OIDC/SAML). Les passkeys restent rattachées à l'AuthIdentity, jamais au
 * provider — mais un compte externe doit pouvoir en enrôler/utiliser.
 */
async function findFactorIdentity(userId: string) {
  return (
    (await prisma.authIdentity.findFirst({
      where: { userId, kind: "local" },
      include: FACTOR_INCLUDE,
    })) ??
    (await prisma.authIdentity.findFirst({
      where: { userId },
      orderBy: { createdAt: "asc" },
      include: FACTOR_INCLUDE,
    }))
  )
}

// ── Configuration du Relying Party (RP) ──

export function getWebauthnConfig(clientOrigin?: string) {
  const rpName = process.env.WEBAUTHN_RP_NAME || "Hullbay"
  const envRpId = process.env.WEBAUTHN_RP_ID
  const envOrigin = process.env.WEBAUTHN_ORIGIN

  let rpID = envRpId
  let origin = envOrigin

  // Fail-closed : sans WEBAUTHN_ORIGIN, le fallback localhost produirait des
  // cérémonies invalides (et silencieusement non sécurisées). On ne l'autorise
  // que pour un environnement explicitement de développement ou de test — une
  // prod où NODE_ENV est absent/non standard ne doit PAS retomber en mode dev.
  const env = process.env.NODE_ENV
  if (!envOrigin && env !== "development" && env !== "test") {
    throw new AuthError(
      "webauthn_not_configured",
      "WEBAUTHN_ORIGIN doit être configuré (hors développement/test)",
      500,
    )
  }

  // En production avec WEBAUTHN_ORIGIN explicite, on n'autorise QUE l'origine configurée
  if (envOrigin) {
    return {
      rpName,
      rpID: rpID || new URL(envOrigin).hostname,
      origin: envOrigin,
      allowedOrigins: [envOrigin],
    }
  }

  // En développement local : n'accepte clientOrigin que s'il s'agit d'un hostname local
  if (clientOrigin) {
    try {
      const parsed = new URL(clientOrigin)
      if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1") {
        origin = clientOrigin
        rpID = parsed.hostname
      }
    } catch {
      // Ignorer origin invalide
    }
  }

  if (!origin) {
    origin = "http://localhost:5273"
  }
  if (!rpID) {
    rpID = "localhost"
  }

  const allowedOrigins = Array.from(
    new Set([
      origin,
      "http://localhost:5273",
      "http://localhost:3000",
      "http://127.0.0.1:5273",
      "http://127.0.0.1:3000",
    ]),
  )

  return { rpName, rpID, origin, allowedOrigins }
}

/**
 * Clé de challenge : isolée par token (session/pending) pour éviter qu'une
 * nouvelle cérémonie écrase celle d'une autre requête en cours (self-DoS /
 * TOCTOU) et pour rester stable quand plusieurs instances partagent le store.
 * Sans discriminant (appel direct/tests), on retombe sur la clé par utilisateur.
 */
function challengeStoreKey(prefix: string, userId: string, challengeKey?: string): string {
  return challengeKey ? `${prefix}:${userId}:${challengeKey}` : `${prefix}:${userId}`
}

function parseTransports(raw?: string | null): any | undefined {
  if (!raw) return undefined
  try {
    return JSON.parse(raw)
  } catch {
    return undefined
  }
}

// ── Store temporaire de challenges en mémoire bornée ──
//
// CONTRAINTE DE DÉPLOIEMENT : process-local. En multi-instance, un
// challenge émis sur A n'est pas vérifiable sur B (assertion WebAuthn rejetée).
// Single-instance ou affinité sticky requis pour les cérémonies WebAuthn.

interface StoredChallenge {
  challenge: string
  expiresAt: number
}

class WebauthnChallengeStore {
  private readonly challenges = new Map<string, StoredChallenge>()
  private readonly maxEntries = 512

  set(key: string, challenge: string, ttlMs = 300_000): void {
    this.purge()
    if (this.challenges.size >= this.maxEntries) {
      const oldestKey = this.challenges.keys().next().value
      if (oldestKey) this.challenges.delete(oldestKey)
    }
    this.challenges.set(key, {
      challenge,
      expiresAt: Date.now() + ttlMs,
    })
  }

  getAndConsume(key: string): string | null {
    const entry = this.challenges.get(key)
    if (!entry) return null
    this.challenges.delete(key)
    if (Date.now() > entry.expiresAt) return null
    return entry.challenge
  }

  private purge(): void {
    const now = Date.now()
    for (const [k, v] of this.challenges.entries()) {
      if (now > v.expiresAt) {
        this.challenges.delete(k)
      }
    }
  }

  clear(): void {
    this.challenges.clear()
  }
}

export const webauthnChallengeStore = new WebauthnChallengeStore()

// ── Enrôlement WebAuthn (Registration) ──

export async function generateWebauthnRegistrationOptions(
  userId: string,
  clientOrigin?: string,
  challengeKey?: string,
) {
  const identity = await findFactorIdentity(userId)

  if (!identity) {
    throw new AuthError("mfa_not_configured", "identité introuvable", 400)
  }

  const { rpName, rpID } = getWebauthnConfig(clientOrigin)

  const excludeCredentials = identity.webauthnCredentials.map((c) => ({
    id: c.credentialId,
    transports: parseTransports(c.transports),
  }))

  const userEmail = identity.email || identity.user.email || `${userId}@hullbay.local`
  const userName = identity.user.name || userEmail

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: new Uint8Array(Buffer.from(userId)),
    userName: userEmail,
    userDisplayName: userName,
    attestationType: "none",
    excludeCredentials,
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
    },
  })

  webauthnChallengeStore.set(challengeStoreKey("reg", userId, challengeKey), options.challenge)

  return options
}

export async function verifyWebauthnRegistration(
  userId: string,
  body: { response: RegistrationResponseJSON; name?: string },
  clientOrigin?: string,
  challengeKey?: string,
) {
  const expectedChallenge = webauthnChallengeStore.getAndConsume(
    challengeStoreKey("reg", userId, challengeKey),
  )
  if (!expectedChallenge) {
    throw new AuthError("mfa_token_invalid", "Challenge expiré ou invalide", 400)
  }

  const identity = await findFactorIdentity(userId)

  if (!identity) {
    throw new AuthError("mfa_not_configured", "identité introuvable", 400)
  }

  const { rpID, allowedOrigins } = getWebauthnConfig(clientOrigin)

  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge,
      expectedOrigin: allowedOrigins,
      expectedRPID: rpID,
      requireUserVerification: true,
    })
  } catch (err) {
    // Détail (RP ID/origine attendus, etc.) loggé côté serveur uniquement.
    void eventBus.emit(AUTH_AUDIT_EVENTS.mfaFailed, { userId, factor: "webauthn", step: "registration" }).catch(() => {})
    if (err instanceof Error) console.error("[webauthn] registration verification failed:", err.message)
    throw new AuthError("mfa_code_invalid", "vérification de la clé de sécurité échouée", 400)
  }

  const { verified, registrationInfo } = verification

  if (!verified || !registrationInfo) {
    throw new AuthError("mfa_code_invalid", "vérification de la clé de sécurité échouée", 400)
  }

  const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo

  // Persiste le credential et active la MFA
  const cred = await prisma.$transaction(async (tx) => {
    const created = await tx.webauthnCredential.create({
      data: {
        identityId: identity.id,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey),
        counter: BigInt(credential.counter),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: credential.transports ? JSON.stringify(credential.transports) : null,
        name: body.name || "Security Key",
      },
    })

    if (!identity.mfaEnabled) {
      await tx.authIdentity.update({
        where: { id: identity.id },
        data: { mfaEnabled: true },
      })
    }

    return created
  })

  void eventBus.emit(AUTH_AUDIT_EVENTS.mfaEnabled, { userId, factor: "webauthn" }).catch(() => {})
  void eventBus.emit(AUTH_AUDIT_EVENTS.webauthnRegistered, { userId, credentialId: cred.id, name: cred.name }).catch(() => {})

  return { verified: true, credentialId: cred.id }
}

// ── Authentification WebAuthn ──

export async function generateWebauthnAuthenticationOptions(
  userId: string,
  clientOrigin?: string,
  challengeKey?: string,
) {
  const identity = await findFactorIdentity(userId)

  if (!identity || identity.webauthnCredentials.length === 0) {
    throw new AuthError("mfa_not_configured", "aucune clé WebAuthn enregistrée pour ce compte", 400)
  }

  const { rpID } = getWebauthnConfig(clientOrigin)

  const allowCredentials = identity.webauthnCredentials.map((c) => ({
    id: c.credentialId,
    transports: parseTransports(c.transports),
  }))

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: "required",
  })

  webauthnChallengeStore.set(challengeStoreKey("auth", userId, challengeKey), options.challenge)

  return options
}

export async function verifyWebauthnAuthentication(
  userId: string,
  body: { response: AuthenticationResponseJSON },
  clientOrigin?: string,
  challengeKey?: string,
) {
  const expectedChallenge = webauthnChallengeStore.getAndConsume(
    challengeStoreKey("auth", userId, challengeKey),
  )
  if (!expectedChallenge) {
    throw new AuthError("mfa_token_invalid", "Challenge expiré ou invalide", 400)
  }

  const identity = await findFactorIdentity(userId)

  if (!identity) {
    throw new AuthError("mfa_not_configured", "identité introuvable", 400)
  }

  const credentialRow = identity.webauthnCredentials.find(
    (c) => c.credentialId === body.response.id,
  )

  if (!credentialRow) {
    throw new AuthError("mfa_code_invalid", "clé de sécurité inconnue pour ce compte", 400)
  }

  const { rpID, allowedOrigins } = getWebauthnConfig(clientOrigin)

  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge,
      expectedOrigin: allowedOrigins,
      expectedRPID: rpID,
      credential: {
        id: credentialRow.credentialId,
        publicKey: new Uint8Array(credentialRow.publicKey),
        counter: Number(credentialRow.counter),
        transports: parseTransports(credentialRow.transports),
      },
      requireUserVerification: true,
    })
  } catch (err) {
    void eventBus.emit(AUTH_AUDIT_EVENTS.mfaFailed, { userId, factor: "webauthn" }).catch(() => {})
    if (err instanceof Error) console.error("[webauthn] authentication verification failed:", err.message)
    throw new AuthError("mfa_code_invalid", "vérification de la clé de sécurité échouée", 400)
  }

  if (!verification.verified) {
    void eventBus.emit(AUTH_AUDIT_EVENTS.mfaFailed, { userId, factor: "webauthn" }).catch(() => {})
    throw new AuthError("mfa_code_invalid", "vérification de la clé de sécurité échouée", 400)
  }

  // Garde : un compteur non strictement croissant signale une copie du
  // credential ou une réinitialisation (rejeu). On refuse — sans jamais
  // persister le nouveau compteur — pour empêcher que la copie devienne la
  // référence officielle.
  if (Number(verification.authenticationInfo.newCounter) <= Number(credentialRow.counter)) {
    void eventBus.emit(AUTH_AUDIT_EVENTS.mfaFailed, { userId, factor: "webauthn", reason: "counter_replay" }).catch(() => {})
    throw new AuthError("mfa_code_invalid", "clé de sécurité compromise ou rejouée", 401)
  }

  // Met à jour le compteur et la date de dernière utilisation
  await prisma.webauthnCredential.update({
    where: { id: credentialRow.id },
    data: {
      counter: BigInt(verification.authenticationInfo.newCounter),
      lastUsedAt: new Date(),
    },
  })

  void eventBus.emit(AUTH_AUDIT_EVENTS.mfaSuccess, { userId, factor: "webauthn" }).catch(() => {})

  return { verified: true }
}

// ── Gestion des Credentials ──

export async function listUserWebauthnCredentials(userId: string) {
  // Selects publics uniquement (jamais publicKey/counter vers le client).
  const listArgs = {
    include: {
      webauthnCredentials: {
        select: {
          id: true,
          credentialId: true,
          name: true,
          deviceType: true,
          createdAt: true,
          lastUsedAt: true,
        },
        orderBy: { createdAt: "desc" as const },
      },
    },
  }
  const identity =
    (await prisma.authIdentity.findFirst({
      where: { userId, kind: "local" },
      ...listArgs,
    })) ??
    (await prisma.authIdentity.findFirst({
      where: { userId },
      ...listArgs,
    }))

  return identity?.webauthnCredentials ?? []
}

export async function deleteUserWebauthnCredential(userId: string, credentialId: string) {
  const identity = await findFactorIdentity(userId)

  if (!identity) {
    throw new AuthError("mfa_not_configured", "identité introuvable", 404)
  }

  const target = identity.webauthnCredentials.find((c) => c.id === credentialId)
  if (!target) {
    throw new AuthError("mfa_not_configured", "clé de sécurité introuvable", 404)
  }

  await prisma.webauthnCredential.delete({
    where: { id: credentialId },
  })

  // S'il n'y a plus de credentials WebAuthn et pas de secret TOTP, on désactive mfaEnabled
  const remaining = identity.webauthnCredentials.filter((c) => c.id !== credentialId)
  if (remaining.length === 0 && !identity.mfaSecretEnc) {
    await prisma.authIdentity.update({
      where: { id: identity.id },
      data: { mfaEnabled: false },
    })
  }

  void eventBus.emit(AUTH_AUDIT_EVENTS.webauthnDeleted, { userId, credentialId: target.id, name: target.name }).catch(() => {})

  return { ok: true }
}
