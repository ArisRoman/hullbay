import { prisma } from "../../../lib/prisma"
import { userSessionStore } from "./user-session.store"

/**
 * Liste les sessions actives d'un utilisateur. `currentJti` (jti du token qui
 * fait la requête) est marqué `current: true` pour que l'UI identifie l'appareil
 * courant et avertisse avant de le révoquer (sinon → logout immédiat).
 */
export async function listSessions(userId: string, currentJti?: string) {
  const sessions = await prisma.userSession.findMany({
    where: { userId, revokedAt: null },
    orderBy: { lastSeenAt: "desc" },
    select: { id: true, jti: true, providerId: true, createdAt: true, expiresAt: true, lastSeenAt: true, ip: true, userAgent: true },
  })
  return {
    sessions: sessions.map((s: { jti: string }) => ({ ...s, current: s.jti === currentJti })),
  }
}

/**
 * Révoque une session : invalide le cache mémoire (effet immédiat sur ce process)
 * ET écrit `revokedAt` en DB (source de vérité pour les autres process/restarts).
 */
export async function revokeSession(jti: string) {
  await userSessionStore.revoke(jti)
  return { revoked: true }
}

/**
 * Révoque TOUTES les sessions d'un utilisateur, sauf `notJti` éventuel
 * (jti de la session courante — permet « déconnecter tous les autres
 * appareils » sans se logout soi-même). Utilisée aussi par setRole (baisse)
 * et deleteUser pour réduire la fenêtre où un claim périmé reste accepté.
 */
export async function revokeUserSessions(userId: string, notJti?: string) {
  await userSessionStore.revokeUserSessions(userId, notJti)
  return { revoked: true }
}
