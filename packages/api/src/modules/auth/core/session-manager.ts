/**
 * SessionStore : abstraction des sessions (§9, §5.2 du plan).
 * Phase 2 : StatelessJwtStore — comportement actuel (JWT signé, audience cloisonnée).
 * Phase 5A : UserSessionStore (source de vérité = table UserSession + jti + révocation).
 *
 * Les audiences sont strictement séparées :
 * - AUD_SESSION  : seul type de token accepté par la garde /api/* et le handshake WS.
 * - AUD_MFA_PENDING : token court (5 min) de "pré-auth" MFA — JAMAIS accepté comme session.
 */

import jwt from "jsonwebtoken"
import { AuthError } from "../providers/types"

export interface SessionHandle {
  sub: string
  role: string
  mfaEnabled: boolean
}

export interface SessionStore {
  signSession(userId: string, role: string, mfaEnabled: boolean): string
  verifySession(token: string): SessionHandle
  signPending(userId: string): string
  verifyPending(token: string): { sub: string }
}

const AUD_SESSION = "session"
const AUD_MFA_PENDING = "mfa-pending"
const TOKEN_TTL = "12h"
const PENDING_TTL = "5m"

function secret(): string {
  return process.env.JWT_SECRET as string
}

/** SessionStore stateless, comportement identique à l'ancien AuthService JWT. */
export class StatelessJwtStore implements SessionStore {
  /** Token de session (audience "session"). */
  signSession(userId: string, role: string, mfaEnabled: boolean): string {
    return jwt.sign({ sub: userId, role, mfaEnabled }, secret(), {
      expiresIn: TOKEN_TTL,
      audience: AUD_SESSION,
    })
  }

  /** Vérifie un token de session : audience SESSION, rôle requis, mfa absent. */
  verifySession(token: string): SessionHandle {
    const decoded = jwt.verify(token, secret(), {
      audience: AUD_SESSION,
    }) as { sub?: string; role?: string; mfa?: string; mfaEnabled?: boolean }

    if (decoded.mfa || !decoded.role || !decoded.sub) {
      throw new Error("token de session invalide")
    }

    return {
      sub: decoded.sub,
      role: decoded.role,
      mfaEnabled: decoded.mfaEnabled ?? false,
    }
  }

  /** Token court de pré-auth MFA (audience "mfa-pending", TTL 5 min). */
  signPending(userId: string): string {
    return jwt.sign({ sub: userId, mfa: "pending" }, secret(), {
      expiresIn: PENDING_TTL,
      audience: AUD_MFA_PENDING,
    })
  }

  /**
   * Vérifie un pendingToken MFA : audience MFA_PENDING, claim mfa="pending".
   * Un token de session ou un token expiré échoue ici.
   */
  verifyPending(token: string): { sub: string } {
    let decoded: { sub?: string; mfa?: string }
    try {
      decoded = jwt.verify(token, secret(), {
        audience: AUD_MFA_PENDING,
      }) as { sub?: string; mfa?: string }
    } catch {
      throw new AuthError("mfa_token_invalid", "token MFA invalide", 401)
    }
    if (decoded.mfa !== "pending" || !decoded.sub) {
      throw new AuthError("mfa_token_invalid", "token MFA invalide", 401)
    }
    return { sub: decoded.sub }
  }
}

export const sessionManager: SessionStore = new StatelessJwtStore()
