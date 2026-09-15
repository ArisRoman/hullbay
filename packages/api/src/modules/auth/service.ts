/**
 * Façade AuthService — conserve les signatures publiques exactes pour compatibilité §2.
 * La logique métier a été déplacée dans core/auth-core.ts, providers/local,
 * session-manager et mfa/totp. Cette façade délègue tout en restant la surface
 * publique (imports des tests, websocket, routes).
 */

import * as authCore from "./core/auth-core"
import { sessionManager } from "./core/session-manager"
import type { Role } from "./authorization/rbac"

// Re-export des erreurs (compat : security.test.ts importe AuthError depuis "../service")
export { AuthError } from "./providers/types"
export type { AuthErrorCode } from "./providers/types"

export class AuthService {
  async createOwner(email: string, password: string) {
    return authCore.createOwner(email, password)
  }

  async login(email: string, password: string) {
    return authCore.login(email, password)
  }

  async verifyMfa(pendingToken: string, code: string) {
    return authCore.verifyMfa(pendingToken, code)
  }

  async startMfaEnrollment(userId: string) {
    return authCore.startMfaEnrollment(userId)
  }

  async confirmMfaEnrollment(userId: string, code: string) {
    return authCore.confirmMfaEnrollment(userId, code)
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    return authCore.changePassword(userId, currentPassword, newPassword)
  }

  async countUsers(): Promise<number> {
    return authCore.countUsers()
  }

  async listUsers() {
    return authCore.listUsers()
  }

  async createUser(email: string, password: string, role: "operator" | "viewer") {
    return authCore.createUser(email, password, role)
  }

  async setRole(userId: string, role: Role) {
    return authCore.setRole(userId, role)
  }

  async deleteUser(userId: string, actingUserId: string) {
    return authCore.deleteUser(userId, actingUserId)
  }

  issueToken(userId: string, role: string, mfaEnabled: boolean): string {
    return authCore.issueToken(userId, role, mfaEnabled)
  }

  verifyToken(token: string) {
    return authCore.verifyToken(token)
  }
}

export const authService = new AuthService()
