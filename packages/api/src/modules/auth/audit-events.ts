/**
 * Events d'audit émis par la couche d'authentification. Le subscriber
 * on-deploy-finished les journalise dans AuditLog (mêmes noms → action).
 *
 * Partage contractuel entre service.ts (émetteur) et on-deploy-finished.ts
 * (auditeur) : toute évolution des noms se fait ici, des deux côtés.
 */

export const AUTH_AUDIT_EVENTS = {
  loginSuccess: "auth.login.success",
  loginFailed: "auth.login.failed",
  mfaSuccess: "auth.mfa.success",
  mfaFailed: "auth.mfa.failed",
  passwordChanged: "auth.password.changed",
} as const

export type AuthAuditEvent = (typeof AUTH_AUDIT_EVENTS)[keyof typeof AUTH_AUDIT_EVENTS]