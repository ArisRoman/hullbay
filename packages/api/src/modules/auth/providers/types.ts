/**
 * Contrats partagés entre tous les providers et le cœur auth (§5.1 du plan).
 * Aucune dépendance Fastify ici : les callbacks reçoivent des types génériques
 * (FastifyRequest/FastifyReply au niveau impl).
 */

export type ProviderKind = "local" | "oidc" | "oauth2" | "saml" | "ldap"

export interface ExternalIdentity {
  providerId: string
  kind: ProviderKind
  issuer: string | null      // NULL pour local / ldap-bind
  subject: string            // identifiant stable : local:<id> / iss+sub / objectGUID…
  email?: string | null
  name?: string
  groups?: string[]
}

export interface AuthInput {
  kind: ProviderKind
  email?: string
  password?: string
  code?: string
  redirectUri?: string
  codeVerifier?: string
  samlResponse?: string
  relayState?: string
  ldapUsername?: string
  ldapPassword?: string
}

export interface AuthResult {
  identity: ExternalIdentity
  mfaRequired: boolean
  mfaPendingToken?: string
  // Résolution vers un User enregistré (POST mapping) : chaque provider doit
  // exposer le userId + rôle effectif pour le signing de session (§5.1 du plan).
  userId: string
  role: string
}

export interface ProviderPublicConfig {
  id: string
  kind: ProviderKind
  name: string
  enabled: boolean
}

export interface AuthProviderContract {
  id: string
  kind: ProviderKind
  enabled: boolean
  authenticate(input: AuthInput): Promise<AuthResult>
  initiateLogin?(req: unknown, reply: unknown): Promise<void>
  callback?(req: unknown, raw: unknown): Promise<ExternalIdentity>
  logout?(req: unknown): Promise<void>
  getConfig(): ProviderPublicConfig
}

// ── Erreurs d'authentification partagées (§10 du plan) ──

export type AuthErrorCode =
  | "invalid_credentials"
  | "mfa_token_invalid"
  | "mfa_code_invalid"
  | "mfa_not_configured"
  | "mfa_enrollment_missing"
  | "mfa_not_enabled"
  | "password_incorrect"
  | "identity_pending_approval"
  | "session_revoked"
  | "session_invalid"

export class AuthError extends Error {
  code: AuthErrorCode
  status: number

  constructor(code: AuthErrorCode, message: string, status = 400) {
    super(message)
    this.name = "AuthError"
    this.code = code
    this.status = status
  }
}
