/**
 * Barrel public du module auth — point d'entrée unique (§14 du plan).
 * Tous les exports sont réexportés ici pour que les consommateurs puissent
 * importer depuis "./modules/auth" sans connaître l'arborescence interne.
 *
 * Chemins conservés pour compatibilité (tests existants) :
 *  - auth/service  → authService, AuthService, AuthError, AuthErrorCode
 *  - auth/rbac     → requireRole, currentUser, Role
 *  - auth/crypto   → encryptSecret, decryptSecret
 */

// Service (chemin conservé pour 10 fichiers de tests + websocket)
export { authService, AuthService, AuthError } from "./service"
export type { AuthErrorCode } from "./service"

// RBAC (chemin conservé pour 9 modules de routes)
export { requireRole, currentUser } from "./authorization/rbac"
export type { Role } from "./authorization/rbac"

// Routes
export { registerAuthGuard } from "./routes/guard"
export { registerAuthRoutes } from "./routes/auth.routes"
export { registerSsoRoutes } from "./routes/sso.routes"
export { registerSamlRoutes } from "./routes/saml.routes"
export { registerProvidersRoutes } from "./routes/providers.routes"
export { registerPendingRoutes } from "./routes/pending.routes"
export { registerSessionsRoutes } from "./routes/sessions.routes"
export { registerWebauthnRoutes } from "./routes/webauthn.routes"
export { registerLdapRoutes } from "./routes/ldap.routes"

// Provider registry
export { providerRegistry } from "./registry/provider-registry"
export { syncProviderSeedsToDb } from "./registry/provider-db"
