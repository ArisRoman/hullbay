/**
 * Shim de réexport — conserve le chemin d'import `../auth/rbac` pour les 9 modules
 * existants (servers, settings, clusters, reconciler, projects, registry, secrets,
 * observability, updates) — implémentation réelle dans authorization/rbac.ts.
 */

export type { Role } from "./authorization/rbac"
export { requireRole, currentUser } from "./authorization/rbac"
