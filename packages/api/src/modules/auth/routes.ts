/**
 * Barrel de compat — les routes ont été décomposées en routes/guard.ts,
 * routes/auth.routes.ts et routes/users.routes.ts. Ce fichier conserve le chemin
 * d'import `../auth/routes` utilisé par auth.test.ts (non-régression) : les
 * tests existants restent verts sans modification.
 */

export { registerAuthGuard } from "./routes/guard"
export { registerAuthRoutes } from "./routes/auth.routes"