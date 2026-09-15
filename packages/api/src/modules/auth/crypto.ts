/**
 * Shim de réexport — conserve le chemin d'import `../auth/crypto` pour :
 *  - registry/service.ts
 *  - lib/keys.ts
 *  - lib/ssh-tunnel.ts
 *  - workflows/provision-server.ts
 *  - workflows/cluster-anchor.ts
 *  - lib/__tests__/ssh-tunnel.test.ts (mock)
 *
 * L'implémentation réelle est dans secrets/secret-encryption-service.ts (§8 du plan).
 * La façade encryptSecret/decryptSecret délègue au scope "mfa" pour compatibilité.
 */

export { encryptSecret, decryptSecret } from "./secrets/secret-encryption-service"
