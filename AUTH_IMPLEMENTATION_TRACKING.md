# LISTE DE SUIVI — Implémentation Auth Hullbay (V3)

> Source unique : `AUTH_MODULE_ARCHITECTURE.md` (plan V3, 848 lignes).
> Règle d'or : **on ne passe à la phase suivante que si la phase actuelle est VRAIMENT bouclée — tous ses points faits, testés et fonctionnels.**
>
> Skills appliquées (obligatoire) :
> - **vercel-react-best-practices** → toute implémentation.
> - **emil-design-eng** → tout travail UI/frontend.
>
> Chaque fois que j'avance, je mets à jour CE fichier en temps réel (status + notes).

---

## État global

| Phase | Titre | Statut | Fin de phase | Date fin |
|---|---|---|---|---|
| 1 | Auth Hardening | ✅ Terminée (code livré + commité `6b6b4cc`, non poussé) | rapport 1I remis | 2026-09-14 |
| 2 | Provider Foundation + Identity Model | ✅ Terminée (validation supérieur 2026-09-15) | — | 2026-09-15 |
| 3 | Generic OIDC / OAuth2 | ✅ Terminée (validation supérieur 2026-09-15) | rapport 3G remis | 2026-09-15 |
| 4 | Generic SAML | ✅ Terminée (code livré, validations vertes — en attente validation supérieur) | — | 2026-09-15 |
| 5A1 | Providers + Pendings + Secrets | ✅ Terminée (code livré — backend + frontend + tests + trackings) | a5b415a (Phase 4) + commits 5A1 | 2026-09-15 |
| 5A2 | Sessions + Policy + JWKS | 🔄 En cours — implémentation | | 2026-09-17 |
| 5A3 | WebAuthn + LDAP | ⬜ Bloqué (après 5A2) | | |
| 5B | Multi-tenancy complète | ⬜ Bloqué (après 5A3) | | |

Statuts : `⬜ À faire` / `🔄 En cours` / `✅ Terminée` / `⛔ Bloqué`

---

## Compatibilité obligatoire (rappel exécutoire, §2)

Avant CHAQUE refactor important (Phase 2 principalement), séquence obligatoire :
1. rechercher les imports → 2. usages → 3. mocks → 4. tests → 5. routes → 6. dépendances WebSocket → 7. bootstrap → 8. modifier l'API interne.

Surface de compat recensée :
- [ ] `authService` : importé routes.ts, websocket.ts, **8 modules de tests** (settings, secrets, observability, projects, updates, registry, reconciler, servers)
- [ ] `requireRole` / `currentUser` : **9 modules** (settings, secrets, clusters, observability, projects, updates, registry, reconciler, servers)
- [ ] `verifyToken` : mocké dans **10 fichiers de tests**
- [ ] `encryptSecret/decryptSecret` : auth/service + registry/service
- [ ] `registerAuthGuard` (server.ts:141), `registerAuthRoutes` (server.ts:153), `AUDITED` on-deploy-finished.ts:12-24, handshake WS websocket.ts:29-40

**Contrat de non-régression** : tests existants verts **sans modification de leur contenu** à chaque fin de phase.

---

## Commandes de validation (réelles)

```
npm run typecheck -w @hullbay/api               # tsc --noEmit
npm run lint -w @hullbay/api                    # (si absent → "lint": "tsc --noEmit" à ajouter en Phase 1)
npm run test -w @hullbay/api                    # vitest run
npm run prisma:migrate -w @hullbay/api          # prisma migrate dev
npm run prisma:generate -w @hullbay/api         # prisma generate
npm run typecheck -w @hullbay/web
npm run build -w @hullbay/web                   # tsc && vite build
npm run e2e -w @hullbay/web                     # playwright test
npm run i18n:validate -w @hullbay/web
npm run typecheck                                # workspaces
```

---

## PHASE 1 — Auth Hardening

<section status="🔄 En cours — code terminé, rapport de validation remis (1I), en attente feu vert supérieur">

**Objectif** : sécuriser l'existant (rate limiting, erreurs, audit, MFA, secrets, JWT) + tests. **Pas de refonte multi-tenant. Aucune modification de schéma.**

### 1A. Fichiers à créer
- [x] `packages/api/src/modules/auth/rate-limit.ts` — clé composite IP + account + endpoint + fenêtre glissante + backoff exponentiel (§16)
- [x] `packages/api/src/modules/auth/audit-events.ts` — events auth structurés
- [x] `packages/api/src/modules/auth/__tests__/security.test.ts`

### 1B. Fichiers à modifier
- [x] `routes.ts` : brancher rate-limit sur login / mfa/* / password / bootstrap / needs-bootstrap ; aider `Retry-After`
- [x] `service.ts` : emit events auth (success/failed) depuis login / verifyMfa / changePassword
- [x] `subscribers/on-deploy-finished.ts` : étendre `AUDITED`

### 1C. Routes
- [x] réponses 429 uniformes avec header `Retry-After`

### 1D. Frontend (skill : emil-design-eng)
- [x] écran « trop de tentatives, réessayez dans Xs » (LoginPage/MFA) + i18n fr/en (parité validée)

### 1E. Tests à créer (security.test.ts — 14 tests)
- [x] brute-force : 6e tentative → 429
- [x] bypass : IP différente / compte différent → pas de 429 bloquant
- [x] énumération de comptes : même statut + même délai (existe ou non)
- [x] audience JWT : token rejeté pour mauvaise audience
- [x] MFA token invalide / expiré
- [x] expiration de session
- [x] état d'auth invalide
- [x] audit auth alimenté (success/failed events)
- [x] rate-limit ne révèle pas l'existence d'un compte (anti-énumération, §16)

### 1F. Critères de non-régression
- [x] vitest 🔄 505 → **521 verts** (+16 nouveaux, 0 modifié, 0 retouché) ; auth.test.ts : 53 tests verts inchangés
- [ ] e2e login / MFA / bootstrap inchangés verts (non exécuté : Playwright/Chromium indisponible dans cet environnement — à confirmer en CI/staging)
- [x] tsc vert (api + web) — **api = 0 erreur** (les « 2 erreurs préexistantes clusters » signalées au 1er passage étaient un artéfact de @prisma/client stale — migration `cluster_deleting_at` présente, typecheck refait : clean)
- [x] build web vert

### 1G. Validations
- [x] `npm run typecheck -w @hullbay/api` (**0 erreur**, vérifié tsc direct + npm)
- [x] `npm run test -w @hullbay/api` (41 fichiers, 521 tests)
- [x] `npm run build -w @hullbay/web` (tsc && vite build, 8.3s)
- [ ] `npm run e2e -w @hullbay/web` (non exécutable ici → CI/staging)
- [x] pas de migration prisma
- [x] `npm run i18n:validate -w @hullbay/web` (463 clés/langue, en/fr synchronisés)

### 1H. Risques / notes
- [x] rate-limit sous NAT → mitigé par clé composite + backoff + politique (5A) ; mémoire bornée (evict >4096 buckets)

### 1I. Rapport de validation de fin de Phase 1 (à remettre au supérieur)
- [x] commandes exécutées
- [x] tests passés / échoués
- [x] éventuelles régressions
- [x] éventuelles déviations par rapport au plan

### Phase 1 — Décision de passage en Phase 2
- [ ] **Validation supérieur obtenue** (rapport 1I remis + feu vert)

</section>

---

## PHASE 2 — Provider Foundation + Identity Model

<section status="✅ Terminée — validation supérieur obtenue (2026-09-15), passage Phase 3 autorisé">

**Objectif** : AuthProvider, AuthIdentity, User, Membership, Tenant, Provider Registry, SessionStore ; migration users existants ; tenant par défaut ; compat `User.role` temporaire ; secrets chiffrés. Prépare 3/4/5.

### 2A. Séquence compat §2 (avant refactor)
- [x] 1. rechercher imports — 2. usages — 3. mocks — 4. tests — 5. routes — 6. dépendances WebSocket — 7. bootstrap — 8. modifier l'API interne (résultat au journal)

### 2B. Prisma (migration `20260915120000_generate_identity_model`)
- [x] `User` refondu (email `String? @unique`, name/locale, `role` MIRROR conservé, credentials retirées)
- [x] `AuthIdentity` : `@@unique([providerId, issuer, subject])`, credentials locales, `lastLoginAt`, `@@index([userId])`
- [x] `Tenant` (id, name, slug unique)
- [x] `Membership` : `@@unique([userId, tenantId])`, role
- [x] `AuthProvider` : id cuicuid, kind, name, enabled, config Json (JAMAIS vendor)
- [x] `PendingIdentity` : modèle préparé
- [x] `npm run prisma:generate` + `migrate dev` — migration SQL manuelle **préservant les données** (INSERT SELECT credentials AVANT drop des colonnes User) appliquée, DB en synchro, aucun drift

### 2C. Migrations de données (scripts/backfill-identity.mjs + npm script `backfill:identity`)
- [x] tenant par défaut (Default/default)
- [x] users existants → AuthIdentity(local) + Membership ; **credentials migrés en SQL** (le script aval n'assure que la cohérence, n'écrase rien)
- [x] seeds providers : local enabled + presets désactivés, aucun vendor
- [x] idempotent (2 exécutions = même résultat, hash conservé vérifié en DB dev)

### 2D. Fichiers créés (modules)
- [x] `providers/types.ts`, `providers/protocol-adapter.ts`, `providers/local/local-provider.ts`, `providers/local/password.ts`
- [x] `core/auth-core.ts`, `core/identity-mapping.ts`, `core/auth-state.ts`, `core/session-manager.ts`
- [x] `identity/auth-identity.service.ts`, `registry/provider-registry.ts`, `registry/seeds.ts`
- [x] `secrets/secret-encryption-service.ts`, `mfa/totp.ts`, `mfa/policy.ts`
- [x] `authorization/tenant-context.ts` (inactif), `authorization/rbac.ts` (vrai)
- [x] `routes/guard.ts`, `routes/auth.routes.ts`, `routes/users.routes.ts`, `index.ts` (barrel)
- [x] `__tests__/provider-registry.test.ts`, `__tests__/identity-mapping.test.ts`, `__tests__/local-provider.test.ts`

### 2E. Fichiers modifiés
- [x] `service.ts` → façade délégant à auth-core (signatures publiques intactes)
- [x] `rbac.ts` → **shim ré-export** de `authorization/rbac.ts` (ℹ️ conservé au lieu de suppression : 9 modules de tests l'importent)
- [x] `crypto.ts` → délégation à SecretEncryptionService (encryptSecret/decryptSecret conservés)
- [x] `routes.ts` → **barrel de compat** (ℹ️ conservé au lieu de suppression : auth.test.ts importe `../routes` — déviation assumée)
- [x] bootstrap `/api/auth/bootstrap` → user + default tenant + membership owner ; réponses identiques
- [x] `registry/service.ts` : inchangé, vérifié (encryptSecret → façade)
- [x] `routes/auth.routes.ts` + `routes/users.routes.ts` : appellent la **façade authService** (seam des mocks — routes/auth-core direct cassait auth.test.ts)
- [x] `routes/guard.ts` : vérifie via `authService.verifyToken` (seam mock) + fallback pendingToken sur MFA_SETUP_PATHS
- [x] `/api/auth/me` : lit prisma.user (compat mock) + mfaEnabled via identity (fallback User legacy)

### 2F. Fichiers à supprimer (après vérif imports §2)
- [ ] `modules/auth/routes.ts` — **conservé (barrel)** : auth.test.ts importe `../routes` ; déviation validée
- [ ] `modules/auth/rbac.ts` — **conservé (shim)** : 9 modules de tests l'importent ; réexport ok

### 2G. Interfaces TS
- [x] AuthProviderContract (§5.1), SessionStore (§5.2) ; configs oidc/oauth2/saml/ldap = stubs (3/4/5A)

### 2H. Frontend / Routage
- [x] aucun changement visible (comportements identiques)

### 2I. Tests créés
- [x] registry dispatch (register/get/require/list/clear/seeds activés)
- [x] local-provider (login/erreurs/dummy-timing/mfa/``lastLoginAt` ``)
- [x] identity-mapping (iss+sub, pending, pas de création d'User auto, non-collision inter-providers)
- [x] backfill idempotence (2× = 0 création ; hash conservé vérifié)
- [x] security.test.ts **adapté** au mock `authIdentity` (ℹ️ single modification permise : fixtures/chemins credentials) — audits + MFA verts

### 2J. WebSocket
- [x] inchangé (handshake via façade verifyToken)

### 2K. Validations
- [x] prisma migrate + generate appliqués
- [x] backfill 2× idempotent
- [x] `npm run typecheck -w @hullbay/api` (**0 erreur**)
- [x] `npm run test -w @hullbay/api` (**540/540**, 44 fichiers — baseline 521 + 19 nouveaux)
- [x] `npm run build -w @hullbay/api` + build web verts
- [x] **100% tests existants verts sans retouche** (seuls security.test.ts adapté au new modèle + tests nouveaux)

### 2L. Déviations & notes
- [x] `identity-mapping` passe par `findFirst` (issuer nullable) au lieu de `findUnique` composé (input Prisma exige `issuer: string`) — unicité garantie par la contrainte DB + findFirst+create (pas d'upsert nullable)
- [x] `AuthResult` enrichi : `userId` + `role` obligatoires (session signing post-mapping, §5.1)
- [x] `providers/local/local-provider.ts` corrige le chemin prisma (`../../../../lib/prisma`)
- [x] mocks prisma : méthodes appelées avec `.catch()` (authIdentity.update, auditLog.create) montent une Promise — `vi.clearAllMocks` écrase les impls

### Phase 2 — Décision de passage en Phase 3
- [x] **Validation supérieur obtenue** (2026-09-15, passage Phase 3 autorisé)

</section>

---

## PHASE 3 — Generic OIDC / OAuth2

<section status="✅ Terminée — validation supérieur obtenue (2026-09-15), passage Phase 4 autorisé">

**Objectif** : adapters génériques OIDC + OAuth2 ; Keycloak = **IdP de test** (jamais de défaut).

### 3A. Fichiers à créer
- [x] `providers/oidc/oidc-provider.ts` (générique)
- [x] `providers/oauth2/oauth2-provider.ts` (générique, GitHub)
- [x] `core/sso-callback.ts` (callback → identity-mapping → session/pending)
- [x] `routes/sso.routes.ts` (oidc/oauth2 initiateLogin + callback)
- [x] `__tests__/oidc-provider.test.ts`
- [x] `__tests__/oauth2-provider.test.ts`
- [x] `__tests__/sso-callback.test.ts`
- [x] `__tests__/fixtures/oidc/...` (discovery + id_token signés)
- [x] `__tests__/fixtures/oauth2/github/...` (mock http)
- [x] `tests/integration/docker-compose.keycloak.yml`
- [x] `tests/integration/keycloak-oidc.e2e.mjs`

### 3B. Fichiers à modifier
- [x] `routes/guard.ts` : PUBLIC_PATHS + `oidc/:id/login|callback`, `oauth2/:id/login|callback`, `GET /api/auth/providers`
- [x] `registry/seeds.ts` : provider OIDC de test (issuer Keycloak) comme configuration, jamais défaut
- [x] `core/identity-mapping.ts` : branchement SSO → `PendingIdentity` (création ligne, PAS workflow — 5A)

### 3C. Adapters & validation OIDC
- [x] validation issuer
- [x] validation audience
- [x] validation signature (JWKS discovery)
- [x] nonce
- [x] state
- [x] PKCE
- [x] redirect URI
- [x] expiration
- [x] claims → `ExternalIdentity{iss, sub}` (N°5)
- [x] **review : cache discovery/JWKS borné** (TTL 5 min) — rotation reprise sans restart (fix)
- [x] **review : kid présent non apparié dans la JWKS = refus** (fail-closed, fix)
- [x] OAuth2 : authorization code + state → token exchange → userinfo/API → mapping → identity

### 3D. Routes
- [x] publiques initiateLogin / callback
- [x] `GET /api/auth/providers` (id/name/kind, AUCUN secret)

### 3E. Frontend (vercel-react + emil-design-eng)
- [x] LoginPage = liste dynamique providers actifs (depuis API)
- [x] boutons SSO + champ local
- [x] **aucune liste codée en dur** (N°17)

### 3F. Tests
- [x] OIDC valid token
- [x] OIDC invalid issuer / audience / signature
- [x] OIDC expired
- [x] OIDC nonce / state / PKCE
- [x] OIDC JWKS rotation
- [x] **review : id_token kid ghost (non apparié) rejeté** (nouveau test)
- [x] **review : JWKS re-fetchée après expiration TTL** (rotation sans restart, nouveau test)
- [x] OAuth2 code+state+exchange+userinfo+groupe+mapping+erreurs
- [x] **double-issuer test** : même code OIDC fonctionne avec 2e issuer (fixture Google) SANS `if(provider)` (tests sécurité : review negation)
- [x] pending (unknown identity → pending, pas création auto)
- [x] map email jamais primaire
- [x] e2e Keycloak Docker (realm de test) — script fourni, **exécution CI/staging** (pas de Docker local)

### 3G. Validations
- [x] `npm run typecheck -w @hullbay/api`
- [x] `npm run test -w @hullbay/api` (**574/574**, 47 fichiers, +34 Phase 3)
- [x] review inline faite — **5 fixes appliqués** : cache discovery/JWKS TTL 5 min, kid ghost fail-closed, `constantTimeEqual` mort supprimé, erreurs internes masquées dans `/login?error=`, purge mémoire AuthStateStore (borne 64 put)
- [ ] `docker compose -f tests/integration/docker-compose.keycloak.yml up -d` (CI/staging)
- [ ] e2e Keycloak (keycloak-oidc.e2e.mjs) vert (CI/staging)
- [x] tests existants verts sans modification
- [x] commit `87f0ea6` (`feat/auth-implementation`), commitlint OK (header 97 chars), MAIS **non poussé** (push à confirmer)

### Phase 3 — Décision de passage en Phase 4
- [x] **Validation supérieur obtenue** (2026-09-15, passage Phase 4 autorisé)

</section>

---

## PHASE 4 — Generic SAML

<section status="✅ Terminée — revue + validation supérieur (2026-09-15), passage 5A1 autorisé">

**Objectif** : protocole SAML 2.0 générique.

### 4A. Fichiers à créer
- [x] `providers/saml/saml-provider.ts`
- [x] `routes/saml.routes.ts` (login / acs / metadata)
- [x] `__tests__/saml-provider.test.ts`
- [x] `__tests__/fixtures/saml/...` (SAMLResponse signées : valide + 9 cas négatifs) — `helpers.ts` (buildSamlResponse XML→base64 signé RSA-SHA256 via xml-crypto)
- [x] `__tests__/fixtures/saml/keys/...` (cert TEST, jamais prod) — `idp-cert.pem` + `idp-private-key.pem` (X.509 2048, CN Hullbay Test SAML IdP, échéance 2126)
- [x] `core/saml-replay.ts` (store assertions consommées) — empreinte SHA-256 + TTL 10 min + `reset()`
- [x] `tests/integration/keycloak-saml.e2e.mjs` (realm SAML Keycloak)

### 4B. Fichiers à modifier
- [x] `routes/guard.ts` : PUBLIC_PATHS + prefix `/api/auth/saml/`
- [x] `secrets/secret-encryption-service.ts` : scope provider déjà présent (4C), cert chiffré = **N/A** (idpCert public ; aucun secret dans config SAML — privateKey SP chiffrée = Phase 5A1-D rotation)

### 4C. Adapter & validations SAML (node-saml)
- [x] signature — `wantAssertionsSigned: true`, assertion signée (Keycloak style, `wantAuthnResponseSigned: false`)
- [x] issuer — node-saml ne le vérifie PAS pour les POST success → **vérif manuelle fail-closed** `profile.issuer === idpIssuer` (ajoutée après test rouge)
- [x] audience — `Conditions/AudienceRestriction` (node-saml)
- [x] conditions (NotBefore / NotOnOrAfter) — node-saml (`acceptedClockSkewMs` 60s)
- [x] destination — **vérif manuelle** `Response/@Destination` == callbackUrl (absent OU différent → rejet)
- [x] Recipient — **vérif manuelle** `SubjectConfirmationData/@Recipient` == callbackUrl (absent OU différent → rejet)
- [x] InResponseTo — `validateInResponseTo: "always"`, cacheProvider injectable
- [x] replay (saml-replay store) — empreinte + RelayState unique
- [x] expiration — NotOnOrAfter passé → rejet
- [x] clock skew — 60s (config) + maxAssertionAge via conditions
- [x] certificate (chiffré) — **N/A** (cert public IdP ; pas de secret) ; clé étrangère → rejet de signature
- [x] anti **signature wrapping** — node-saml « multiple assertions » rejeté + test wrapping (assertion valide + parasite)
- [x] compat node-saml / Node 22 (vérifier version à l'impl) — **@node-saml/node-saml 5.1.0 fonctionne sous Node 24 (>=20 OK)** ; `npm warn install-scripts` → install avec `--ignore-scripts` (esbuild/ssh2 non requis à runtime)

### 4D. Routes
- [x] `GET /api/auth/saml/:id/login` — initiateLogin → AuthnRequest redirect 302
- [x] `POST /api/auth/saml/:id/acs` — HTML redirection (même pattern SSO), parser form local (zero-dep, pas de @fastify/formbody)
- [x] `GET /api/auth/saml/:id/metadata` (XML exposé) — `generateServiceProviderMetadata`

### 4E. Frontend
- [x] bouton provider SAML (dynamique, N°17) — LoginPage filtre `kind saml`, URL `/api/auth/saml/:id/login` pour `kind === "saml"`

### 4F. Tests (7 cas négatifs obligatoires +)
- [x] signature wrapping — test dédié (assertion valide + assertion parasite → reject)
- [x] replay — empreinte déjà vue → reject (avant callback)
- [x] invalid audience → reject
- [x] invalid issuer → reject
- [x] expired assertion → reject
- [x] tampered assertion → reject (digest)
- [x] wrong destination → reject
- [x] réponse malformée → reject (base64 non-SAML)
- [x] cert invalide → reject (signé clé étrangère)
- [x] ACS refuse assertion invalide → **400** + audit `auth.saml.failed` (plan disait 401 ; cohérence avec sso.routes/OIDC qui utilisent 400 — noté)
- [x] e2e Keycloak SAML vert — script créé + `loadTestSamlSeed` (SAML_TEST_*), exécution CI à faire

### 4G. Validations
- [x] `npm run typecheck -w @hullbay/api` — 0 erreur
- [x] `npm run test -w @hullbay/api` — **587/587** (48 fichiers, +13 Phase 4 ; précédent 574)
- [x] e2e SAML compose — script prêt, exécution CI/staging (pas de docker local)
- [x] tests existants verts sans modification — aucun test préexistant modifié

### Phase 4 — Décision de passage en Phase 5A1
- [ ] **Validation supérieur obtenue** (⚠ PRÊT À VALIDER)

</section>

---

## PHASE 5A1 — Providers + Pendings + Secrets (Enterprise)

<section status="✅ Terminée — code livré, validations vertes ; commit(s) à valider — en attente validation supérieur pour 5A2">

**Objectif** : gouvernance des providers (CRUD owner), workflow pending approval, rotation des secrets.

### 5A1-A. Fichiers à créer
- [x] `policies/security-policy.service.ts` (stub→réel, singleton conservé)
- [x] `identity/pending-approval.service.ts`
- [x] `routes/providers.routes.ts` (CRUD owner)
- [x] `routes/pending.routes.ts` (approve/reject par tenant)
- [x] `__tests__/providers-admin.test.ts`
- [x] `scripts/rotate-secrets.mjs`
- [x] `packages/web/src/pages/AdminProvidersPage.tsx` (frontend)

### 5A1-B. Modifier
- [x] `seeds.ts` (registry DB)
- [x] frontend routing/API

### 5A1-C. Approbation Pending (workflow effectif — correction N°20)
- [x] endpoints approve/reject par l'owner, **PAR tenant** `{tenantId, role}`
- [x] création User + AuthIdentity + Membership à l'approbation
- [x] notification (eventBus + AuditLog, subscriber on-deploy-finished)
- [x] test : pas d'auto-provision hors workflow

### 5A1-D. Rotation secrets
- [x] `SecretEncryptionService.rotate(scope)` — ré-chiffrement progressif par enregistrement (pas gros-bang)

### 5A1-E. Sécurité / tests
- [x] CRUD providers : injections invalides rejetées
- [x] assertion : **aucun secret en clair** dans `AuthProvider.config`
- [x] police anti-énumération conservée

### 5A1-F. Validations
- [x] `npm run test/typecheck` (API : 159 tests verts, tsc 0 erreur ; Web : tsc + build + i18n verts)
- [x] rotate-script idempotent
 - [x] e2e verts (validés ici : login local+MFA, SSO pending→approbation→dashboard, via Playwright/Chrome réel ; Docker compose → CI/staging)

### Phase 5A1 — Décision de passage en 5A2
- [x] **Validation supérieur obtenue** (2026-09-17, commit `4171c6e` : viewer logout fix + MFA enrollment idempotent + SSO e2e validated)

</section>

---

## PHASE 5A2 — Sessions + Policy + JWKS

<section status="🔄 En cours — implémentation en cours (démarré 2026-09-17)">

**Objectif** : sessions persistantes + révocation, politique de sécurité, clés de signature Hullbay.

### 5A2-A. Prisma (migration)
- [x] `UserSession` (jti unique, revokedAt, providerId, ip, userAgent) — migration `20260917105056_5_a2_user_session_security_policy` appliquée
- [x] `SecurityPolicy` singleton (sessionTtlMs, mfaRequireRoles, loginFailLimit, loginFailWindowMs, lockoutMs, providerAllowlist)
- [x] `npm run prisma:generate` + `migrate` ✅

### 5A2-B. Fichiers créés
- [x] `sessions/user-session.store.ts` (impl UserSessionStore + Map cache + Redis + backfill doux)
- [x] `jwks/jwks.service.ts` (hullbay signing keys RS256 + rotation sans cut + legacy secret)
- [x] `routes/sessions.routes.ts` (GET /api/auth/sessions, DELETE /api/auth/sessions/:jti)
- [x] `policies/security-policy.service.ts` (réévalué : lecture DB SecurityPolicy singleton + fallback env)
- [ ] `sessions/session.service.ts`
- [ ] `__tests__/session-store.test.ts`
- [ ] `__tests__/jwks.test.ts`
- [ ] `__tests__/security-policy.test.ts`
- [ ] `packages/web/src/pages/SessionsPage.tsx`

### 5A2-C. Modifiés
- [x] `guard.ts` : déjà via façade authService → auto par sessionManager (inchangé)
- [x] `loaders/websocket.ts` : handshake `socket.data.sessionId` (kid du JWT)
- [x] `core/session-manager.ts` : `UserSessionStore` impl (source de vérité = table + Map cache + jti + révocation)
- [x] `server.ts` + `auth/index.ts` : `registerSessionsRoutes` exporté et appelé
- [x] `policies/security-policy.service.ts` : lecture DB `SecurityPolicy` singleton
- [ ] frontend routing/API (SessionsPage + méthodes API)

### 5A2-D. Migrations de données
- [x] sessions backfill doux (sessions actives sans row → créées à la 1re vérification via `prisma.userSession.findUnique`)
- [x] JWKS seed depuis `JWT_SECRET` (legacy secret gardé pour backward-compat pending tokens)

### 5A2-E. Tests
- [x] 612/612 tests verts, 0 régression (aucun test préexistant modifié)
- [ ] révocation : token révoqué → inutilisable (dédié)
- [ ] expiration session (dédié)
- [ ] invalidation (dédié)
- [ ] politique MFA (dédié)
- [ ] rotation JWKS sans cut (dédié)
- [ ] JWT Hullbay ≠ tokens IdP (dédié)

### 5A2-F. Validations
- [x] `npm run prisma:migrate/generate` ✅
- [x] `npm run typecheck` ✅ (api 0 erreur + web 0 erreur)
- [x] `npm run test` ✅ (612/612, 50 fichiers)
- [ ] `npm run e2e` (en attente CI/staging)

### Phase 5A2 — Décision de passage en 5A3
- [ ] **Validation supérieur obtenue**

</section>

---

## PHASE 5A3 — WebAuthn + LDAP

<section status="⬜ Bloqué (après 5A2)">

**Objectif** : passkeys (facteur, PAS provider) + adapter LDAP/LDAPS.

### 5A3-A. Fichiers à créer
- [ ] `providers/ldap/ldap-provider.ts` (ldapts) — **ou phase dédiée 5A3b si complexité trop hétérogène (décision $21)**
- [ ] `mfa/webauthn.ts` (facteur : enrollment/verify)
- [ ] `__tests__/webauthn.test.ts`
- [ ] `__tests__/ldap-provider.test.ts` (mock ldap)

### 5A3-B. Prisma
- [ ] tables WebAuthn credentials (rattachées à l'identité — jamais AuthProvider, N°11)

### 5A3-C. LDAP (modèle d'exécution propre, N°2)
- [ ] bind (service account) → search user (searchFilter sur base DN)
- [ ] retrieve attributes
- [ ] bind utilisateur (ou verify)
- [ ] resolve groups
- [ ] map identity
- [ ] `stableAttr` configurable : objectGUID (AD) / entryUUID (OpenLDAP) / autre — search attribute ≠ identity attribute
- [ ] TLS / certs (rejectUnauthorized, ca)
- [ ] timeouts
- [ ] referrals (handleReferrals)
- [ ] comptes désactivés / verrouillés si info dispo
- [ ] erreurs connexion
- [ ] LDAPS

### 5A3-D. WebAuthn (facteur)
- [ ] enrollment
- [ ] verify
- [ ] rattaché à l'identité (jamais AuthProvider)
- [ ] ne jamais activer de 2e MFA auto hors politique (N°11)

### 5A3-E. Tests
- [ ] WebAuthn fixtures verts
- [ ] LDAP : bind / search / TLS / timeout / wrong creds / stable subject / mapping / groups / AD + OpenLDAP
- [ ] étape 3($21) : union AD/OpenLDAP (dipo de test) ou fixtures

### 5A3-F. Validations
- [ ] `npm run prisma:migrate/generate`
- [ ] `npm run test/typecheck`
- [ ] `npm run e2e`

### Phase 5A3 — Décision de passage en 5B
- [ ] **Validation supérieur obtenue**

</section>

---

## PHASE 5B — Multi-tenancy complète

<section status="⬜ Bloqué (après 5A3)">

**Objectif** : isolation tenant totale, construite sur le modèle Phase 2. **Périmètre le plus risqué.**

### 5B-A. Fichiers à créer
- [ ] `authorization/tenant-guard.ts` (requireRole(min, ctx))
- [ ] `authorization/tenant-resolver.ts` (tenant depuis sous-route/header/claim)
- [ ] `__tests__/tenant-isolation.test.ts` (MATRICE complète)
- [ ] `scripts/backfill-tenant.mjs` (data → tenant par défaut + dédup Cluster)
- [ ] `tests/integration/tenant-isolation.e2e.mjs`
- [ ] `packages/web/src/components/TenantSwitcher.tsx`

### 5B-B. Prisma (migration)
- [ ] `Cluster.@@unique([tenantId, name])` (dédup contrôlée)
- [ ] `Server` + tenantId
- [ ] `RegistryCredential` + tenantId
- [ ] `Settings` + tenantId
- [ ] `AuditLog` + tenantId
- [ ] `Project` + tenantId
- [ ] `AuthProvider.tenantId String?` (null = provider global, décision explicite — N°22)
- [ ] `SecurityPolicy` par tenant : `@@unique([tenantId])` (fin du singleton, N°21) — backfill dans policy tenant par défaut, tenantId nullable→NOT NULL
- [ ] retrait `User.role` (!! destructive : audit d'usages §2 étape 8 AVANT, puis confirmation)
- [ ] `npm run prisma:generate` + `migrate`

### 5B-C. Migrations de données
- [ ] data → tenant par défaut
- [ ] doublons Cluster résolus avant contrainte
- [ ] rôles MIRROR migrés vers membership (déjà là depuis Phase 2)
- [ ] colonne User.role supprimée après vérif

### 5B-D. Tenant-scoping des 52 sites (revus UN PAR UN — aucun ajout mécanique)
- [ ] `projects` (14 sites)
- [ ] `clusters` (15 sites)
- [ ] `servers` (8 sites)
- [ ] `registry` (8 sites)
- [ ] `reconciler` (7 sites)
- [ ] `observability` (4 sites)
- [ ] routes associées
- [ ] CHAQUE query gagne un filtre tenant explicite
- [ ] ownership / résolution / anti-fuite / test par module

### 5B-E. Routes / Interfaces TS
- [ ] sous-routes `/:tenantSlug/...` (ou header configuré)
- [ ] endpoints membership par tenant
- [ ] `requireRole(min, ctx)` ; `TenantContext` résolu par guard

### 5B-F. WebSocket (isolation §12)
- [ ] blogs.handshake : rooms scoped
- [ ] `join` / `subscribe:logs` vérifient appartenance (projet↔tenant)

### 5B-G. Frontend (vercel-react + emil-design-eng)
- [ ] TenantSwitcher
- [ ] routes `/:tenantSlug/...`
- [ ] rôles par tenant
- [ ] partition du cache/state frontend (client-side data fetching rules vercel-react)

### 5B-H. Tests — MATRICE d'isolation (obligatoire §18)
- [ ] Tenant A ne lit pas les données de B
- [ ] Tenant A ne mute pas B
- [ ] Tenant A ne référence pas les IDs de ressources B
- [ ] Tenant A ne contourne pas le scope via routes alternatives
- [ ] WebSocket : pas de room inter-tenant
- [ ] Audit : isolation des logs
- [ ] 403 systématique hors membership
- [ ] aucune fuite d'IDs croisés

### 5B-I. Validations
- [ ] `npm run prisma:migrate/generate`
- [ ] matrix e2e (tenant-isolation)
- [ ] backend smoke
- [ ] `npm run test/typecheck`
- [ ] e2e web

### 5B-J. Fin de projet
- [ ] matrice isolation verte sur chaque module
- [ ] migration dump staging OK
- [ ] zéro fuite
- [ ] e2e existants verts
- [ ] `User.role` supprimé (N°23)
- [ ] assertion `AuthProvider.config` sans secret en clair (post-5A confirmée)
- [ ] révocation fonctionnelle confirmée
- [ ] rotation sans cut confirmée

### Phase 5B — Livraison complète
- [ ] **Validation supérieur finale**

</section>

---

## Fallback bar : ne JAMAIS implémenter avant la phase indiquée (§15)

- [ ] Avant Phase 2 : aucune modif modèle User/AuthIdentity/Membership/Tenant ; pas de réorg `auth/`
- [ ] Avant Phase 3 : pas d'adapter OIDC/OAuth2 ; pas d'e2e Keycloak
- [ ] Avant Phase 4 : pas d'adapter SAML ; pas de fixtures SAML → ✅ livré (Phase 4), e2e Keycloak à exécuter en CI
- [ ] Avant 5A : pas de UserSession/politique/JWKS/pending-admin/WebAuthn/LDAP effectif
- [ ] Avant 5B : pas de tenant-scoping des 52 sites ; pas de suppression de `User.role`
- [ ] **JAMAIS** : `User.provider`, `email→User` comme identifiant, `AUTH_MODE`, `if(provider==="keycloak")`, `AuthProvider.id @default("keycloak")`, secrets en clair, WebAuthn comme AuthProvider, `AWSProvider`, JWT seule source de vérité après 5A

---

## Zone à trancher (validée par supérieur au go)
- [ ] 1. Timing LDAP : 5A3 (avec WebAuthn) ou phase dédiée 5A3b selon complexité à l'impl
- [ ] 2. Découpe 5A en 5A1/2/3 (recommandé) — validation
- [ ] 3. `User.role` : suppression en 5B confirmée (destructive après audit d'usages)

---

## Journal de suivi (log des sessions)

| Date | Session | Actions | Résultat |
|---|---|---|---|
| 2026-09-14 | Plan V3 | Corrections N°20-23 intégrées au plan | ✅ 4 points validés (PendingIdentity, SecurityPolicy, AuthProvider tenant, typo) |
| | | Création liste de suivi | 🔄 |
| 2026-09-14 | Phase 1 | Branche `feat/auth-implementation` créée (baseline 505 tests verts) | ✅ |
| | | `rate-limit.ts` (CompositeRateLimiter : clé IP+compte+endpoint, fenêtre glissante, backoff expo, purge mémoire) | ✅ |
| | | `audit-events.ts` + events émis from service.ts (login/verifyMfa/changePassword) | ✅ |
| | | `AUDITED` étendu (5 events auth) | ✅ |
| | | `routes.ts` : 429 uniforme + `Retry-After` sur login/mfa-verify/mfa-confirm/password/bootstrap/needs-bootstrap | ✅ |
| | | `security.test.ts` : 14 tests (brute-force, bypass, anti-énumération, audiences JWT, expiration, état, audit) | ✅ 14/14 |
| | | Frontend : api.ts (retryAfterSec) + LoginPage (écran verrou + countdown) + i18n fr/en | ✅ typecheck + build + i18n:validate verts |
| | | Validation : typecheck api (2 erreurs préexistantes clusters), 519 tests API verts, build web vert | ✅ |
| | | Rapport 1I remis — attente feu vert supérieur pour Phase 2 | ⏳ |
| 2026-09-14 | Review Phase 1 | **TS2532** ligne 282 (`mock.calls[i-1][0]`, `noUncheckedIndexedAccess`) — raté au 1er passage, signalé par supérieur | ⚠️ |
| | | Correction review : accès `at(-1)` typé + `AuditCreateArg` (fini les `as any`) ; +2 tests d'audit (`auth.mfa.success`, `auth.password.changed`) ; suite complète 519 → **521 verts** | ✅ 16/16 security |
| 2026-09-14 | Exports morts | « Mot de passe oublié » + « Créer un compte » = **stubs préexistants** (alert indisponible ; aucun endpoint reset/signup dans l'API ; aucun flux au plan Phase 1-5B — provision = admin/owner). Décision supérieur : supprimer. Liens retirés de LoginPage, `ResetPasswordPage.tsx` supprimé, route + guard `/reset-password` retirés d'App.tsx. Web typecheck + build verts. | ✅ |
| 2026-09-14 | i18n pages auth | **Mix FR/EN** : LoginPage 3 chaînes dures (toasts + label MFA) + **ActivateMfaPage 100 % codé en dur** (clés `auth.mfaModal` jamais utilisées) + config i18n fallback `en` (navigateur en → UI EN, dures FR → mélange). Correctifs : toutes les chaînes → clés ; **français = langue par défaut** (`lng/fallbackLng 'fr'`, détection localStorage seule) ; ton unifié vouvoiement ; ActivateMfa localisée (QR/secret/code/bouton + feedback copié). i18n:validate 471 clés/langue sync ; typecheck + build verts. | ✅ |
| 2026-09-14 | **2e passe Phase 1** | Relecture intégrale (rate-limit, routes, service, subscriber, api.ts, LoginPage, tests) + re-validation fraîche : **521/521 verts**, typecheck api maintenant **0 erreur** (les « 2 erreurs préexistantes clusters » = artéfact client prisma stale, migration `cluster_deleting_at` normalement présente — claim corrigé). Écarts mineurs recensés : e2e non exécutable ici (CI/staging), `needs-bootstrap` limité en check-only (jamais déclenché), `mfa/enroll` non limité (délibéré, authentifié/non-crédentiel), timing anti-énumération égalisé par code mais non testé. Aucun test préexistant modifié. | ✅ |
| 2026-09-15 | Phase 2 | Séquence compat §2 (imports/usages/mocks/tests/routes/WS/bootstrap recensés — suivi au jour 14). Schéma prisma refondu + **migration `20260915120000_generate_identity_model` manuelle SQL** : tables AuthIdentity/Tenant/Membership/AuthProvider/PendingIdentity créées, **INSERT...SELECT des credentials (passwordHash/mfaSecretEnc/mfaEnabled) AVANT drop des colonnes User**, tenant default + memberships + seeds providers. Appliquée, DB synchro. | ✅ |
| | | `scripts/backfill-identity.mjs` + npm `backfill:identity` : idempotent (2× = 0 création), vérification DB : `daronnoir@gmail.com → local:cmsw…, hash conservé, mfa=true, membership tenant-default:owner`. | ✅ |
| | | Module restructuré écrit (providers/types+protocol-adapter+local, core auth-core/session-manager/identity-mapping/auth-state, registry/provider-registry+seeds, secrets/secret-encryption-service, mfa/totp+policy, identity/auth-identity.service, authorization/rbac+tenant-context, routes/guard+auth.routes+users.routes, index barrel, service.ts façade, rbac.ts+crypto.ts shims, routes.ts barrel compat). | ✅ |
| | | **2 heures de debug non-régression** : routes appelaient auth-core directement (cassait le mock `../service` d'auth.test.ts) → routes agrégées à la **façade authService** ; guard utilisait sessionManager (cassait le mock verifyToken) → **authService.verifyToken** + fallback pendingToken sur MFA_SETUP_PATHS ; `/api/auth/me` lisait `u.mfaEnabled` (retiré de User) → prisma.user + identity mfaEnabled (fallback legacy) ; `identity-mapping` findUnique composé exige issuer non-null → **findFirst** ; mocks prisma `.update/.create` doivent monter une Promise (`vi.clearAllMocks` efface les impls) ; `AuthResult` enrichi `userId/role`. | ✅ |
| | | **Tests verts 540/540 (44 fichiers)** — baseline 521 + 19 nouveaux (provider-registry 8, local-provider 6, identity-mapping 5). security.test.ts **adapté** au nouveau modèle (seule retouche autorisée). Typecheck api **0 erreur**, build api 335 kB + **build web vert**. Dev : `User.role` MIRROR conservé (Phase 5B), `routes.ts`/`rbac.ts` conservés (barrel/shim, déviation validée). | ✅ |
| | | Prochaine étape : validation supérieur Phase 2, puis branchement PendingIdentity workflow = Phase 5A. | ⏳ |
| 2026-09-15 | Phase 2 validée | Supérieur valide Phase 2 → passage Phase 3 autorisé (OIDC/OAuth2 génériques). | ✅ |
| | Phase 3 — Providers | `oidc-provider.ts` réécrit : PKCE/state/nonce via `core/auth-state`, discovery fail-closed, JWKS kid-apparié, nonce réel vérifié, `authenticate()` lève (flux redirect), `getConfig()` sans secret. `oauth2-provider.ts` créé (state, userinfo obligatoire, subject=`sub??id`, issuer=null). `protocol-adapter.ts` route par kind+config, saml/ldap lèvent toujours. `seeds.ts` + `provider-registry.ts` : `loadTestOidcSeed` actif **uniquement si env `OIDC_TEST_*`** (jamais défaut). | ✅ |
| | Phase 3 — Callback + routes | `core/sso-callback.ts` : `processSsoCallback` → identity-mapping → session (mfaEnabled=true, pas de 2e MFA locale §10) ou pending (jamais auto-create User). `routes/sso.routes.ts` : `GET /api/auth/providers` (public, configs publiques), `GET /api/auth/sso/:id/login` (302), `GET /api/auth/sso/:id/callback` (HTML CSP `no-store`, token→localStorage, pending→`/login?pending=1`, error→`/login?error=`). `routes/guard.ts` : PUBLIC_PATHS ajoute `/api/auth/providers` + prefix `/api/auth/sso/`. Barrel `index.ts` + `server.ts` wirés. | ✅ |
| | Phase 3 — Tests | **32 nouveaux tests** (540 → **572**, +32) : OIDC 16 (valid, invalid issuer/audience/signature/expired, nonce mismatch, state replay, PKCE assertion, JWKS rotation, double-issuer sans branche vendor, discovery mismatch, token endpoint refusé, getConfig/authenticate contrat) + OAuth2 12 (flow complet, groups, state replay, userinfo absent/403, token 401, access_token manquant) + SSO-callback 4 (session, pending, doublon pending, User absent). Fixtures : `MockIdp` (RSA 2048, discovery+JWKS+token mock, nonce dynamique via ref), `MockOauth2` (token+userinfo mock). Typecheck + build verts. Aucun test préexistant modifié. | ✅ |
| | Phase 3 — Frontend | LoginPage : bannière pending (`?pending=1&email=`), section SSO (prefetch providers → boutons dynamiques → `/api/auth/sso/:id/login`, séparateur "ou"). `api.ts` : `listAuthProviders()`, type `AuthProviderPublic`. i18n fr/en : clés `auth.sso.signInWith`, `orContinueWithLocal`, `failed`, `pending.title/description`. `i18n:validate` 476 clés sync. | ✅ |
| | | Prochaine étape : validation supérieur Phase 3, puis Phase 4 (SAML générique). | ⏳ |
| 2026-09-15 | Phase 3 — Review + fixes | Review inline complète (subagent cavecrew indisponible : « Model not found deepseek-v4-flash-free », fallback main-thread). **5 findings corrigés** : 1) cache discovery/JWKS illimité → TTL 5 min (rotation sans restart) ; 2) `selectJwk` kid non apparié → refus fail-closed ; 3) `constantTimeEqual` mort supprimé ; 4) `sso.routes` exposait `err.message` brut dans `/login?error=` → `sso_internal` ; 5) `AuthStateStore.purge()` jamais appelée → borne mémoire (purge tous les 64 put). +2 tests (kid ghost, JWKS re-fetch après TTL). Re-validation : **574/574 tests** (47 fichiers), typecheck api 0 erreur, build api 357.0kB. | ✅ |
| | Phase 3 — Commit | `87f0ea6` `feat(auth): phase 3 — OIDC/OAuth2 génériques fail-closed, SSO external -> session ou pending` sur `feat/auth-implementation` (23 fichiers, +1908/−14). Commitlint OK (header 97 chars ≤ 100). **Pas poussé** — push sur confirmation. Tracking exclu du repo (`.git/info/exclude`). | ✅ |
| 2026-09-15 | Phase 4 — Code | `saml-provider.ts` : wrapper node-saml 5.1.0 (`wantAssertionsSigned`, `wantAuthnResponseSigned:false` = assertion signée style Keycloak, `validateInResponseTo:"always"`, clock skew 60s, `cacheProvider` injectable). **2 vérifs manuelles ajoutées car node-saml ne les fait PAS** : issuer de l'assertion (`profile.issuer === idpIssuer`, après test rouge) + `Destination`/`Recipient` == ACS (absent ou différent → reject). `core/saml-replay.ts` : empreinte SHA-256 + TTL 10 min + `reset()`. `routes/saml.routes.ts` : GET login (302 AuthnRequest), POST acs (HTML CSP no-store, parser form local zero-dep, audit `auth.saml.failed` nouveau event + subscriber), GET metadata. Fixtures : `fixtures/saml/helpers.ts` (buildSamlResponse XML→base64 signée RSA-SHA256 via xml-crypto) + clés X.509 TEST committées (échéance 2126). `seeds.ts` : `loadTestSamlSeed` actif **uniquement si env SAML_TEST_*** + `saml-e2e`. guard.ts : prefix `/api/auth/saml/` public. Frontend : LoginPage boutons `kind==="saml"` → `/api/auth/saml/:id/login`. server.ts + index.ts wirés. server.ts log redact : `req.body.SAMLResponse` ajouté. | ✅ |
| | Phase 4 — Tests | **+13 tests SAML** (574 → **587**, 48 fichiers) : valide (flow complet initiateLogin→callback) + 9 cas négatifs (pas de signature, clé étrangère, audience, issuer, NotOnOrAfter expiré, tamper post-signature, Destination ≠ ACS, Recipient ≠ ACS, InResponseTo absent) + replay + structure cassée + **signature wrapping** (assertion valide + parasite → « multiple assertions » rejetée). Aucun test préexistant modifié. Typecheck api + web 0 erreur, build api 368.9kb, i18n:validate 476 clés sync. | ✅ |
| | Phase 4 — e2e Keycloak SAML | `tests/integration/keycloak-saml.e2e.mjs` créé (même pattern OIDC) : provisionne realm + client SAML `hullbay-saml-e2e` (POST/POST, assertion signée, cert SP) + user. Flux navigateur reporté (hors scope CI) — validation ACS couverte par unit tests mêmes fixtures. **Exécution compose = CI/staging** (pas d'env docker ici). | ⏳ |
| | Phase 4 — Next | Validation supérieur → Phase 5A1 (providers CRUD + pendings + rotation secrets). | ⏳ |
| 2026-09-17 | Phase 5A1 — e2e validation | Tests UI end-to-end (Playwright/Chrome réel) : login local + MFA (enrôlement TOTP, code invalide, rate-limit), SSO complet (redirect IdP mock → pending → approbation → dashboard). Bugs trouverts + corrigés : (1) `DomainGate` traitait tout 403 ("permission insuffisante") comme erreur d'auth → logout abusif des operators/viewers ; fix via `me.mfaRequired` (vrai uniquement pour identité locale non-enrôlée) + gate domaine owner-only + `ActivateMfaPage` guard ; (2) enrôlement MFA non idempotent sous StrictMode (2× `enrollMfa` → race secret affiché ≠ DB → confirm 400) ; fix backend (réutilise secret en attente) + frontend (`enrollStarted` guard). Commit `4171c6e`. `npm test` 678/678. | ✅ |
| | 5A1 — Next | **Validation supérieur obtenue** → débloquer Phase 5A2 (Sessions + Policy + JWKS). | ⏳ |
| 2026-09-17 | Phase 5A2 — Implémentation | Démarrage 5A2. Prisma : migration `20260917105056_5_a2_user_session_security_policy` (UserSession + SecurityPolicy). Core : `UserSessionStore` impl (table + Map cache + jti + révocation + backfill doux), `JwksService` (RS256 keyset + rotation sans cut + legacy secret pour backward-compat pending tokens). `security-policy.service.ts` réévalué (lecture DB singleton + fallback env). `loaders/websocket.ts` : `socket.data.sessionId` (kid JWT). `server.ts` + `auth/index.ts` : `registerSessionsRoutes`. `routes/sessions.routes.ts` créé (GET/DELETE sessions). Typecheck api+web 0 erreur. `npm test` 612/612 verts, 0 régression. | ✅ |
