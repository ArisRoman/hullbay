# PLAN D'IMPLEMENTATION V4 — Authentification Hullbay (référentiel décisionnel)
### Source unique des décisions d'authentification — en vigueur
### Corrections finales et validation conditionnelle intégrées 

---

## 0. Architecture cible validée (rappel figé)

```
IdP
 ↓
Protocol Adapter                Provider Registry
 ↓                                    │
AuthProvider ◄────────────────────────┘
 ↓
External Identity
 ↓
AuthIdentity
 ↓
User
 ↓
Membership
 ↓
Tenant
 ↓
Authorization / RBAC
```

Protocoles ciblés : **OIDC, OAuth2, SAML 2.0, LDAP/LDAPS, Local**.
Règle : *nouveau fournisseur sur protocole supporté = configuration ; nouveau protocole = nouvel adapter*.
**Aucun fournisseur commercial privilégié** (pas de KeycloakProvider, EntraProvider, AWSProvider).

---

## D. Référentiel de décisions actées (source de vérité)

Ce plan est **la source de toutes les décisions d'authentification Hullbay**. Tout comportement livré doit pouvoir être rattaché à une entrée de ce référentiel. Aucune décision extérieure au plan n'est opposable ; toute évolution passe par une mise à jour du présent document.

### D.1 Stockage et cycle de vie des états

- **Single-instance** : `AuthStateStore` (state/nonce/PKCE), `SamlReplayStore` (assertions consommées), store des challenges WebAuthn et compteurs de rate-limite sont des stores mémoire bornés (purge périodique). Les sessions s'appuient sur Redis via `UserSessionStore`. Contrainte single-instance actée ; horizon multi-instance = remplacement par un stockage partagé.
- **Redis** : client créé paresseusement à la première utilisation ; un handler `error` empêche la chute du processus ; Redis indisponible → session store indisponible, jamais de dégradation silencieuse.

### D.2 Sessions, jeton, révocation

- **Keyring JWKS Hullbay** persisté sur disque (`JWKS_KEYRING_FILE`) ; la clé courante signe, les anciennes valident (rotation sans invalider les jetons en vol) ; `kid` inconnu → rejet (jamais de repli sur `JWT_SECRET` en dur).
- Jeton Hullbay : audience `session`, expiration ; séparation stricte avec les JWKS IdP (§11).
- **Révocation** : ensemble `revokedJtis` en mémoire vérifié de façon synchrone + persistance DB dans `UserSessionStore` (la vérité reste la table) ; un jeton révoqué n'est jamais ré-accepté depuis le cache seul.
- **Backfill doux** : sessions actives sans ligne `UserSession` → créées à la première vérification ; refusées si le `User` a été supprimé.
- `lastSeenAt` écrit au maximum une fois par minute.

### D.3 SSO générique

- Discovery/JWKS OIDC en cache avec TTL 5 minutes (rotation sans redémarrage). Échec de lecture → `sso_internal` (jamais de message brut renvoyable).
- Décalage d'horloge IdP : `acceptedClockSkewMs`, défaut 30 secondes, transmis à chaque adapter.
- SAML : en plus des validations node-saml, vérifications **manuelles obligatoires** de l'issuer d'assertion et de `Destination`/`Recipient` (node-saml ne les effectue pas). 9 cas négatifs + replay + signature wrapping requis (§19).

### D.4 WebAuthn / MFA

- WebAuthn = **facteur**, jamais `AuthProvider` (§10). `userVerification:"required"` + `requireUserVerification` côté serveur.
- **Origine fail-closed** : origine arbitraire interdite ; production réglée par `WEBAUTHN_ORIGIN`, dev restreint à localhost.
- Parsing des transports tolérant (`parseTransports`) — jamais de crash sur données invalides.
- **Garde anti-replay** : compteur de session WebAuthn strictement croissant (`newCounter > stored`), sinon 401 + audit `counter_replay`.
- Challenge indexé par empreinte du token (anti auto-DoS).
- Un seul facteur MFA suffit à lever la garde (TOTP **ou** passkey) ; l'ajout d'une passkey lève la garde `mfaRequired`.

### D.5 LDAP

- subject = `stableAttr` configurable (`objectGUID` canonisé little-endian / `entryUUID`), jamais un attribut de recherche (§1 N°2).
- Filtres : placeholders `{{username}}`, `{username}` et `%u` ; filtre sans placeholder → fail-closed. Valeurs UAC acceptées en tableau.
- Recherche de groupes OpenLDAP via `groupSearchBase` + `groupFilter`.
- **Referrals** : autorisés en ldaps uniquement, hôte étranger restreint au même domaine ; `bindSecret` jamais transmis cross-host (anti SSRF / vol de service account).
- Péréquation temporelle du bind (anti oracle de présence de compte) ; comptes désactivés/verrouillés détectés via UAC quand dispo.
- URL restreinte au schéma `ldap(s)://`.

### D.6 Erreurs, audits, internationalisation

- `AuthError.reason` : champ d'analyse interne, **jamais sérialisé** dans une réponse.
- Messages d'échec uniformes (anti-énumération) : code machine en réponse + détail en log serveur ; traduction à l'affichage par code de clé (`apiErrors.*`).
- **Français = langue par défaut** (fallback `fr`), détection par localStorage seul.
- Échecs LDAP/SAML/WebAuthn → audits `auth.ldap.failed`, `auth.saml.failed`, `auth.webauthn.*` émis.

### D.7 Multi-tenant

- `AuthProvider.tenantId String?` (§4.2, §5B) : `null` = provider global (presets locaux/SSO transverses) ; chaque tenant dispose de ses providers ; les mutations des providers globaux sont réservées au tenant par défaut.
- **Policy par tenant** : rate-limiting et exigence MFA locale évalués via `getPolicyCached (tenantId)` à partir de la policy du tenant courant.
- Events d'audit portent `tenantId`.
- `/api/auth/session/switch-tenant` fait partie des chemins autorisant la configuration MFA.

### D.8 Périmètre produit

- **Hors périmètre** : réinitialisation de mot de passe en libre-service et création de compte en libre-service (provision = admin/owner). Les stubs correspondants sont retirés.
- **Découpe 5A actée** : 5A1 providers+pendings, 5A2 sessions+policy+JWKS, 5A3 WebAuthn+LDAP (**pas** de phase 5A3b dédiée).
- `AuthResult` expose `userId` et `role` ; la façade `authService` conserve ses signatures publiques ; `routes.ts`/`rbac.ts` conservés comme points d'entrée de compat.

---

## 1. Corrections obligatoires intégrées (rappel des écarts V2 → V3)

| N° | Correction | État dans V3 |
|---|---|---|
| 2 | LDAP ≠ OIDC/SAML : modèle d'exécution propre (bind→search→attrs→bind user→groups→map) ; subject = attribut stable configurable (AD `objectGUID`, LDAP `entryUUID`, ou configuré), **jamais** attribut de recherche (`samAccountName`/`uid`/`email` = recherche seulement) | §5.5, §17.4 |
| 3 | AWS : ne jamais coder un « AWSProvider » ; réduire au protocole exposé (OIDC/SAML/X) | §7 |
| 4 | Prisma `AuthProvider.id @default("keycloak")` supprimé → `@default(cuid())` | §4.4 |
| 5 | `AuthIdentity` : unicité `@@unique([providerId, issuer, subject])` conservée ; email = attribut | §4.1 |
| 6 | Multi-tenant préparé dès Phase 2 (modèles), enforce 5B | §6, §12 |
| 7 | Keycloak = simple configuration OIDC, jamais obligatoire, jamais `AUTH_MODE`, jamais `if(provider==="keycloak")` | §7 |
| 8 | `SecretEncryptionService` : séparation logique mfa / provider / session ; `encryptSecret/decryptSecret` en façade de compat | §8 |
| 9 | SessionStore abstraite dès Phase 2 ; JWT stateless transitoire, pas enfermé | §9 |
| 10 | JWT Hullbay ↔ JWKS IdP strictement séparés | §11 |
| 11 | WebAuthn/TOTP = **facteurs**, jamais AuthProvider ; pas de 2e MFA auto sauf politique | §10 |
| 12 | RBAC : `requireRole(min)` en transition, `User.role` temporaire supprimé en fin de 5B | §13 |
| 13 | Compat : inspecter imports/usages/mocks/tests/routes/ws/bootstrap avant chaque refactor | §2, §14 |
| 15 | Pending approval pensé tenant-aware dès le modèle (approbation = membership) | §6, §17.2 |
| 16 | Rate limiting : IP + account + endpoint + backoff, anti-énumération | §16, Phase 1 |
| 17 | UI : « Add provider → Protocole → Configuration » ; aucune liste hardcodée | §14UI |
| 19 | Wording : « supports standards-based identity providers through OIDC, OAuth2, SAML 2.0 and LDAP/LDAPS » ; « any provider compatible with a supported protocol… » | §18 |
| 20 | `PendingIdentity` : **modèle préparé dès Phase 2**, workflow d'approbation effectif (validation owner, création User+AuthIdentity+Membership) **en Phase 5A** seulement | §4, §1 p.4 |
| 21 | `SecurityPolicy` : singleton conservé 5A, **évolution explicite vers policies par tenant (`@@unique([tenantId])`) en Phase 5B** (backfill dans policy du tenant par défaut, `tenantId` nullable → NOT NULL) | §4, §5B |
| 22 | `AuthProvider` : association `tenantId String?` en 5B (**null = provider global**, décision explicite presets locaux/SSO transverses) ; chaque tenant = ses providers | §4, §5B |
| 23 | Typo corrigée : « `User.role` fantoe » → « **supprimé** » | §14 |

---

## 2. Compatibilité obligatoire avant tout refactor (rappel exécutoire)

**Séquence obligatoire avant chaque refactor important** (Phase 2 principalement) :
1. rechercher les imports ; 2. les usages ; 3. les mocks ; 4. les tests ; 5. les routes ; 6. les dépendances WebSocket ; 7. le bootstrap ; 8. ensuite modifier l'API interne.

Surface de compat recensée (vérifié, §2 V2) :
- `authService` : importé `routes.ts`, `websocket.ts`, **8 modules de tests** (settings, secrets, observability, projects, updates, registry, reconciler, servers).
- `requireRole` / `currentUser` : importés par **9 modules** (settings, secrets, clusters, observability, projects, updates, registry, reconciler, servers).
- `verifyToken` : mocké dans **10 fichiers de tests**.
- `encryptSecret/decryptSecret` : utilisés par `auth/service` et `registry/service`.
- `registerAuthGuard(app)` server.ts:141 ; `registerAuthRoutes(app)` server.ts:153 ; `AUDITED` on-deploy-finished.ts:12-24 ; handshake WS websocket.ts:29-40.

**Contrat de non-régression** : à chaque fin de phase, tests existants verts **sans modification de leur contenu**.

---

## 3. Commandes de validation (réelles, recensées)

```
# API
npm run typecheck -w @hullbay/api              # tsc --noEmit
npm run lint -w @hullbay/api                   # (si script présent — vérifier à l'usage)
npm run test -w @hullbay/api                   # vitest run
npm run prisma:migrate -w @hullbay/api         # prisma migrate dev
npm run prisma:generate -w @hullbay/api        # prisma generate

# Web
npm run typecheck -w @hullbay/web
npm run build -w @hullbay/web                  # tsc && vite build
npm run e2e -w @hullbay/web                    # playwright test
npm run i18n:validate -w @hullbay/web

# Global
npm run typecheck                               # workspaces
```
*(Si `lint` n'existe pas côté api, l'ajouter au script `"lint": "tsc --noEmit"` en Phase 1 — vérifié au moment de l'impl.)*

---

## 4. Modèles Prisma définitifs (corrigés)

### 4.1 User / AuthIdentity / Membership / Tenant

```prisma
model User {
  id          String   @id @default(cuid())
  email       String?
  name        String?
  locale      String?
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  identities  AuthIdentity[]
  memberships Membership[]
}

// Une identité = un compte auprès d'UN provider (ou local).
// Un même User peut cumuler : local + google + entra + ... (aucun provider privilégié).
model AuthIdentity {
  id           String   @id @default(cuid())
  userId       String
  providerId   String                         // id du provider (registry)
  kind         String    // local | oidc | oauth2 | saml | ldap
  issuer       String?                        // O/S obligatoire pour oidc/saml ; NULL pour local/ldap-bind
  subject      String                         // sub OIDC / NameID SAML / objectGUID LDAP / "local:<userId>"
  email        String?

  // Crédenciales locales uniquement (kind=local)
  passwordHash String?
  mfaSecretEnc String?
  mfaEnabled   Boolean  @default(false)

  createdAt    DateTime @default(now())
  lastLoginAt  DateTime?

  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([providerId, issuer, subject])
  @@index([userId])
}

// Rôle = propriété de la membership, PAS du user (préparé en Phase 2, enforce 5B).
model Tenant {
  id          String       @id @default(cuid())
  name        String
  slug        String       @unique
  createdAt   DateTime     @default(now())
  updatedAt   DateTime     @updatedAt

  memberships Membership[]
  clusters    Cluster[]
  settings    Settings[]
  auditLogs   AuditLog[]
}

model Membership {
  id        String   @id @default(cuid())
  userId    String
  tenantId  String
  role      String   // owner | operator | viewer
  createdAt DateTime @default(now())

  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  tenant    Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)

  @@unique([userId, tenantId])
}
```

### 4.2 AuthProvider (correctif obligatoire N°4)

```prisma
// id généré — JAMAIS de défaut vendor. Keycloak n'a aucun privilège architectural.
model AuthProvider {
  id        String   @id @default(cuid())     // identifiant généré/explicite, PAS "keycloak"
  kind      String   // local | oidc | oauth2 | saml | ldap
  name      String                            // nom libre choisi par l'admin : "Entra Corp", "Company LDAP"...
  enabled   Boolean  @default(false)
  config    Json     @default("{}")           // champs sensibles CHIFFRÉS individuellement (§8)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
// ÉVOLUTION 5B (correction N°22) : `+ tenantId String?` — association provider→tenant.
// null = provider GLOBAL (presets locaux/SSO transverses, décision explicite).
// Chaque tenant dispose de ses propres providers ; `@@index([tenantId])`.
```

### 4.3 Sessions / Politiques (5A)

```prisma
model UserSession {
  id         String    @id @default(cuid())
  userId     String
  identityId String?
  jti        String    @unique
  providerId String
  createdAt  DateTime  @default(now())
  expiresAt  DateTime
  lastSeenAt DateTime  @default(now())
  userAgent  String?
  ip         String?
  revokedAt  DateTime?
  user       User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@index([userId])
  @@index([jti])
}

model SecurityPolicy {
  id                String  @id @default("singleton")
  sessionTtlMs      Int     @default(43200000)     // 12h par défaut
  mfaRequireRoles   String  @default("[]")         // rôles exigeant MFA locale même SSO
  loginFailLimit    Int     @default(5)
  loginFailWindowMs Int     @default(60000)
  lockoutMs         Int     @default(300000)
  providerAllowlist String  @default("[]")         // restriction providers par tenant
  updatedAt         DateTime @updatedAt
}
// V4 : même modèle, singleton — les premières phases (2-5A) s'en servent tel quel.
// ÉVOLUTION 5B : SecurityPolicy passe en `@@unique([tenantId])` (plus de singleton) — chaque
// tenant a ses propres règles MFA, TTL, faillock, allowlist. Le code d'évaluation lit la
// policy du tenant courant (résolu via TenantContext). Migration 5B : backfill des paramètres
// globaux existants dans la policy du tenant par défaut ; nouveau champ `tenantId String?`
// (nullable jusqu'à la fin de migration, puis NOT NULL) + `@@unique([tenantId])`.
// Le singleton `id` peut devenir obsolète — voir §17/5B au moment de l'impl.
```

### 4.4 Ajustements tenant-scope (exécutés en Phase 5B)

```prisma
Cluster.name @unique  →  @@unique([tenantId, name])   // dédup contrôlée en migration
Server, RegistryCredential, Settings, AuditLog, Project → +tenantId
User.role  → supprimé définitivement à la fin de 5B (§13)
```

---

## 5. Interfaces TypeScript (corrigées)

### 5.1 Contrat Provider (`auth/providers/types.ts`)

```ts
export type ProviderKind = "local" | "oidc" | "oauth2" | "saml" | "ldap"

export interface ExternalIdentity {
  providerId: string
  kind: ProviderKind
  issuer: string | null      // NULL pour local / ldap-bind
  subject: string            // identifiant stable (iss+sub / objectGUID / local:<id>)
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
}

export interface AuthProviderContract {
  id: string
  kind: ProviderKind
  enabled: boolean
  authenticate(input: AuthInput): Promise<AuthResult>
  initiateLogin?(req: FastifyRequest, reply: FastifyReply): Promise<void>
  callback?(req: FastifyRequest, raw: unknown): Promise<ExternalIdentity>
  logout?(req: FastifyRequest): Promise<void>
  getConfig(): ProviderPublicConfig      // jamais les secrets
}
```

### 5.2 SessionStore (abstraction dès Phase 2, §9)

```ts
export interface SessionStore {
  create(user: { userId: string; identityId?: string; providerId: string }): Promise<SessionHandle>
  verify(token: string): Promise<SessionHandle>   // Phase 2-4 : JWT signé ; Phase 5A : UserSession + jti
  revoke(sessionId: string): Promise<void>
  listByUser(userId: string): Promise<SessionHandle[]>
}
```

### 5.3 Provider configs (par kind)

```ts
type OidcConfig  = { issuer: string; clientId: string; clientSecret: string; scopes: string; redirectUri: string; clientAuthMethod?: string }
type Oauth2Config = { authorizationUri: string; tokenUri: string; userinfoUri: string; clientId: string; clientSecret: string; redirectUri: string; scopes: string; groupAttr?: string }
type SamlConfig  = { entityId: string; entryPoint: string; idpCert: string; callbackUrl: string; wantAssertionsSigned?: boolean; nameIdFormat?: string }
type LdapConfig  = { url: string; tlsOptions: { rejectUnauthorized: boolean; ca?: string }; bindDn: string; bindSecret: string; searchBase: string; searchFilter: string; groupSearchBase?: string; groupFilter?: string;
                     stableAttr: string /* objectGUID | entryUUID | autre */; attrMap: { username: string; email: string; name: string; groups: string }; timeoutMs?: number; handleReferrals?: boolean }
```
`clientSecret`, `idpCert`, `bindSecret`, `tlsOptions.ca` sont **chiffrés individuellement** avant stockage.

---

## 6. Identity Mapping & Pending approval (tenant-aware)

```
ExternalIdentity (providerId, issuer, subject)
        │  lookup @@unique([providerId, issuer, subject])
        ▼
  AuthIdentity trouvée → User (+ membership tenant courant)
        │
        │  absente → Pending identity (Table : PendingIdentity)
        ▼
PendingIdentity { id, providerId, issuer, subject, email?, name?, requestedForTenantId?, createdAt, status }
        │
        │ owner approuve/rejette PAR tenant : { tenantId, role }
        ▼
User créé (ou relié) + AuthIdentity + Membership(tenant, rôle)
```

- **Modèle dès Phase 2** : table `PendingIdentity` préparée (§4, §1 N°20). Approbation par tenant (`{ tenantId, role }`), jamais globale.
- **Workflow effectif en Phase 5A** : endpoints d'approbation/rejet par l'owner, création User + AuthIdentity + Membership, notification. Avant 5A : table présente mais processus administratif/manuel (pas d'auto-provision).
- **Dès Phase 3/4/5A** : l'approbation **attribue une membership** (tenant + rôle). Pas d'approbation « globale ».
- **Phase 2** : tenant par défaut unique (compat V1).
- Email = **jamais** identifiant primaire (attribut : affichage, notification, onboarding, rapprochement contrôlé seulement).

---

## 7. Place de Keycloak / AWS (nettoyées)

- **Keycloak** : un provider OIDC **comme un autre**. Utilisé (a) en tests e2e (`tests/integration/docker-compose.keycloak.yml`), (b) IdP self-hosted, (c) broker ; proposé à un user voulant une IAM open-source. **Absent du cœur, du modèle, du défaut** (correctif N°4, N°7).
- **AWS / tout fournisseur** : uniquement via le protocole réellement exposé. « AWS » + OIDC → adapter OIDC. **AwsOidcProvider n'existe pas**. Aucune dépendance commerciale.

---

## 8. SecretEncryptionService (séparation logique, rotation future)

```
SecretEncryptionService
├── encrypt(kind: "mfa" | "provider" | "session", value) → string   // AES-256-GCM iv:tag:ciphertext
├── decrypt(kind, storage) → string
├── encryptObject/decryptObject(config)  // chiffre champs sensibles de AuthProvider.config
└── rotate(kind)                          // ré-chiffrement progressif par enregistrement (pas gros-bang)
```

- **Séparation logique forcée** : clés plafonnées par domaine (`MFA_ENCRYPTION_KEY` pour mfa ; `PROVIDER_SECRET_KEY` pour provider ; `SESSION_SIGNING_KEY` pour signing) — rotation indépendante possible.
- **Façade compat conservée** : `encryptSecret()/decryptSecret()` → délèguent à `encrypt("mfa"/…)` — les appels existants (`auth/service`, `registry/service`) **intacts** (compat §13, N°8).
- **Aucun secret IdP en clair en base** : `.env` = seed initial ; prod = config chiffrée.

---

## 9. Sessions (abstraction, pas d'enfermement)

```
Auth → SessionStore → JWT (Phase 2-4) → UserSession + Redis + jti + revocation (Phase 5A)
```

- Phase 2 : `SessionStore` interface + impl `StatelessJwtStore` (= comportement actuel, sessions conservées).
- Phase 5A : impl `UserSessionStore` (source de vérité = table) ; JWT = présentation (`jti`) ; révocation ; liste appareils ; cache Redis.
- JWT Hullbay ≠ tokens IdP (séparation N°10).

---

## 10. MFA / WebAuthn (facteurs ≠ providers)

- **TOTP** : factor sur identité locale (conservé).
- **WebAuthn/Passkeys** : **facteur / step-up**, dans `mfa/`, rattaché à l'identité ; **jamais** `AuthProvider`.
- **Politique** : sécurité IdP MFA ≠ obligation d'une 2e MFA Hullbay. Par défaut : pas de 2e MFA locale après SSO. Forcée par `SecurityPolicy.mfaRequireRoles` si besoin.
- **Step-up** : MFA locale pour actions sensibles (option, Activity 5A).

---

## 11. JWT / JWKS (responsabilités séparées)

- **Clés de session Hullbay** : keyset JWKS Hullbay (`kid`), indépendant du SSO ; clé courante signe, anciennes valident ; rotation sans cut des sessions ; migration depuis `JWT_SECRET` en seed.
- **JWKS IdP externes** : gérées dans les adapters (`openid-client`, node-saml) — jamais fusionnées avec Hullbay.

---

## 12. WebSocket (évolutif)

| Phase | Changement | Compat |
|---|---|---|
| 2 | aucun (via façade `verifyToken`) | 100 % |
| 5A | handshake via `SessionStore` (présence + non-révocation) ; `socket.data.sessionId` | comportement identique |
| 5B | validation d'appartenance projet↔tenant avant `join:project`/`subscribe:logs` ; rooms tenant-scoped | isolation activée |

---

## 13. RBAC (transition + cible)

- **Transition** : `requireRole(min)`, `currentUser(req)` inchangés ; le rôle est résolu via `membership(user, tenantCourant).role` ; tenant courant = tenant par défaut tant que 5B inactive.
- **Cible** : `User → Membership → Tenant → Role → Permission` ; `requireRole(min, ctx)` avec `ctx.tenantId`.
- `User.role` : MIRROR temporaire conservé pendant la migrate (Phase 2-5A), **supprimé en fin de 5B** (test d'usages d'abord, §2).

---

## 14. Les 5 phases — Plan d'implémentation concret

> Règle : chaque phase = PR(s) dédiée(s), tsc/lint/vitest/e2e verts, tests existants inchangés verts, migration appliquée sur dump staging. Rien d'une phase suivante n'est implémenté avant contrôle (§14 directive).

---

### PHASE 1 — Auth Hardening

**OBJECTIF** : sécuriser l'existant (rate limiting, erreurs, audit, MFA, secrets, JWT) + tests. **Pas de refonte multi-tenant.**

**Fichiers à créer**
```
packages/api/src/modules/auth/rate-limit.ts            // clé composite + backoff
packages/api/src/modules/auth/audit-events.ts          // events auth structurés
packages/api/src/modules/auth/__tests__/security.test.ts
```

**Fichiers à modifier**
- `packages/api/src/modules/auth/routes.ts` : brancher rate-limit sur login/mfa/*/password/bootstrap ; aider `Retry-After`.
- `packages/api/src/modules/auth/service.ts` : emit events auth (success/failed) depuis login/verifyMfa/changePassword.
- `packages/api/src/subscribers/on-deploy-finished.ts` : étendre `AUDITED`.

**Fichiers à supprimer** : aucun.

**Prisma** : aucun changement.

**Migrations de données** : aucune.

**Adapters** : aucun.

**Routes** : réponses 429 uniformes (`Retry-After`).

**Frontend** : écran de verrouillage avec compte à rebours alimenté par `Retry-After` (décision D.6). `needs-bootstrap` reste un contrôle (check-only), jamais déclencheur d'une modification.

**WebSocket** : inchangé.

**Bootstrap** : inchangé.

**Tests à créer** : brute-force (6ᵉ→429), bypass (IP diff / compte diff), énumération de comptes (même status), audience JWT, MFA token invalide/expiré, expiration de session, état d'auth invalide. Audit auth alimenté.

**Tests de sécurité** : voir ci-dessus ; message d'échec uniforme (pas d'énumération), rate-limit ne révèle pas l'existence d'un compte.

**Risques de régression** : nuls (aucun déplacement de code). Rate-limit sous NAT → mitigé par clé composite + backoff + politique (5A).

**Critères d'acceptation** : vitest 53→≈75 verts ; e2e login/MFA/bootstrap inchangés verts ; 429+Retry-After ; audit auth complet.

**Validations** : `npm run typecheck -w @hullbay/api` ; `npm run test -w @hullbay/api` ; `npm run build -w @hullbay/web` ; `npm run e2e -w @hullbay/web` ; pas de migration.

---

### PHASE 2 — Provider Foundation + Identity Model

**OBJECTIF** : AuthProvider, AuthIdentity, User, Membership, Tenant, Provider Registry, SessionStore ; migration users existants ; tenant par défaut ; compat `User.role` temporaire ; secrets chiffrés. Prépare 3/4/5.

**Fichiers à créer**
```
packages/api/src/modules/auth/providers/types.ts
packages/api/src/modules/auth/providers/protocol-adapter.ts
packages/api/src/modules/auth/providers/local/local-provider.ts
packages/api/src/modules/auth/providers/local/password.ts        // hash/verify scrypt (code existant déplacé)
packages/api/src/modules/auth/core/auth-core.ts
packages/api/src/modules/auth/core/identity-mapping.ts
packages/api/src/modules/auth/core/auth-state.ts                 // state/nonce/PKCE stores
packages/api/src/modules/auth/core/session-manager.ts            // SessionStore (§5.2)
packages/api/src/modules/auth/identity/auth-identity.service.ts
packages/api/src/modules/auth/registry/provider-registry.ts
packages/api/src/modules/auth/registry/seeds.ts                  // local (enabled) + oidc/saml/ldap presets (désactivés, SANS vendor-default)
packages/api/src/modules/auth/secrets/secret-encryption-service.ts
packages/api/src/modules/auth/mfa/totp.ts                        // code existant déplacé
packages/api/src/modules/auth/mfa/policy.ts                      // décision selon SecurityPolicy (stub)
packages/api/src/modules/auth/authorization/tenant-context.ts     // résolution tenant courant (inactif jusqu'à 5B)
packages/api/src/modules/auth/routes/guard.ts                    // registerAuthGuard (visage public inchangé)
packages/api/src/modules/auth/routes/auth.routes.ts              // login/MFA/me/password/bootstrap/needs-bootstrap
packages/api/src/modules/auth/routes/users.routes.ts             // users + membres (owner)
packages/api/src/modules/auth/index.ts                           // barrel : authService, registerAuthGuard/registerAuthRoutes, requireRole, currentUser
packages/api/src/modules/auth/__tests__/provider-registry.test.ts
packages/api/src/modules/auth/__tests__/identity-mapping.test.ts
packages/api/src/modules/auth/__tests__/local-provider.test.ts
packages/api/prisma/migrations/2026xxxx_generate_identity_model/...
packages/api/src/modules/auth/scripts/backfill-identity.mjs        // backfill idempotent
```

**Fichiers à modifier**
- `packages/api/src/modules/auth/service.ts` → perd la logique (déplacée local-provider + totp), devient **façade orchestrant auth-core** ; signatures publiques INTACTES.
- `packages/api/src/modules/auth/rbac.ts` → déplacé `authorization/rbac.ts` + ré-export ; résout rôle depuis membership tenant par défaut.
- `packages/api/src/modules/auth/crypto.ts` → remplacé par délégation à `SecretEncryptionService` ; `encryptSecret/decryptSecret` conservés.
- `packages/api/src/modules/auth/routes.ts` → décomposé en `routes/guard.ts`, `auth.routes.ts`, `users.routes.ts` ; comportements identiques.
- `packages/api/src/modules/registry/service.ts` : inchangé (utilise `encryptSecret` → façade).

**Fichiers à supprimer** : `modules/auth/routes.ts` (après split) ; `modules/auth/rbac.ts` (après déplacement, réexport ok). **Après** vérification imports (§2).

**Prisma (exact)** : `User(email?/name?/locale?/identities/memberships)`, `AuthIdentity`, `Tenant`, `Membership`, `AuthProvider(id cuid, kind, name, enabled, config)`, `PendingIdentity`. Le modèle `PendingIdentity` est préparé dès la Phase 2 ; le **workflow d'approbation effectif** (validation owner, création User + AuthIdentity + Membership) est livré en **Phase 5A**. Bonification : `User.role` conservé temporaire comme MIRROR.

**Migrations de données** :
- Étape 0 : créer **default tenant** (`name:"Default", slug:"default"`).
- Étape 1 : pour chaque user existant → `AuthIdentity{ providerId:"local", kind:"local", issuer:null, subject:"local:"+id, email, passwordHash conservé, mfaSecretEnc, mfaEnabled }` + `Membership{ user, defaultTenant, role=user.role }`.
- La migration copie les credentials existants (`passwordHash`, `mfaSecretEnc`, `mfaEnabled`) vers `AuthIdentity` **avant** la suppression des colonnes `User` (INSERT…SELECT, décision D.2).
- Étape 2 : seeds providers — `local` (enabled=true), presets oidc/saml/ldap (enabled=false, **aucun id "keycloak" par défaut**, correctif N°4).
- Backfill : script idempotent (`backfill-identity`), 2 exécutions = aucune création dupliquée (décision D.2).

**Interfaces TS** : §5.1-5.3 (contract + SessionStore + configs). `AuthResult` expose `userId` et `role` (décision D.8).

**Adapters** : local (actif) ; oidc/oauth2/saml/ldap = interfaces placées, **implémentation Phase 3/4/5A**.

**Routes** : inchangées (callers intactes). `registerAuthGuard` → core. La façade `authService` conserve ses signatures publiques et reste le point d'agrégation des routes ; `routes.ts` et `rbac.ts` sont conservés comme points d'entrée de compat (décision D.8).

**Frontend** : aucun changement visible.

**WebSocket** : inchangé.

**Bootstrap** : `/api/auth/bootstrap` ré-écrit → crée user + default tenant + membership owner ; **réponses identiques**.

**Tests à créer** : registry dispatch, local-provider (scrypt/MFA), identity-mapping (iss+sub, pending), migration backfill (idempotence, hash conservé).

**Tests de sécurité** : collisions identity (`@@unique`), pending sans création auto.

**Risques de régression** : principaux (réorg). Garde : **100% des tests existants verts sans retouche** ; fa.çade `authService` intacte.

**Critères d'acceptation** : tests existants verts sans modification ; migration backfill OK sur dump staging ; `npm run typecheck/test` ; e2e verts.

**Validations** : prisma:migrate + generate ; backfill script (2 exécutions = idempotent) ; `npm run test/typecheck` ; `npm run e2e`.

---

### PHASE 3 — Generic OIDC / OAuth2

**OBJECTIF** : adapters génériques OIDC + OAuth2 ; Keycloak = **IdP de test**; pending approval.

**Fichiers à créer**
```
packages/api/src/modules/auth/providers/oidc/oidc-provider.ts        // OIDCProvider générique
packages/api/src/modules/auth/providers/oauth2/oauth2-provider.ts    // OAuth2Provider générique (GitHub)
packages/api/src/modules/auth/core/sso-callback.ts                   // traitement callback → identity-mapping → session/pending
packages/api/src/modules/auth/routes/sso.routes.ts                   // oidc/oauth2 initiateLogin + callback
packages/api/src/modules/auth/__tests__/oidc-provider.test.ts
packages/api/src/modules/auth/__tests__/oauth2-provider.test.ts
packages/api/src/modules/auth/__tests__/sso-callback.test.ts
packages/api/src/modules/auth/__tests__/fixtures/oidc/...            // discovery + id_token signés (priv/pub key de test)
packages/api/src/modules/auth/__tests__/fixtures/oauth2/github/...   // mock http
tests/integration/docker-compose.keycloak.yml
tests/integration/keycloak-oidc.e2e.mjs
```

**Fichiers à modifier**
- `auth/routes/guard.ts` : `PUBLIC_PATHS` + `oidc/:id/login|callback`, `oauth2/:id/login|callback`, `GET /api/auth/providers`.
- `auth/registry/seeds.ts` : ajouter provider OIDC de test (issuer Keycloak) **comme configuration**, jamais comme défaut.
- `auth/core/identity-mapping.ts` : branchement SSO → `PendingIdentity` (création de la ligne, **pas de workflow**) ; l'approbation effective (validation owner → User + AuthIdentity + Membership) est en **Phase 5A** (correction N°20).

**Fichiers à supprimer** : aucun.

**Prisma** : aucun changement structurel (Phase 2 prévu). Seulement données : `AuthProvider` config réel + `AuthIdentity(oidc/oauth2)` à la 1re approbation ; `PendingIdentity` (table **déjà créée en Phase 2**, correction N°20 — remplie ici, workflow d'approbation en 5A).

**Migrations de données** : aucune structurelle.

**Adapters** : impl OIDC (openid-client) + OAuth2 (HTTP natif). Validation OIDC : issuer, audience, signature, nonce, state, PKCE, redirect URI, expiration, claims. Identifiant `iss+sub` (N°5). Décisions D.3 : discovery/JWKS en cache TTL 5 min (rotation sans redémarrage), échec de lecture → `sso_internal`, `acceptedClockSkewMs` (défaut 30 s) transmis à l'adapter. `AuthStateStore` est purgé de façon bornée (décisions D.1).

**Routes** : publiques initiateLogin/callback ; `GET /api/auth/providers` (liste id/name/kind, aucun secret).

**Frontend** : LoginPage = liste dynamique des providers actifs ; boutons SSO + champ local ; aucune liste codée en dur (N°17).

**WebSocket** : inchangé.

**Bootstrap** : inchangé.

**Tests à créer** : OIDC valid/invalid issuer/audience/signature/expired/nonce/state/PKCE/JWKS rotation ; OAuth2 code+state+exchange+userinfo+groupe+mapping+erreurs ; e2e Keycloak Docker (realm de test) ; **le même code OIDC fonctionne avec un 2ᵉ issuer (fixture Google) sans `if(provider)`**.

**Tests de sécurité** : pending (unknown identity → pending, pas création auto) ; map email jamais primaire.

**Risques de régression** : découverte réseau en CI → fixtures+mocks ; `If` vendor interdit (review negation).

**Critères d'acceptation** : e2e Keycloak passe ; double-issuer test vert sans code vendor ; tsc/lint/vitest/e2e verts.

**Validations** : `npm run test/typecheck` ; `docker compose -f tests/integration/docker-compose.keycloak.yml up -d` puis e2e.

---

### PHASE 4 — Generic SAML

**OBJECTIF** : protocole SAML 2.0 générique.

**Fichiers à créer**
```
packages/api/src/modules/auth/providers/saml/saml-provider.ts
packages/api/src/modules/auth/routes/saml.routes.ts                  // login / acs / metadata
packages/api/src/modules/auth/__tests__/saml-provider.test.ts
packages/api/src/modules/auth/__tests__/fixtures/saml/...            // SAMLResponse signées (valide + 7 cas négatifs)
packages/api/src/modules/auth/__tests__/fixtures/saml/keys/...       // cert private/public de TEST (jamais prod)
packages/api/src/modules/auth/core/saml-replay.ts                    // store assertions consommées (replay)
tests/integration/keycloak-saml.e2e.mjs                               // realm SAML Keycloak
```

**Fichiers à modifier** : `routes/guard.ts` (PUBLIC_PATHS + saml routes) ; `secrets/secret-encryption-service` (scope provider, cert chiffré).

**Fichiers à supprimer** : aucun.

**Prisma** : aucun changement.

**Migrations** : aucune.

**Adapters** : SAML (node-saml). Validations : signature, issuer, audience, conditions (NotBefore/NotOnOrAfter), destination, `InResponseTo`, replay (store), expiration, clock skew, certificate (chiffré), anti **signature wrapping**. S'y ajoutent les vérifications **manuelles obligatoires** (node-saml ne les effectue pas, décision D.3) : issuer de l'assertion == issuer IdP, `Destination`/`Recipient` == ACS, absent ou différent → rejet ; émet un audit `auth.saml.failed`.

**Routes** : `GET /api/auth/saml/:id/login`, `POST /api/auth/saml/:id/acs`, `GET /api/auth/saml/:id/metadata` (XML exposé).

**Frontend** : bouton provider (dynamique, N°17).

**WebSocket / Bootstrap** : inchangés.

**Tests à créer** : 7 cas négatifs obligatoires (signature wrapping, replay, invalid audience, invalid issuer, expired assertion, tampered assertion, wrong destination) + réponse malformée + cert invalide.

**Tests de sécurité** : voir ci-dessus (obligatoires §18).

**Risques de régression** : compat node-saml/Node 22 (vérif version à l'impl) ; XML parser sûr ; tests négatifs mandatory.

**Critères d'acceptation** : ACS refuse assertion invalide (401 + audit `auth.saml.failed`) ; e2e Keycloak SAML passe ; tests négatifs verts + fixtures.

**Validations** : `npm run test/typecheck` ; e2e SAML compose.

---

### PHASE 5A — Enterprise Authentication

**OBJECTIF** : gouvernance complète (sans remettre le modèle en cause).

**Fichiers à créer**
```
packages/api/src/modules/auth/providers/ldap/ldap-provider.ts        // ldapts (ou phase dédiée selon complexité — voir risque)
packages/api/src/modules/auth/sessions/user-session.store.ts         // impl UserSessionStore (+ Redis)
packages/api/src/modules/auth/sessions/session.service.ts
packages/api/src/modules/auth/policies/security-policy.service.ts
packages/api/src/modules/auth/identity/pending-approval.service.ts
packages/api/src/modules/auth/mfa/webauthn.ts                        // facteur (enrollment/verify)
packages/api/src/modules/auth/jwks/jwks.service.ts                   // hullbay signing keys + rotation
packages/api/src/modules/auth/routes/sessions.routes.ts
packages/api/src/modules/auth/routes/providers.routes.ts             // CRUD owner
packages/api/src/modules/auth/routes/pending.routes.ts               // approve/reject par tenant
packages/api/src/modules/auth/__tests__/session-store.test.ts
packages/api/src/modules/auth/__tests__/jwks.test.ts
packages/api/src/modules/auth/__tests__/security-policy.test.ts
packages/api/src/modules/auth/__tests__/webauthn.test.ts
packages/api/src/modules/auth/__tests__/providers-admin.test.ts
packages/api/src/modules/auth/__tests__/ldap-provider.test.ts         // mock ldap
packages/api/src/modules/auth/scripts/rotate-secrets.mjs
packages/web/src/pages/AdminProvidersPage.tsx
packages/web/src/pages/PendingApprovalsPage.tsx
packages/web/src/pages/SessionsPage.tsx
```

**Fichiers à modifier** : `guard.ts` (handshake → session-store), `loaders/websocket.ts` (session-manager), `core/session-manager.ts` (impl UserSession), `seeds.ts` (registry DB), `SecurityPolicy` model, frontend routing/API.

**Fichiers à supprimer** : aucun (User.role MIRROR reste jusqu'en 5B).

**Prisma** : `UserSession`, `SecurityPolicy`, `PendingIdentity`, tables WebAuthn credentials, `AuthProvider` persistés (config chiffrée).

**Migrations de données** : §4 étape « sessions backfill doux » (sessions actives sans row → créées à la 1re vérification ; refusées si `User` supprimé) ; JWKS seed depuis JWT_SECRET sans invalider token en vol ; `SecretEncryptionService.rotate()` (par scope). Décisions D.2 : keyring JWKS persisté sur disque (`JWKS_KEYRING_FILE`), `kid` inconnu rejeté (jamais de repli HS256 en dur), jeton d'audience `session` + `exp`, révocation = ensemble `revokedJtis` + persistance DB (le cache seul n'autorise jamais un jeton révoqué), `lastSeenAt` throttlé. En production, volume persistant monté pour le keyring (`ops_jwks`).

**Adapters** : LDAP (bind→search→attrs→bind user→groups→map ; stableAttr configurable : objectGUID/entryUUID ; TLS/timeouts/referrals/analucent comptes désactivés si info dispo) **— voir N°2, et décisions D.5** : placeholders `{{username}}`/`{username}`/`%u`, UAC en tableau, group search OpenLDAP, referrals ldaps + même domaine, `bindSecret` jamais cross-host, péréquation temporelle, filtre sans placeholder fail-closed, URL `ldap(s)://`. WebAuthn = **facteur**, pas provider — décisions D.4 : origine fail-closed, `userVerification:"required"`, parsing transports tolérant, garde anti-replay du compteur (401 + audit `counter_replay`), challenge par empreinte du token.

**Routes** : CRUD `/api/auth/providers` (owner), `/api/auth/sessions` + DELETE, `/api/auth/pending/:id/approve|reject` (tenant+rôle), test de connexion avant activation.

**Frontend** : admin providers (protocole→config, formulaire N°17), pending approvals, appareils connectés, passkeys, politique.

**WebSocket** : handshake session-store.

**Bootstrap** : inchangé.

**Tests à créer** : CRUD providers (injections invalides), révocation (token→inutile), politique MFA (owner SSO forcé), rotation JWKS (sans cut), WebAuthn fixtures, LDAP (bind/search/TLS/timeout/wrong creds/stable subject/mapping/groups/AD+OpenLDAP), sessions expiration/invalidation.

**Tests de sécurité** : aucun secret en clair (assertion test sur `AuthProvider.config`) ; police anti-énumération.

**Risques de régression** : révocation introduit dépendance DB à chaque vérif → couche Set mémoire + cache Redis (§D.2). Découpage **acté** (D.8) : **5A1 (providers+pendings+secrets) / 5A2 (sessions+policy+JWKS) / 5A3 (WebAuthn+LDAP)** ; LDAP intégré à 5A3, **aucune phase 5A3b dédiée**.

**Critères d'acceptation** : révocation effective ; politique MFA ; rotation sans cut ; LDAP sur union AD/OpenLDAP (si dipo de test) ou fixtures ; aucun secret en clair ; e2e verts.

**Validations** : `npm run prisma:migrate/generate` ; test(s) ; rotate-script idempotent ; `npm run e2e` ; assertion de non-clair.

---

### PHASE 5B — Multi-tenancy complète

**OBJECTIF** : isolation tenant totale, construite sur le modèle Phase 2.

**Fichiers à créer**
```
packages/api/src/modules/auth/authorization/tenant-guard.ts          // requireRole(min, ctx)
packages/api/src/modules/auth/authorization/tenant-resolver.ts       // tenant depuis sous-route/header/claim
packages/api/src/modules/auth/__tests__/tenant-isolation.test.ts     // MATRICE complète
packages/api/src/modules/auth/scripts/backfill-tenant.mjs            // data → tenant par défaut + dédup Cluster
tests/integration/tenant-isolation.e2e.mjs
packages/web/src/components/TenantSwitcher.tsx
```

**Fichiers à modifier** (52 sites tenant-scopables revus **un par un**, ownership/résolution/anti-fuite/test)
- `projects` (14 sites) ; `clusters` (15) ; `servers` (8) ; `registry` (8) ; `reconciler` (7) ; `observability` (4) ; + routes. Chaque query gagne un filtre tenant explicite — **aucun ajout mécanique**.
- `blogs.handshake` : WS rooms scoped ; `join`/`subscribe:logs` vérifient appartenance.
- `AuditLog` : `tenantId`.

**Fichiers à supprimer** : colonne `User.role` (après vérification usages, §13, N°12). *Destructive délibérée : après confirmation.* Respecter l'étape 8 de §2.

**Prisma** : `Cluster.@@unique([tenantId, name])` (dédup), `Server/Registry/Settings/AuditLog/Project` +`tenantId`, `AuthProvider.tenantId String?` (association provider→tenant : chaque tenant dispose de ses propres providers ; `null` = provider global, disponible pour tous les tenants — décision explicite pour les presets locaux/SSO transverses), `SecurityPolicy` par tenant (§2 V4 : `@@unique([tenantId])` au lieu du singleton), retrait `User.role`.

**Isolation providers (décision D.7)** : `tenantId null` = provider global (presets locaux/SSO transverses), visible par tous les tenants ; les mutations des providers globaux sont réservées au tenant par défaut (404 pour tout autre tenant) ; un tenant ne voit pas les providers d'un autre tenant.

**Migrations de données** : étape 5 (§15 V2) : data → tenant par défaut ; doublons Cluster résolus avant la contrainte ; rôles MIRROR migrés vers membership (déjà là depuis Phase 2) puis colonne supprimée.

**Interfaces TS** : `requireRole(min, ctx)` ; `TenantContext` résolu par guard.

**Routes** : sous-routes `/:tenantSlug/...` (ou header configuré) ; endpoints membership par tenant.

**Frontend** : switcher tenant, routes `/:tenantSlug/...`, rôles par tenant.

**WebSocket** : isolation (§12).

**Tests à créer** : MATRICE d'isolation (obligatoire §18) :
```
Tenant A ne lit pas les données de B
Tenant A ne mute pas B
Tenant A ne référence pas les IDs de ressources B
Tenant A ne contourne pas le scope via routes alternatives
WebSocket : pas de room inter-tenant
Audit : isolation des logs
```

**Tests de sécurité** : 403 systématique hors membership ; aucune fuite d'IDs croisés.

**Risques de régression** : chaînage d'IDs ≈ porte de fuite nº1 → review + tests par module ; contrainte Cluster = migration risque → dédup/mastérisation en amont ; suppression User.role = decisive → validée par test de §2.

**Critères d'acceptation** : matrice isolation au vert sur chaque module ; migration dump staging ; zéro fuite ; e2e existants verts.

**Validations** : `npm run prisma:migrate/generate` ; matrix e2e ; backend smoke ; `npm run test/typecheck` ; e2e web.

---

## 15. Chronologie et « ce qui n'est PAS fait avant »

```
Phase 1  →  Phase 2  →  Phase 3  →  Phase 4  →  5A1  →  5A2  →  5A3  →  5B
(hardening) (foundation) (OIDC/OAuth2) (SAML)  (providers (sessions (webauthn (tenant)
                                                 +pendings) +policy   +LDAP)
```

**Ce qui NE doit PAS être implémenté AVANT la phase indiquée** :
- Avant Phase 2 : **aucune** modification de modèle User/AuthIdentity/Membership/Tenant ; pas de réorg `auth/`.
- Avant Phase 3 : pas d'adapter OIDC/OAuth2 ; pas d'e2e Keycloak.
- Avant Phase 4 : pas d'adapter SAML ; pas de fixtures SAML.
- Avant 5A : pas de UserSession/politique/JWKS/pending-admin/WebAuthn/LDAP effectif.
- Avant 5B : pas de tenant-scoping des 52 sites ; pas de suppression de `User.role`.
- **JAMAIS** : `User.provider`, `email→User` comme identifiant, `AUTH_MODE`, `if(provider==="keycloak")`, `AuthProvider.id @default("keycloak")`, secrets en clair, WebAuthn comme AuthProvider, `AWSProvider`, JWT comme seule source de vérité après 5A.

---

## 16. Rate limiting (détail N°16)

Clé composite, ordre de priorité à l'implémentation :
```
IP
+ account/login identifier (quand présent — p.ex. email tenté)
+ endpoint
+ fenêtre glissante + backoff exponentiel
```
- anti-énumération : même réponse (statut + délai) que le compte existe ou non ; le compteur ne précède/reShift rien qui révèle l'existence.
- Configurable via `SecurityPolicy` (seuils, fenêtres, backoff) en Phase 5A.
- Inactif sur routes non-auth ; actif login/mfa/*/password/bootstrap/needs-bootstrap.

---

## 17. Détail par protocole (interfaces/config/tests)

### 17.1 OIDC (adapter)
```
authorization + state + nonce + PKCE → callback → échange → id_token validation
(iss, aud, signature via discovery/JWKS, expiration, claims) → ExternalIdentity{iss, sub}
```
Tests : §18 (OIDC) obligatoires.

### 17.2 OAuth2 (adapter)
```
authorization + state → callback → code → access_token → userinfo/API → mapping → identity
```
Tests : code+state, exchange, userinfo, erreurs, mapping, groups.

### 17.3 SAML (adapter)
```
metadata SP → AuthnRequest (RelayState) → IdP → SAMLResponse ACS → validations
(signature, issuer, audience, destination, conditions, InResponseTo, replay, expiration, clock skew, anti-wrapping)
```
Tests : §18 (SAML) → 7+ cas négatifs.

### 17.4 LDAP/LDAPS (adapter — modèle d'exécution propre, N°2)
```
bind (service account) → search user (searchFilter sur base DN)
→ retrieve attributes → bind utilisateur (ou verify) → resolve groups → map identity
```
- **subject stable** : `stableAttr` configurable (`objectGUID` AD / `entryUUID` OpenLDAP / autre) — **search attribute ≠ identity attribute**.
- reload config : `url, tlsOptions(rejectUnauthorized, ca), bindDn, bindSecret(chiffré), searchBase, searchFilter, groupSearchBase, groupFilter, attrMap(username/email/name/groups), timeoutMs, handleReferrals`.
- Cas AD à prévoir : bind user, service account, base DN, user/group filter, attributs configurables, LDAPS, validation TLS/certs, timeouts, erreurs connexion, comptes désactivés/verrouillés si dispo, referrals, mapping.
Tests : §18 (LDAP) obligatoires.

### 17.5 Pending identity / approbation (tenant-aware, N°15, §6)
```
Unknown identity → PendingIdentity(status=pending, requestedForTenantId?)
  → owner approve {tenantId, role} → User + AuthIdentity + Membership(tenant, role)
```
- Phase 2-5A : tenant par défaut si non spécifié ; modèle autorise déjà le scope tenant.

---

## 18. Wording produit & documentation (N°19)

Formulations autorisées :
> **Hullbay supports standards-based identity providers through OIDC, OAuth2, SAML 2.0 and LDAP/LDAPS.**
> **Any provider compatible with a supported protocol can be configured without implementing a provider-specific integration.**

Interdites : « Hullbay supports *any* Identity Provider » sans précision de protocole.

Sponsor min doc : guide « Add authentication provider » (protocol → configuration → test → activate), formulaires N°17 (Issuer/Client ID/Client Secret/Scopes/Claims mapping ; Metadata/Entity ID/Certificate/ACS ; Server/Base DN/Bind/User filter/Group filter/Attribute mapping).

---

## 19. Tests obligatoires par protocole (N°18 résumé)

| Domaine | Cas obligatoires |
|---|---|
| Identity | mapping, collision (unique), issuer+subject, plusieurs identités/user, email change, linking |
| OIDC | valid token, invalid issuer/audience/signature, expired, nonce, state, PKCE, JWKS rotation |
| OAuth2 | authorization code, state, token exchange, userinfo, erreurs, mapping |
| SAML | signature, issuer, audience, destination, expiration, replay, InResponseTo, signature wrapping, cert invalide, réponse malformée |
| LDAP | bind, search, authentication, TLS, timeout, wrong credentials, user mapping, stable subject mapping, groups, AD/OpenLDAP scenarios |
| Multi-tenant | A↛B lecture/écriture (matrice §14/Phase 5B) |

---

## 20. Critères de validation globaux
- tsc + lint verts à chaque phase ; vitest verts ; e2e verts ; tests existants verts **sans modification** ; migrations appliquées sur dump staging ; aucun saut de phase.
- après 5A : assertion `AuthProvider.config` sans secret en clair ; révocation fonctionnelle ; rotation sans cut.
- après 5B : matrice d'isolation verte ; `User.role` supprimé.

---

## 21. Décisions actées

Ce **Plan d'Implémentation V4** est le référentiel décisionnel (§D) et intègre toutes les corrections (§1-§20) :
- AuthProvider.sans défaut vendor ; AuthIdentity iss+sub ; LDAP distinct ; AWS protocol-only ; Keycloak option config ; SecretEncryptionService séparé ; SessionStore abstraite ; JWT/JWKS distincts ; WebAuthn facteur ; RBAC transition→cible avec suppression User.role en 5B ; pending tenant-aware ; rate-limit composite anti-énumération ; UI protocole-first ; wording standard ; tests par protocole obligatoires ; phases séquentielles avec commandes de validation réelles.

**Zones précédemment ouvertes — décisions actées** :
1. **Timing LDAP** : LDAP intégré à la **Phase 5A3** (avec WebAuthn) ; aucune phase 5A3b dédiée (D.8).
2. **Découpe 5A** : **actée** — 5A1 (providers+pendings+secrets), 5A2 (sessions+policy+JWKS), 5A3 (WebAuthn+LDAP).
3. **`User.role`** : **suppression confirmée en Phase 5B** (destructive, après recensement des usages §2, en fin de phase).

Toute décision ultérieure est annexée à ce document (section D) avant implémentation. Aucun code n'est modifié hors périmètre d'une phase décrite ici.