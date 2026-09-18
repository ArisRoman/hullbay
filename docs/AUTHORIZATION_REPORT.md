# AUTHORIZATION REPORT — V1 (Phase 0 discovery + plan)

Rapport d'état du système d'autorisation Hullbay


---

## 1. Current State

L'authentification a été refaite (Phases 2→5B) : `User`, `Tenant`, `Membership`, `AuthIdentity`,
`AuthProvider`, `PendingIdentity`, `UserSession`, `SecurityPolicy`, JWT avec claim `tenantId`,
header `x-tenant-id`, WebSocket rooms par tenant. 716 tests verts, typecheck OK.

L'autorisation, elle, est **toujours un RBAC à 3 rôles codés en dur** :

```
guard.ts (authN + MFA + cross-tenant)  →  requireRole(min)  →  scoping tenant manuel dans les routes
```

- `requireRole(min)` : `RANK = { viewer: 0, operator: 1, owner: 2 }`, rôle inconnu → rang 0
  (fail-closed). 16 usages dans 15 fichiers.
- Re-résolution cross-tenant : si le header résout un tenant ≠ token, le rôle est re-résolu
  depuis `Membership` (authorization/rbac.ts).
- Scoping tenant : `clusterService.get(id, tenantId)`, `getProjectGraph(id, tenantId)`,
  `ensureClusterInTenant` (secrets), `ensureTenantScoped` (reconciler).

## 2. Resource Inventory (réalité Prisma)

| Ressource | Colonnes auth | Parent | Notes |
|---|---|---|---|
| `Tenant` | — | racine | slug unique, `tenant-default` défaut |
| `User` | `role` (MIRROR legacy) | — | email = attribut seulement |
| `AuthIdentity` | — | User | kind local/oidc/oauth2/saml/ldap |
| `Membership` | `role` (owner/operator/viewer) | User×Tenant | **vraie source du rôle** |
| `Cluster` | tenantId | Tenant | `@@unique([tenantId, name])` |
| `Server` | tenantId | Cluster | clé SSH chiffrée |
| `Project` | tenantId | Cluster | graph via Node/Edge |
| `Node` | — | Project | container/network/volume/gateway |
| `Edge` | — | Project | |
| `RegistryCredential` | tenantId | Tenant | token chiffré |
| `Secret` | **aucune table** | — | vit dans Docker seulement (labels) |
| `Settings` | tenantId | Tenant | domaine |
| `AuthProvider` | tenantId? (null=global) | Tenant | |
| `SecurityPolicy` | tenantId | Tenant | MFA/session, pas autorisation |
| `AuditLog` | tenantId? (nullable) | Tenant | |
| `UserSession`, `PendingIdentity`, `WebauthnCredential`, `SystemInfo`, `SystemUpdate` | — (souvent global) | — | |

**Absents** : `Role`, `Permission`, `Team`, `Scope`, `Policy` — rien à migrer, tout à créer.

## 3. Resource Relationships (réalité)

```
User ─< Membership >─ Tenant
AuthIdentity ─User
Tenant ─< Cluster → Server
                 └→ Project → Node → Edge
Tenant ─< RegistryCredential
Tenant ─< Settings (1:1)
Tenant ─< AuthProvider (nullable tenant)
Tenant ─< SecurityPolicy (1:1)
Tenant ─< AuditLog (nullable tenant)
```

`Secret` : pas d'entité — API `clusters/:id/secrets`, valeurs write-only jamais renvoyées.

## 4. Current Authorization Mechanisms

| Mécanisme | Lieu | Portée |
|---|---|---|
| AuthN JWT + MFA gate | routes/guard.ts | global `/api/*` |
| Cross-tenant header vérifié (assertUserInTenant) | guard.ts:72-80 | 403 tenant_forbidden |
| `requireRole(viewer/operator/owner)` | authorization/rbac.ts:25 | 16 sites |
| Scoping tenant service-level | `clusterService.get(id,tenantId)`, `getProjectGraph(id,tenantId)`, `ensureClusterInTenant`, `ensureTenantScoped` | dispatché |
| Session ownership / switch-tenant | sessions.routes.ts, auth.routes.ts | self |
| WebSocket : handshake JWT, room `tenant:<id>`, join validé | loaders/websocket.ts | global/tenant |
| fallback `io.emit` global | websocket.ts:135 | events système (updates/auth/user) uniquement |

**UI** : `useMe.can(min)` + NAV table AppLayout.tsx:36-49 ; seul en-page redirect =
AdminProvidersPage. Pas de `can()` sur delete/deploy/rebuild dans plusieurs pages → boutons
visibles mais 403 serveur (enforcement serveur seul fait foi).

## 5. Current Role/Permission Matrix (réalité exhaustive)

- **owner** : clusters CRUD+delete, servers provision/remove/role, registry CRUD, settings
  domain, updates apply/rollback/channel, users CRUD+role, providers admin, pendings
  approve/reject, tenants liste, prune **apply**.
- **operator** : projects CRUD+graph mutations, deploy/destroy/rebuild, secrets CRUD,
  prune dry-run, audit lecture.
- **viewer** : lecture projets/health/drift/placement/plan/preview, sessions self.
- **auth-only (aucun requireRole)** : `GET /projects`, `GET /projects/:id`,
  `GET /reconciler plan + preview` (tout utilisateur connecté).
- **Hors guard `/api/`** : `GET /docs` (swagger), `GET /health/docker` (info engine).
- **Jobs globaux sans auth** (par design) : prune-orphans (dry≠apply), auto-scaler,
  cluster-health, reconcile-drift (lecture), updater auto-finalize.

## 6. Authorization Gaps

1. 3 rôles codés en dur partout (enum TS, RANK) — aucun rôle personnalisable.
2. Zéro granularité : operator ⇒ projet + secrets + audit + prune.dry ensemble.
3. Zéro scope ressource : `project.deploy` = TOUS les projets du tenant.
4. Rôle = string `Membership.role` — pas d'entité Role.
5. Pas de Teams, pas de groupes IdP.
6. Pas d'ABAC/Policy (SecurityPolicy = MFA/session seulement).
7. Pas d'audit des refus d'accès (seulement les actions).
8. `User.role` mirror vivant (double source temporaire).
9. Rôle claim signé dans JWT → stale si membership change (re-résolu seulement si
   header tenant ≠ token tenant).
10. Routes lecture viewer : `requireRole("viewer")` = "connecté", pas de permission
    `x.read` exprimable.

## 7. Target Architecture

```
User ─ memberships → Tenant
  ├─ Direct Roles
  └─ Team memberships → Team → Role (+scope)
Role → Permissions → Resource Scope → @policy → ALLOW / DENY
```

- Réutilise `User/Membership/Tenant` existants (pas de modèle parallèle).
- `Membership` → relation `roleId → Role` à terme (remplace la string).
- **Presets explicites** : Owner/Operator/Viewer seedés par tenant, rôles normaux
  modifiables/clonables. `Root` = rôle système protégé, non-assignable via UI.
- **Engine** : `authorization.require({ subject, action, resource, context })` / `.can()`.
  Une seule abstraction pour routes, jobs (re-résolution serveur), WebSocket, UI.

## 8. Role Model

- Table `Role` (tenantId, name, system?, preset template).
- Presets `owner/operator/viewer` générés depuis la matrice §5, tous explicites (pas
  d'héritage de permissions).
- `Root` système protégé : suppression/renommage/édition bloqués, protection en DB.

## 9. Permission Model

- String libre `resource.action` (données, pas enum TS).
- Catalogue seedé issu du code réel (voir §semence).
- `RolePermission` = Role × Permission (+ scope).

## 10. Team Model

- `Team` (tenantId, name), `TeamMember` (user×team), `TeamRole` (team×role + scope).
- Scope = JSON `{ resourceType, resourceId? }` — null = toute la classe dans le tenant.

## 11. Resource Scope Model

- Bind Team-Role porte scope JSON + index générés.
- Résolution : permission + scope correct (ressource appartient au tenant) → ALLOW.
- Pas de scope implicite hiérarchique (cluster.manage ∤ project.deploy).

## 12. Policy / ABAC Model

- Rules JSON (subject/action/resource/tenant/team/conditions). Phase postérieure R6,
  architecture prévue dès R1. **Deny domine, default deny.**

## 13. Tenant Integration

- Toute permission résolue DANS le tenant courant (header > token claim > défaut).
- Isolation : permission tenant A ne vaut jamais en tenant B.
- Dépend des 52 sites déjà scopés en 5B (état vert).

## 14. IdP Group Integration

- Mapping explicite : groupe IdP → Team → Role → Scope. Administrable, auditable.
- Dépend : adapters auth exposant les groupes (OIDC/SAML/LDAP — à confirmer côté auth,
  non vérifié dans ce rapport).

## 15. Migration Strategy

1. **R1** : migration Prisma additive — `Role`, `RolePermission`, `Team`, `TeamMember`,
   `TeamRole`, `Membership.roleId?`. Colonne `role` shadow conservée (compat R4).
2. **R4** : compat shim — les 16 `requireRole` via moteur, comportement identique,
   matrice §5 re-testée module par module.
3. **R8** : drop `User.role`, `Membership.role`, swap des presets, suppression du shim.

## 16. Authentication Dependencies

- Auth 5B livré → **aucun blocage R1-R4** (tenantId claim, membership source, WS rooms,
  backfill, e2e existants).
- Points de frottement : guard MFA (mfaRequireRoles lit `role` string), `switch-tenant`
  re-signe le token, `resolveRoleForUser` devient input du moteur.
- R7 (IdP groups) dépend de l'exposition des groupes par les adapters.

## 17. Implementation Phases

| Phase | Contenu | Raccorde rabc |
|---|---|---|
| **R0** | discovery (ce rapport) | §34 |
| **R1** | migration Prisma additive + presets seed idempotents | §18 |
| **R2** | engine `require()`/`can()` — repositories abstraits (0 Prisma dans le moteur), cache court, fail-closed | §19 |
| **R3** | resolver subject (memberships + teams + direct) + scope + effective-permissions | §19/25 |
| **R4** | brancher les 16 `requireRole` → moteur (+ audit DENY) | §20/26 |
| **R5** | API admin : CRUD roles/teams/scopes, clones, rôles système, effective perms | §21/25 |
| **R6** | policies JSON | §22 |
| **R7** | IdP groups → Team mapping | §23 |
| **R8** | migration finale : drop mirror, swap shim, cleanup | §24 |

## 18. Parallelization / Dependencies

- Auth déjà 5B : R1-R4 en séquence, R2 testable seul (repositories abstraits).
- R6/R8 chevauchables après R5. R7 seul blocage externe (adapters groupes).

## 19. Testing Strategy

- R2 : unitaires moteur sans Prisma — default deny, permission directe, via rôle, via team,
  multi-rôles, scope bon/mauvais, tenant bon/mauvais, ressource inexistante, policy
  allow/deny/conflit, rôle supprimé, rôle système (matrice §31 rabc).
- Chaque phase : régression — matrice §5 doit rester identique.
- e2e d'isolation tenant existant réutilisé (tenant-isolation.e2e.mjs).

## 20. Security Considerations

- Default deny. Enforcement serveur seul. Isolation tenant + ressource (scopes).
- Secrets granulaire. Ops destructives explicitement protégées (auditées).
- `require()` AVANT toute action sensible.
- Pas de dépendance fournisseur dans le moteur.

## 21. Open Architectural Decisions (Tranchées)

1. **Presets explicites**, pas d'héritage hiérarchique. Root = rôle système protégé.
2. **Scope = JSON** `{resourceType, resourceId?}` + index (pas de tables normalisées).
3. **FK `Membership.roleId` dès R1**, shadow drop R8.
4. **Audit TOUS les refus** (DENY → AuditLog : subject/action/resource/scope/reason).
5. **Re-résolution serveur** à chaque `require()` (pas de réveil de sessions au change).
6. Rapport matérialisé dans `docs/AUTHORIZATION_REPORT.md`.
7. Teams : scope porte sur le bind Team-Role (une entrée par scope).
8. Audit lecture : conservé operator aujourd'hui (défaut proposé viewer à confirmer).
9. Root : rôle système protégé, owner n'est PAS auto-Root.
10. JWT role stale → re-résolution serveur (résolu via décision 5).
11. IdP groups : adapters — à confirmer côté auth (non vérifié ici).
12. `/docs` + `/health/docker` hors guard : laissés public (info, non autorisation).

## Semence Catalogue Permission (issue du code réel)

`cluster.{read,create,update,delete}` · `server.{read,create,delete,promote,demote}` ·
`project.{read,create,update,delete,deploy,destroy,rebuild}` ·
`graph.node.{create,update,delete}` · `graph.edge.{create,update,delete}` ·
`secret.{read,set,delete}` · `registry.{read,set,delete}` ·
`settings.domain.{read,set}` · `audit.read` · `update.{check,apply,rollback,channel}` ·
`user.{read,create,update,delete}` · `provider.{read,create,update,delete,test}` ·
`pending.{read,approve,reject}` · `prune.{dry,apply}` · `logs.read`

## Mapping presets (équivalence exacte §5)

- **Viewer** : lecture (project.read, plan/preview, logs.read ; audit.read défaut à décider)
- **Operator** : preset viewer + project/graph/secret CRUD + deploy/destroy/rebuild +
  prune.{dry} + audit.read
- **Owner** : preset operator + cluster/server/registry/settings/user/provider/pending/update
  + prune.apply