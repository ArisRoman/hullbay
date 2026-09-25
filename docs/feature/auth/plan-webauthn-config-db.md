## PLAN D’IMPLÉMENTATION — Configuration WebAuthn en base + garde-fous sur les protocoles  
## 0. Objectif  
Refactorer WebAuthn afin que sa configuration RP soit stockée dans Settings, avec une portée par tenant, au lieu d’être fournie par des variables d’environnement.  
En parallèle, empêcher l’activation des protocoles d’authentification dépendants d’un domaine lorsque le tenant concerné ne possède aucun domaine public configuré.  
L’implémentation doit préserver tous les contrats d’authentification existants ainsi que tous les tests actuellement passants.  
**État de référence**  
D’après la recette v1.3.0-beta.2 :  
* API : 744/744 tests PASS  
* Authentification : 276/276 tests PASS  
* TypeScript : 0 erreur  
* Campagne WebAuthn prod-like : non exécutable car WEBAUTHN_* n’était pas configuré  
* Settings est déjà scoped par tenant  
* Le domaine n’est persisté qu’après succès de la configuration Caddy  
**Ne pas modifier les comportements d’authentification qui ne sont pas concernés par cette évolution.**  
  
⸻  
  
## 1. Règles d’architecture  
## 1.1 Une seule source de vérité  
Après cette évolution, les champs suivants deviennent la source de vérité pour WebAuthn :  
```
Settings.domain
Settings.webauthnEnabled
Settings.webauthnOrigin
Settings.webauthnRpId
Settings.webauthnRpName

```
Les variables suivantes ne doivent plus être utilisées comme source de configuration WebAuthn :  
```
WEBAUTHN_ORIGIN
WEBAUTHN_RP_ID
WEBAUTHN_RP_NAME

```
Les variables d’environnement restent réservées aux secrets maîtres et à la configuration d’installation/runtime qui doit réellement rester hors base.  
  
⸻  
  
## 1.2 Le contexte tenant doit être explicite  
La configuration WebAuthn doit toujours être résolue à partir du tenant effectif.  
Ne pas déduire le tenant uniquement à partir du userId.  
API cible :  
```
getWebauthnConfig({
  tenantId,
  clientOrigin,
})

```
Le tenantId doit provenir du mécanisme de résolution du tenant déjà présent dans l’application.  
Cette règle est importante car un même utilisateur peut appartenir à plusieurs tenants.  
  
⸻  
  
## 2. Phase 1 — Modèle Prisma / Settings  
Étendre le modèle Settings existant :  
```
model Settings {
  id                String   @id @default(cuid())
  domain            String?
  webauthnEnabled   Boolean  @default(false)
  webauthnOrigin    String?
  webauthnRpId      String?
  webauthnRpName    String   @default("Hullbay")
  updatedAt         DateTime @updatedAt
  tenantId          String   @unique
  tenant            Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
}

```
Créer une migration Prisma.  
La migration doit être rétrocompatible :  
* les lignes Settings existantes doivent rester valides ;  
* WebAuthn doit être désactivé par défaut ;  
* les domaines existants ne doivent pas être modifiés ;  
* aucune configuration WebAuthn existante ne doit être écrasée silencieusement.  
Ne pas créer de modèle WebAuthnConfig séparé pour cette version.  
  
⸻  
  
## 3. Phase 2 — Service Settings  
Étendre SettingsService.  
## 3.1 Lecture de la configuration WebAuthn  
Ajouter :  
```
getWebauthn(tenantId)

```
La méthode doit récupérer les paramètres du tenant et, si nécessaire, créer la ligne Settings.  
Retour attendu :  
```
{
  enabled: boolean
  origin: string | null
  rpId: string | null
  rpName: string
}

```
Aucun secret ne doit être retourné : la configuration RP WebAuthn est une configuration publique.  
  
⸻  
  
## 3.2 Modification de la configuration WebAuthn  
Ajouter :  
```
setWebauthn(tenantId, input)

```
Entrée :  
```
{
  enabled: boolean
  origin?: string
  rpId?: string
  rpName?: string
}

```
## Règles sur   
```
origin

```
Si origin est fourni explicitement :  
* doit être une URL HTTPS en production ;  
* ne doit pas contenir de path, query ou fragment ;  
* doit être normalisé avant stockage.  
Si origin n’est pas fourni :  
```
https://<Settings.domain>

```
doit être utilisé lorsqu’un domaine existe.  
En production, si l’utilisateur tente d’activer WebAuthn alors qu’aucun domaine n’est configuré :  
```
{
  "code": "domain_not_configured"
}

```
doit être retourné.  
Les origines HTTP localhost restent autorisées en développement/test conformément au comportement local WebAuthn existant.  
## Règles sur   
```
rpId

```
Si aucun rpId n’est fourni :  
```
hostname(origin)

```
doit être utilisé.  
Si un rpId est explicitement fourni, vérifier qu’il est compatible avec l’origin.  
La gestion de plusieurs domaines/RP IDs n’est pas dans le périmètre de cette version.  
## Règles sur   
```
rpName

```
Valeur par défaut :  
```
Hullbay

```
  
⸻  
  
## 4. Phase 3 — Migration du service WebAuthn  
Modifier :  
```
packages/api/src/modules/auth/mfa/webauthn.ts

```
L’implémentation actuelle lit :  
```
WEBAUTHN_ORIGIN
WEBAUTHN_RP_ID
WEBAUTHN_RP_NAME

```
Cette dépendance doit être supprimée en production.  
Nouvelle API :  
```
async function getWebauthnConfig({
  tenantId,
  clientOrigin,
})

```
Flux :  
```
tenantId
   ↓
Settings
   ↓
webauthnEnabled
webauthnOrigin
webauthnRpId
webauthnRpName
   ↓
Configuration WebAuthn

```
En production :  
```
webauthnEnabled != true
        ↓
webauthn_not_configured

```
ou :  
```
webauthnOrigin absent
        ↓
webauthn_not_configured

```
Le comportement doit rester **fail-closed**.  
  
⸻  
  
# 5. Validation de   
```
clientOrigin

```
Les routes WebAuthn transmettent déjà l’Origin du navigateur aux fonctions WebAuthn.  
Conserver ce comportement.  
En production, lorsque clientOrigin est fourni :  
```
clientOrigin === origin configuré

```
doit être obligatoire.  
Une différence doit être rejetée.  
Ne jamais considérer l’Origin envoyé par le navigateur comme étant la configuration de référence.  
La configuration en base est la source de vérité.  
  
⸻  
  
## 6. Comportement développement / test  
Conserver le comportement local existant pour :  
```
NODE_ENV=development
NODE_ENV=test

```
Les origines localhost actuellement supportées doivent continuer à fonctionner :  
```
http://localhost:5273
http://localhost:3000
http://127.0.0.1:5273
http://127.0.0.1:3000

```
Ce fallback ne doit jamais être disponible en production.  
La production doit rester fail-closed.  
  
⸻  
  
## 7. Mise à jour de tous les appels WebAuthn  
La résolution de configuration devenant asynchrone :  
```
getWebauthnConfig(...)

```
devient async.  
Mettre à jour les quatre chemins :  
```
register/options
register/verify
auth/options
auth/verify

```
Le comportement fonctionnel existant des routes doit rester inchangé en dehors de la nouvelle résolution de configuration.  
Préserver notamment :  
* l’isolation des challenges ;  
* les pending tokens ;  
* les sessions ;  
* le rate limiting ;  
* la persistance des credentials ;  
* les événements d’audit ;  
* la sérialisation des erreurs.  
Ne pas profiter de cette modification pour refactorer ces mécanismes.  
  
⸻  
  
## 8. Phase 4 — API Settings WebAuthn  
Étendre les routes Settings existantes.  
Les routes Settings étant déjà réservées au propriétaire, conserver cette politique d’autorisation.  
Ajouter :  
```
GET /api/settings/webauthn

```
et :  
```
POST /api/settings/webauthn

```
Les deux endpoints doivent utiliser le tenant effectif de la requête.  
Ne jamais utiliser silencieusement DEFAULT_TENANT_ID lorsqu’un contexte tenant explicite est disponible.  
Réponse :  
```
{
  "enabled": false,
  "origin": null,
  "rpId": null,
  "rpName": "Hullbay"
}

```
  
⸻  
  
## 9. Phase 5 — Garde-fou sur les providers dépendants d’un domaine  
Modifier :  
```
packages/api/src/modules/auth/routes/providers.routes.ts

```
Protocoles dépendants d’un domaine :  
```
const DOMAIN_DEPENDENT_PROTOCOLS = new Set([
  "oidc",
  "oauth2",
  "saml",
])

```
Ne pas inclure :  
```
ldap
local

```
LDAP et l’authentification locale doivent rester utilisables sans domaine public.  
  
⸻  
  
## 9.1 Création d’un provider  
Avant de persister un provider activé :  
```
if (
  production &&
  body.enabled &&
  DOMAIN_DEPENDENT_PROTOCOLS.has(body.kind)
) {
  const settings = await settingsService.get(effectiveTenantId)

  if (!settings.domain) {
    return 400 domain_not_configured
  }
}

```
Le contrôle doit être effectué avant la persistance.  
  
⸻  
  
## 9.2 Mise à jour d’un provider  
Ne pas tester uniquement :  
```
body.enabled === true

```
Calculer l’état final :  
```
const finalEnabled =
  body.enabled !== undefined
    ? body.enabled
    : row.enabled

```
Puis appliquer le garde-fou.  
Cela évite qu’un PUT partiel permette de conserver ou d’atteindre un état invalide.  
  
⸻  
  
## 9.3 Portée du provider  
La recherche du domaine doit correspondre à la portée réelle du provider.  
**Provider tenant-scoped**  
Si :  
```
provider.tenantId != null

```
utiliser :  
```
provider.tenantId

```
pour récupérer Settings.  
**Provider global**  
Si :  
```
provider.tenantId == null

```
utiliser explicitement la portée globale/d’installation définie par l’architecture actuelle.  
Ne jamais utiliser arbitrairement le tenant de la requête pour valider un provider global.  
Cette règle doit être clairement documentée dans le code.  
  
⸻  
  
## 10. Interaction avec l’anti-lockout existant  
Ne pas supprimer ni affaiblir la protection existante empêchant la désactivation du dernier provider actif.  
Le nouveau contrôle concerne uniquement l’activation de protocoles dépendants d’un domaine.  
Ordre recommandé :  
```
résolution du provider
        ↓
calcul de l'état final
        ↓
validation de la portée / ownership
        ↓
vérification du domaine
        ↓
anti-lockout existant
        ↓
validation de la configuration provider
        ↓
persistance
        ↓
reload du provider registry

```
Pour une création :  
```
validation
   ↓
garde-fou domaine
   ↓
persistance

```
  
⸻  
  
## 11. Phase 6 — Suppression des variables WebAuthn  
Supprimer toute utilisation et génération de :  
```
WEBAUTHN_ORIGIN
WEBAUTHN_RP_ID
WEBAUTHN_RP_NAME

```
dans :  
```
.env.template
docker-compose.yml
docker-compose.prod.yml
install.sh

```
Point important : install.sh génère actuellement la configuration WebAuthn à partir de PUBLIC_HOST.  
Cette logique doit disparaître.  
Après cette évolution :  
```
PUBLIC_HOST

```
peut continuer à être utilisé pour l’installation, Caddy et la configuration publique.  
Mais il ne doit plus exister de chaîne :  
```
PUBLIC_HOST
   ↓
WEBAUTHN_*

```
  
⸻  
  
## 12. Comportement de l’installation  
L’installateur ne doit plus générer de configuration WebAuthn.  
Le flux devient :  
```
PUBLIC_HOST
   ↓
configuration publique / Caddy
   ↓
Settings.domain
   ↓
administration Hullbay
   ↓
configuration WebAuthn

```
Si une configuration WebAuthn automatique après installation est souhaitée ultérieurement, elle devra passer par une initialisation explicite de la base ou un mécanisme de bootstrap, et non par des variables d’environnement.  
Pour cette version, privilégier :  
```
domaine configuré
   ↓
Settings
   ↓
WebAuthn
   ↓
origin préremplie avec https://domain
   ↓
activation explicite par l'administrateur

```
  
⸻  
  
## 13. Phase 7 — Interface Web  
Ajouter une section WebAuthn / Passkeys dans SettingsPage.tsx.  
Champs :  
```
WebAuthn / Passkeys

Activé
Origin
RP ID
RP Name

```
Comportement :  
* l’Origin est préremplie depuis Settings.domain ;  
* le RP ID est dérivé de l’Origin par défaut ;  
* la sauvegarde utilise /api/settings/webauthn ;  
* la sauvegarde utilise /api/settings/webauthn ;  
* afficher clairement l’état configuré/non configuré ;  
* afficher l’absence de domaine comme prérequis lors d’une tentative d’activation.  
Aucune configuration par variable d’environnement ne doit apparaître dans l’interface.  
  
⸻  
  
## 14. Interface des providers  
Dans :  
```
AdminProvidersPage.tsx

```
gérer explicitement :  
```
domain_not_configured

```
Afficher un message indiquant que le provider nécessite un domaine public configuré avant son activation.  
Ne pas effectuer de retry automatique et ne pas modifier silencieusement l’état du provider.  
  
⸻  
  
## 15. Phase 8 — Tests  
L’objectif n’est pas seulement de faire passer les nouveaux tests.  
Toute la suite existante doit rester verte.  
Référence actuelle :  
```
744/744 tests API
276/276 tests Auth
0 erreur TypeScript

```
  
⸻  
  
## 15.1 Tests Settings  
Ajouter notamment :  
```
lecture de la configuration WebAuthn
modification de la configuration WebAuthn
RP Name par défaut
Origin automatique depuis le domaine
RP ID automatique depuis l'Origin
Origin invalide
Origin HTTP rejetée en production
activation sans domaine rejetée
désactivation sans domaine autorisée
isolation entre tenants

```
  
⸻  
  
## 15.2 Tests WebAuthn  
Ajouter notamment :  
```
configuration de production provenant de la base
variables d'environnement ignorées
configuration absente → webauthn_not_configured
WebAuthn désactivé → webauthn_not_configured
Origin absente → webauthn_not_configured
RP ID dérivé de l'Origin
clientOrigin correspondant à l'Origin configurée
clientOrigin différent → rejet
fallback localhost conservé en développement
fallback localhost conservé en test
tenant A ne peut pas utiliser la configuration WebAuthn du tenant B

```
Le dernier test est obligatoire.  
  
⸻  
  
## 15.3 Tests Providers  
Ajouter notamment :  
```
OIDC activé sans domaine → 400
OAuth2 activé sans domaine → 400
SAML activé sans domaine → 400
LDAP activé sans domaine → autorisé
OIDC désactivé sans domaine → autorisé

PUT désactivé → activé sans domaine → 400
PUT d'un provider déjà activé → garde-fou correctement appliqué

tenant A avec domaine → activation SSO autorisée
tenant B sans domaine → activation SSO rejetée

```
Tester également explicitement le comportement des providers globaux.  
  
⸻  
  
## 16. Régression complète  
Exécuter :  
```
npm run test -w @hullbay/api
npx vitest run src/modules/auth
tsc --noEmit

```
Résultat attendu :  
```
0 échec
0 erreur TypeScript

```
Ensuite, relancer la campagne d’authentification prod-like.  
Le scénario :  
```
S9 — WebAuthn

```
doit cette fois être réellement exécuté.  
Il ne doit plus être marqué NON-EXÉCUTÉ à cause d’une absence de WEBAUTHN_*.  
  
⸻  
  
## 17. Critères d’acceptation production  
L’implémentation est considérée comme terminée uniquement si :  
## WebAuthn  
```
[ ] configuration DB fonctionnelle
[ ] aucune configuration WEBAUTHN_* requise
[ ] production fail-closed lorsque WebAuthn n'est pas configuré
[ ] isolation tenant respectée
[ ] Origin navigateur validée

```
## SSO  
```
[ ] OIDC sans domaine → rejeté
[ ] OAuth2 sans domaine → rejeté
[ ] SAML sans domaine → rejeté
[ ] LDAP sans domaine → autorisé
[ ] providers désactivés sans domaine → autorisés

```
## Installation  
```
[ ] install.sh ne génère plus WEBAUTHN_*
[ ] docker-compose ne fournit plus WEBAUTHN_*
[ ] .env.template ne documente plus WEBAUTHN_*

```
## Régression  
```
[ ] tests d'authentification existants toujours verts
[ ] suite complète verte
[ ] typecheck vert
[ ] campagne WebAuthn prod-like réellement exécutée

```
  
⸻  
  
## 18. Documentation  
Mettre à jour :  
```
docs/testing/auth/v1.3.0-beta.2.md

```
Documenter la correction :  
```
La configuration WebAuthn a été migrée des variables
d'environnement vers Settings, avec une portée par tenant.

```
Documenter le nouveau parcours :  
```
Settings
  → Domain
  → WebAuthn / Passkeys

```
Supprimer l’ancienne procédure basée sur :  
```
WEBAUTHN_ORIGIN
WEBAUTHN_RP_ID
WEBAUTHN_RP_NAME

```
Ajouter le nouveau scénario de validation production.  
  
⸻  
  
## 19. Livrables  
Branche :  
```
feat/webauthn-config-db

```
Livrables attendus :  
```
[ ] migration Prisma
[ ] extension du SettingsService
[ ] routes Settings WebAuthn
[ ] résolution WebAuthn depuis la base
[ ] résolution WebAuthn explicitement tenant-aware
[ ] validation de clientOrigin
[ ] garde-fou des providers dépendants d'un domaine
[ ] suppression des variables d'environnement WebAuthn
[ ] adaptation de install.sh
[ ] adaptation des docker-compose
[ ] interface WebAuthn
[ ] traductions FR/EN
[ ] tests
[ ] documentation
[ ] rapport de régression complet
[ ] validation prod-like de S9

```
  
⸻  
  
## 20. Règle d’implémentation obligatoire  
Ne pas commencer directement par modifier webauthn.ts.  
Avant toute modification, inspecter et documenter :  
```
résolution du tenant
contexte tenant disponible dans les sessions/pending tokens
tous les call sites WebAuthn
cycle de vie de Settings
portée globale vs tenant des providers
tests et mocks existants

```
Ensuite seulement effectuer la migration.  
L’objectif est d’introduire une configuration WebAuthn persistée en base sans créer :  
1. un deuxième mécanisme de résolution du tenant ;  
2. une deuxième source de configuration ;  
3. une régression des contrats d’authentification existants.  