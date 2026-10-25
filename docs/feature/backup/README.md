# Backup Engine — architecture

Sauvegarde des données persistantes d'un projet Hullbay (bases de données et
volumes), vers un stockage distant, sans jamais écrire d'archive sur le disque
d'un nœud.

## Couches

```
PersistentDataTarget → BackupPolicy → BackupEngine → BackupStrategy
                                                  → BackupArtifact → StorageProvider → RcloneAdapter
```

| Couche | Rôle | Emplacement |
|---|---|---|
| Target | projection d'un nœud `database`/`volume` | `packages/api/src/modules/backup/targets.service.ts` |
| Policy | intention : cible + destination + planification | `policies.service.ts`, `BackupPolicyInputSchema` |
| Engine | cycle de vie, staging, vérification, commit | `engine/lifecycle.ts` |
| Strategy | plan d'extraction par moteur | `strategies/*.ts` |
| Runner | tâche Swarm one-shot (jamais `docker exec`) | `runner.ts`, `engine/swarm-task.ts` |
| Storage | `put/get/stat/list/delete/move/hash` | `storage/*.ts` |
| Artifact | payload + manifest + checksum | `BackupArtifact` |

Le moteur ne connaît ni rclone ni une stratégie concrète : un test
d'architecture (`strategies.test.ts`) grep les sources et échoue si cette
frontière est franchie.

## Cycle de vie d'un run

`resolving → extracting → transferring → verifying → committing → done`

1. **resolving** : résolution de la connexion (provider du moteur), prérequis
   (`verifyPrereqs`), construction du plan.
2. **extracting/transferring** : `pg_dump`/`mysqldump`/`mongodump`/`redis-cli`/`tar`
   écrit sur stdout → `gzip` → `rclone rcat` vers un préfixe de **staging**
   propre au run (`.staging/<runId>`). Le checksum et la taille sont calculés
   pendant le flux (process substitution), sans fichier intermédiaire.
3. **verifying** : taille et checksum relus côté distant. Un backend sans hash
   natif dégrade en vérification de taille — jamais silencieusement.
4. **committing** : `rclone moveto` staging → préfixe final, puis
   `payload.sha256`, puis `manifest.json` **en dernier**.
5. **done** : le run passe `COMPLETED`, l'artifact existe.

Règles non négociables :

- **partial ≠ valid** : aucun artifact ni `COMPLETED` sur un flux incomplet ;
- le staging est purgé dans tous les cas (`finally`) ;
- la rétention ne s'exécute qu'après un run `COMPLETED`.

## Modèle de données

`BackupTarget` (1) — `BackupPolicy` (N) — `BackupRun` (N) — `BackupArtifact` (0..1)

- `BackupDestination` porte le chiffré (AES-256-GCM, scope `backup`) et une
  matrice de capacités issue du dernier probe.
- `BackupPolicy` porte le lease (`lockedBy`, `lockExpiresAt`) : un seul runner
  planifié à la fois, sans verrou consultatif (Prisma pooling).
- `BackupArtifact.sizeBytes` est un `BigInt` ; l'API le sérialise en chaîne.

## Manifest

Le manifest est auto-descriptif et suffit à restaurer sans Hullbay :

- identité (`artifactId`, `runId`, `createdAt`) ;
- cible et source (moteur, version, hôte, base, utilisateur) ;
- stratégie et outil (`id`, `version`, `tool`, `toolVersion`) ;
- payload (`path`, `format`, `sizeBytes`) ;
- checksum (`sha256`) ;
- commande de restauration standard.

`parseBackupManifest` refuse un `formatVersion` futur au lieu de l'interpréter.

## Sécurité

- Aucun `docker exec` : un service Swarm one-shot par étape, supprimé ensuite.
- Credentials uniquement en Docker Secrets montés en fichiers ; les scripts
  construisent `.pgpass`/`.my.cnf`/`mongodump.yaml` **dans le task**.
- Les mots de passe SFTP/WebDAV/SMB sont **obscurcis** (`rclone obscure`) dans
  la connection-string : rclone refuse un `pass=` en clair.
- Jamais de mot de passe en `Env`, `Args`, log, réponse HTTP ou manifest.
- Les logs de task sont nettoyés (`scrubSecrets`) avant persistance.
- Destinations : lecture = operator (vue sans secret), mutation et probe = owner.

## Limites V1

- Restauration automatique non implémentée (`POST .../restore` → 501) ; la
  procédure manuelle est documentée dans [restauration.md](restauration.md).
- Chiffrement du payload : `encryptionMode = "none"` uniquement (le chiffrement
  des *credentials* est distinct).
- Cibles : nœuds `database` et `volume`. Un conteneur n'expose pas de source
  cohérente et est refusé explicitement.
- Un volume marqué `bozando.database.data=true` est refusé par défaut
  (`BACKUP_ALLOW_DATABASE_VOLUME=true` pour un override opérateur explicite,
  consigné dans les logs).
