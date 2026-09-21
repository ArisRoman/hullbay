-- Tenant-scoping (expand) : colonnes tenantId + contraintes.
-- Stratégie expand/contract : colonnes NULLABLE en transition, backfill immédiat
-- vers le tenant par défaut ('tenant-default', créé avec le modèle identité), puis
-- NOT NULL à l'étape éteinte. Aucune donnée perdue.

-- 0. Garantir le tenant par défaut (idempotent).
INSERT INTO "Tenant" ("id", "name", "slug", "createdAt", "updatedAt")
VALUES ('tenant-default', 'Default', 'default', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT ("slug") DO NOTHING;

-- 1. Colonnes tenantId (nullable).
ALTER TABLE "AuditLog"           ADD COLUMN "tenantId" TEXT;
ALTER TABLE "AuthProvider"       ADD COLUMN "tenantId" TEXT;
ALTER TABLE "Cluster"            ADD COLUMN "tenantId" TEXT;
ALTER TABLE "Project"            ADD COLUMN "tenantId" TEXT;
ALTER TABLE "RegistryCredential" ADD COLUMN "tenantId" TEXT;
ALTER TABLE "Server"             ADD COLUMN "tenantId" TEXT;
ALTER TABLE "SecurityPolicy"     ADD COLUMN "tenantId" TEXT;
ALTER TABLE "Settings"           ADD COLUMN "tenantId" TEXT,
ALTER COLUMN "id" DROP DEFAULT;
ALTER TABLE "SecurityPolicy"     ALTER COLUMN "id" DROP DEFAULT;

-- 2. Backfill → tenant par défaut.
UPDATE "Cluster"            SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "Project"            SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "Server"             SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "RegistryCredential" SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "AuditLog"           SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "Settings"           SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
UPDATE "SecurityPolicy"     SET "tenantId" = 'tenant-default' WHERE "tenantId" IS NULL;
-- AuthProvider : les providers existants (local/oidc/oauth2/saml/ldap) restent
-- GLOBAUX (tenantId NULL) — décision explicite §4.2 (correction N°22).

-- 3. Déduplication des noms de Cluster PAR tenant avant la contrainte composite
--    (l'ancienne unicité était globale, donc aucun doublon attendu : filet de sécurité).
UPDATE "Cluster" c
SET "name" = c."name" || '-' || left(c."id", 6)
WHERE c."id" IN (
  SELECT id FROM (
    SELECT id, row_number() OVER (PARTITION BY "tenantId", "name" ORDER BY "id") AS rn
    FROM "Cluster"
  ) t WHERE t.rn > 1
);

-- 4. Ancienne unicité globale du nom de Cluster → unicité PAR tenant.
DROP INDEX IF EXISTS "Cluster_name_key";

-- 5. Index + contraintes d'unicité.
CREATE INDEX "AuditLog_tenantId_idx" ON "AuditLog"("tenantId");
CREATE INDEX "AuthProvider_tenantId_idx" ON "AuthProvider"("tenantId");
CREATE INDEX "Cluster_tenantId_idx" ON "Cluster"("tenantId");
CREATE UNIQUE INDEX "Cluster_tenantId_name_key" ON "Cluster"("tenantId", "name");
CREATE INDEX "Project_tenantId_idx" ON "Project"("tenantId");
CREATE INDEX "RegistryCredential_tenantId_idx" ON "RegistryCredential"("tenantId");
CREATE UNIQUE INDEX "SecurityPolicy_tenantId_key" ON "SecurityPolicy"("tenantId");
CREATE INDEX "Server_tenantId_idx" ON "Server"("tenantId");
CREATE UNIQUE INDEX "Settings_tenantId_key" ON "Settings"("tenantId");

-- 6. Clés étrangères.
ALTER TABLE "Project"            ADD CONSTRAINT "Project_tenantId_fkey"            FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "AuthProvider"       ADD CONSTRAINT "AuthProvider_tenantId_fkey"       FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "SecurityPolicy"     ADD CONSTRAINT "SecurityPolicy_tenantId_fkey"     FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "AuditLog"           ADD CONSTRAINT "AuditLog_tenantId_fkey"           FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Server"             ADD CONSTRAINT "Server_tenantId_fkey"             FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "RegistryCredential" ADD CONSTRAINT "RegistryCredential_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "Settings"           ADD CONSTRAINT "Settings_tenantId_fkey"           FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
ALTER TABLE "Cluster"            ADD CONSTRAINT "Cluster_tenantId_fkey"            FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE  ON UPDATE CASCADE;
