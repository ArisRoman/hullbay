-- Phase 5B — tenant-scoping (contract) : tenantId NOT NULL.
-- Fin de la stratégie expand/contract. La migration expand (5_b_tenant_scope) a
-- backfillé toutes les lignes vers 'tenant-default' ; on peut donc resserrer.
-- AuthProvider tient des providers GLOBAUX (tenantId NULL) et AuditLog consigne
-- des événements système sans tenant : ces deux colonnes restent NULLABLE.

-- 1. NOT NULL partout où un enregistrement appartient à un tenant.
ALTER TABLE "Cluster" ALTER COLUMN "tenantId" SET NOT NULL;
ALTER TABLE "Project" ALTER COLUMN "tenantId" SET NOT NULL;
ALTER TABLE "Server" ALTER COLUMN "tenantId" SET NOT NULL;
ALTER TABLE "RegistryCredential" ALTER COLUMN "tenantId" SET NOT NULL;
ALTER TABLE "Settings" ALTER COLUMN "tenantId" SET NOT NULL;
ALTER TABLE "SecurityPolicy" ALTER COLUMN "tenantId" SET NOT NULL;