-- Fixtures de la campagne E2E réelle — exécuté APRÈS `prisma migrate reset`
-- (via `prisma db execute`) et AVANT le démarrage de l'API (packages/web/playwright.real.config.ts).
--
-- 1. Deux tenants (default rattaché à la policy ; e2e pour le TenantSwitcher).
-- 2. SecurityPolicy du tenant par défaut : rate-limit accéléré pour un test UI
--    réel rapide (limite 3 échecs, backoff 4 s / max 30 s) au lieu des défauts
--    (5 échecs, backoff 30 s / max 10 min).
-- L'API charge cette policy à son démarrage (constructor) — pas de réécriture
-- par l'upsert bureau aux défauts.

INSERT INTO "Tenant" ("id", "name", "slug", "updatedAt") VALUES
  ('tenant-default', 'Default', 'default', now()),
  ('tenant-e2e',     'E2E',     'e2e',     now())
ON CONFLICT ("id") DO NOTHING;

INSERT INTO "SecurityPolicy"
  ("id", "tenantId", "sessionTtlMs", "rateBaseBackoffMs", "rateMaxBackoffMs",
   "mfaRequireRoles", "loginFailLimit", "loginFailWindowMs", "lockoutMs",
   "providerAllowlist", "updatedAt")
VALUES
  ('singleton-e2e', 'tenant-default', 43200000, 4000, 30000,
   '[]', 3, 60000, 60000,
   '[]', now())
ON CONFLICT ("tenantId") DO NOTHING;