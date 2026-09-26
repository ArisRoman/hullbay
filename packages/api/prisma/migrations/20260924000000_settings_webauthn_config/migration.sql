-- Invert: 20260918000000_tenant_scope (établissement de Settings) — extension rétrocompatible.

-- Configuration WebAuthn stockée en base (par tenant), remplace les variables
-- WEBAUTHN_ORIGIN / WEBAUTHN_RP_ID / WEBAUTHN_RP_NAME.
-- Rétrocompatible : les lignes Settings existantes restent valides, WebAuthn
-- est désactivé par défaut, les domaines existants sont intacts.
ALTER TABLE "Settings"
    ADD COLUMN "webauthnEnabled" BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN "webauthnOrigin" TEXT,
    ADD COLUMN "webauthnRpId" TEXT,
    ADD COLUMN "webauthnRpName" TEXT NOT NULL DEFAULT 'Hullbay';