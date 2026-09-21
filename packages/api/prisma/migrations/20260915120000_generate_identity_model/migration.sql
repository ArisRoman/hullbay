-- Modèle identité (AuthIdentity/Tenant/Membership/AuthProvider/PendingIdentity).
-- ORDRE SÛR : on copie d'abord les credentials existants (User.passwordHash/mfaSecretEnc/
-- mfaEnabled) dans auth_identities, puis on supprime les anciennes colonnes. Les comptes
-- existants restent valides : hash conservés, aucun mot de passe régénéré.

-- 1. Nouvelles tables
CREATE TABLE "AuthIdentity" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "issuer" TEXT,
    "subject" TEXT NOT NULL,
    "email" TEXT,
    "passwordHash" TEXT,
    "mfaSecretEnc" TEXT,
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastLoginAt" TIMESTAMP(3),

    CONSTRAINT "AuthIdentity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Membership" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Membership_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuthProvider" (
    "id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "config" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuthProvider_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PendingIdentity" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "issuer" TEXT,
    "subject" TEXT NOT NULL,
    "email" TEXT,
    "name" TEXT,
    "requestedForTenantId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PendingIdentity_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "AuthIdentity_userId_idx" ON "AuthIdentity"("userId");
CREATE UNIQUE INDEX "AuthIdentity_providerId_issuer_subject_key" ON "AuthIdentity"("providerId", "issuer", "subject");
CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");
CREATE UNIQUE INDEX "Membership_userId_tenantId_key" ON "Membership"("userId", "tenantId");
CREATE UNIQUE INDEX "PendingIdentity_providerId_issuer_subject_key" ON "PendingIdentity"("providerId", "issuer", "subject");

ALTER TABLE "AuthIdentity" ADD CONSTRAINT "AuthIdentity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- 2. COPIE des credentials existants (avant suppression des colonnes User)
INSERT INTO "AuthIdentity" ("id", "userId", "providerId", "kind", "issuer", "subject", "email", "passwordHash", "mfaSecretEnc", "mfaEnabled", "createdAt")
SELECT gen_random_uuid()::text, u."id", 'local', 'local', NULL, 'local:' || u."id", u."email", u."passwordHash", u."mfaSecretEnc", u."mfaEnabled", CURRENT_TIMESTAMP
FROM "User" u;

-- 3. Tenant par défaut + membership existants + seeds providers (aucun vendor)
INSERT INTO "Tenant" ("id", "name", "slug", "createdAt", "updatedAt")
VALUES ('tenant-default', 'Default', 'default', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO "Membership" ("id", "userId", "tenantId", "role", "createdAt")
SELECT gen_random_uuid()::text, u."id", 'tenant-default', u."role", CURRENT_TIMESTAMP
FROM "User" u;

INSERT INTO "AuthProvider" ("id", "kind", "name", "enabled", "config", "createdAt", "updatedAt") VALUES
('provider-local', 'local',  'Local',  true,  '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('provider-oidc',  'oidc',   'OIDC',   false, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('provider-oauth2','oauth2', 'OAuth2', false, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('provider-saml',  'saml',   'SAML',   false, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('provider-ldap',  'ldap',   'LDAP',   false, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- 4. Altérations User : credentials déplacés, attributs ajoutés
ALTER TABLE "User"
    ADD COLUMN "name" TEXT,
    ADD COLUMN "locale" TEXT,
    ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    DROP COLUMN "mfaEnabled",
    DROP COLUMN "mfaSecretEnc",
    DROP COLUMN "passwordHash",
    ALTER COLUMN "email" DROP NOT NULL;

ALTER TABLE "User" ALTER COLUMN "updatedAt" DROP DEFAULT;