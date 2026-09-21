-- AlterTable
-- Garde B5 : un User existant n'est réutilisé à l'approbation que si l'IdP
-- a vérifié l'email (OIDC `email_verified`). LDAP/OAuth2 = false.
ALTER TABLE "PendingIdentity" ADD COLUMN     "emailVerified" BOOLEAN NOT NULL DEFAULT false;