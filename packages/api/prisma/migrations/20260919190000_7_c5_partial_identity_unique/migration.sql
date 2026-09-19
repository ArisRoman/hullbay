-- C5 : UNIQUE(NULL) ne dédoublonne pas sous PostgreSQL. Les identités local/ldap
-- portent issuer = NULL : sans index partiel, un même (providerId, subject)
-- pouvait être inséré plusieurs fois (course) — doublons de pending / de lien.
-- Index partiels (providerId, subject) WHERE issuer IS NULL : l'unicité est
-- maintenant garantie en base pour ces providers. Les flows OIDC/OAuth2/SAML
-- (issuer non NULL) restent couverts par le @@unique([providerId, issuer, subject]).

CREATE UNIQUE INDEX "PendingIdentity_provider_subject_issuer_null"
  ON "PendingIdentity" ("providerId", "subject")
  WHERE "issuer" IS NULL;

CREATE UNIQUE INDEX "AuthIdentity_provider_subject_issuer_null"
  ON "AuthIdentity" ("providerId", "subject")
  WHERE "issuer" IS NULL;