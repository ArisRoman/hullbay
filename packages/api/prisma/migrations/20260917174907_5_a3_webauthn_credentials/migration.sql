-- CreateTable
CREATE TABLE "WebauthnCredential" (
    "id" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKey" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "deviceType" TEXT,
    "backedUp" BOOLEAN NOT NULL DEFAULT false,
    "transports" TEXT,
    "name" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "WebauthnCredential_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WebauthnCredential_credentialId_key" ON "WebauthnCredential"("credentialId");

-- CreateIndex
CREATE INDEX "WebauthnCredential_identityId_idx" ON "WebauthnCredential"("identityId");

-- AddForeignKey
ALTER TABLE "WebauthnCredential" ADD CONSTRAINT "WebauthnCredential_identityId_fkey" FOREIGN KEY ("identityId") REFERENCES "AuthIdentity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
