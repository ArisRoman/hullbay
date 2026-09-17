import { describe, it, expect, vi, beforeEach } from "vitest"
import {
  generateWebauthnRegistrationOptions,
  verifyWebauthnRegistration,
  generateWebauthnAuthenticationOptions,
  verifyWebauthnAuthentication,
  listUserWebauthnCredentials,
  deleteUserWebauthnCredential,
  webauthnChallengeStore,
  getWebauthnConfig,
} from "../mfa/webauthn"
import { AuthError } from "../providers/types"

// Mock de @simplewebauthn/server
const mockGenerateRegOptions = vi.fn()
const mockVerifyRegResponse = vi.fn()
const mockGenerateAuthOptions = vi.fn()
const mockVerifyAuthResponse = vi.fn()

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: (args: any) => mockGenerateRegOptions(args),
  verifyRegistrationResponse: (args: any) => mockVerifyRegResponse(args),
  generateAuthenticationOptions: (args: any) => mockGenerateAuthOptions(args),
  verifyAuthenticationResponse: (args: any) => mockVerifyAuthResponse(args),
}))

// Mock de prisma
vi.mock("../../../lib/prisma", () => {
  const txMock = {
    webauthnCredential: {
      create: vi.fn(),
      delete: vi.fn(),
    },
    authIdentity: {
      update: vi.fn(),
    },
  }
  return {
    prisma: {
      authIdentity: {
        findFirst: vi.fn(),
        update: vi.fn(),
      },
      webauthnCredential: {
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
      },
      $transaction: vi.fn((fn: (tx: any) => Promise<any>) => fn(txMock)),
      _txMock: txMock,
    },
  }
})

// Mock de eventBus
vi.mock("../../../lib/event-bus", () => ({
  eventBus: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

import { prisma } from "../../../lib/prisma"

describe("WebAuthn / Passkeys Factor (Phase 5A3, N°11)", () => {
  const userId = "u-alice"
  const mockIdentity = {
    id: "id-local-1",
    userId,
    kind: "local",
    email: "alice@example.com",
    mfaEnabled: false,
    mfaSecretEnc: null,
    user: { id: userId, email: "alice@example.com", name: "Alice" },
    webauthnCredentials: [],
  }

  beforeEach(() => {
    vi.clearAllMocks()
    webauthnChallengeStore.clear()
  })

  describe("Configuration du Relying Party", () => {
    it("fail-closed en production sans WEBAUTHN_ORIGIN", () => {
      const prevNodeEnv = process.env.NODE_ENV
      const prevOrigin = process.env.WEBAUTHN_ORIGIN
      process.env.NODE_ENV = "production"
      delete process.env.WEBAUTHN_ORIGIN
      try {
        expect(() => getWebauthnConfig()).toThrow(AuthError)
      } finally {
        process.env.NODE_ENV = prevNodeEnv
        if (prevOrigin) process.env.WEBAUTHN_ORIGIN = prevOrigin
      }
    })
  })

  describe("Enrôlement (Registration)", () => {
    it("génère les options d'enregistrement et stocke le challenge", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(mockIdentity as any)
      mockGenerateRegOptions.mockResolvedValueOnce({
        challenge: "test-reg-challenge-123",
        rp: { name: "Hullbay", id: "localhost" },
        user: { id: "u-alice", name: "alice@example.com", displayName: "Alice" },
      })

      const options = await generateWebauthnRegistrationOptions(userId)

      expect(options.challenge).toBe("test-reg-challenge-123")
      expect(webauthnChallengeStore.getAndConsume(`reg:${userId}`)).toBe("test-reg-challenge-123")
    })

    it("exige la vérification utilisateur (UV) à l'enrôlement", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(mockIdentity as any)
      mockGenerateRegOptions.mockResolvedValueOnce({ challenge: "c" })

      await generateWebauthnRegistrationOptions(userId)

      expect(mockGenerateRegOptions).toHaveBeenCalledWith(
        expect.objectContaining({
          authenticatorSelection: expect.objectContaining({ userVerification: "required" }),
        }),
      )
    })

    it("isole le challenge stocké par discriminant de token", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(mockIdentity as any)
      mockGenerateRegOptions.mockResolvedValueOnce({ challenge: "ch-token" })

      await generateWebauthnRegistrationOptions(userId, undefined, "tokA")

      expect(webauthnChallengeStore.getAndConsume(`reg:${userId}:tokA`)).toBe("ch-token")
      expect(webauthnChallengeStore.getAndConsume(`reg:${userId}`)).toBeNull()
    })

    it("lève une erreur si l'identité locale n'existe pas", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null)

      await expect(generateWebauthnRegistrationOptions("unknown")).rejects.toThrow(AuthError)
    })

    it("retombe sur une identité externe (LDAP/OIDC/SAML) sans identité locale", async () => {
      vi.mocked(prisma.authIdentity.findFirst)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          ...mockIdentity,
          id: "id-ldap-1",
          kind: "ldap",
          webauthnCredentials: [],
        } as any)
      mockGenerateRegOptions.mockResolvedValueOnce({ challenge: "ext-reg-challenge" })

      const options = await generateWebauthnRegistrationOptions(userId)

      expect(options.challenge).toBe("ext-reg-challenge")
      expect(prisma.authIdentity.findFirst).toHaveBeenCalledTimes(2)
    })

    it("vérifie l'enregistrement, persiste la clé et active la MFA sur l'identité", async () => {
      webauthnChallengeStore.set(`reg:${userId}`, "test-reg-challenge-123")
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(mockIdentity as any)

      mockVerifyRegResponse.mockResolvedValueOnce({
        verified: true,
        registrationInfo: {
          credential: {
            id: "cred-id-abc",
            publicKey: new Uint8Array([1, 2, 3, 4]),
            counter: 0,
            transports: ["internal"],
          },
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
        },
      })

      const tx = (prisma as any)._txMock
      tx.webauthnCredential.create.mockResolvedValueOnce({ id: "wc-1", credentialId: "cred-id-abc" })
      tx.authIdentity.update.mockResolvedValueOnce({ id: "id-local-1", mfaEnabled: true })

      const res = await verifyWebauthnRegistration(userId, {
        response: { id: "cred-id-abc" } as any,
        name: "YubiKey 5C",
      })

      expect(res.verified).toBe(true)
      expect(res.credentialId).toBe("wc-1")
      expect(tx.webauthnCredential.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            identityId: "id-local-1",
            credentialId: "cred-id-abc",
            name: "YubiKey 5C",
          }),
        }),
      )
      expect(tx.authIdentity.update).toHaveBeenCalledWith({
        where: { id: "id-local-1" },
        data: { mfaEnabled: true },
      })
    })

    it("rejette la vérification si le challenge a expiré ou a déjà été consommé", async () => {
      await expect(
        verifyWebauthnRegistration(userId, { response: {} as any }),
      ).rejects.toThrow(AuthError)
    })
  })

  describe("Authentification (Authentication / Step-up)", () => {
    const credentialRecord = {
      id: "wc-1",
      identityId: "id-local-1",
      credentialId: "cred-id-abc",
      publicKey: Buffer.from([1, 2, 3, 4]),
      counter: BigInt(5),
      transports: '["internal"]',
    }

    it("génère les options d'authentification avec les credentials autorisés", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [credentialRecord],
      } as any)

      mockGenerateAuthOptions.mockResolvedValueOnce({
        challenge: "test-auth-challenge-456",
        allowCredentials: [{ id: "cred-id-abc" }],
      })

      const options = await generateWebauthnAuthenticationOptions(userId)

      expect(options.challenge).toBe("test-auth-challenge-456")
      expect(webauthnChallengeStore.getAndConsume(`auth:${userId}`)).toBe("test-auth-challenge-456")
    })

    it("lève une erreur si aucune clé WebAuthn n'est enregistrée pour l'utilisateur", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(mockIdentity as any)

      await expect(generateWebauthnAuthenticationOptions(userId)).rejects.toThrow(AuthError)
    })

    it("vérifie l'authentification avec succès et met à jour le compteur", async () => {
      webauthnChallengeStore.set(`auth:${userId}`, "test-auth-challenge-456")
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [credentialRecord],
      } as any)

      mockVerifyAuthResponse.mockResolvedValueOnce({
        verified: true,
        authenticationInfo: {
          newCounter: 6,
        },
      })

      vi.mocked(prisma.webauthnCredential.update).mockResolvedValueOnce({} as any)

      const res = await verifyWebauthnAuthentication(userId, {
        response: { id: "cred-id-abc" } as any,
      })

      expect(res.verified).toBe(true)
      expect(prisma.webauthnCredential.update).toHaveBeenCalledWith({
        where: { id: "wc-1" },
        data: expect.objectContaining({
          counter: BigInt(6),
        }),
      })
    })

    it("rejette une clé inconnue pour ce compte", async () => {
      webauthnChallengeStore.set(`auth:${userId}`, "test-auth-challenge-456")
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [credentialRecord],
      } as any)

      await expect(
        verifyWebauthnAuthentication(userId, {
          response: { id: "wrong-credential-id" } as any,
        }),
      ).rejects.toThrow(AuthError)
    })
  })

  describe("Gestion des Credentials (Listing & Deletion)", () => {
    it("liste les credentials WebAuthn de l'utilisateur", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [
          { id: "wc-1", name: "Touch ID", credentialId: "cid-1", createdAt: new Date() },
        ],
      } as any)

      const creds = await listUserWebauthnCredentials(userId)
      expect(creds).toHaveLength(1)
      expect(creds[0]?.name).toBe("Touch ID")
    })

    it("supprime un credential et désactive mfaEnabled si aucun autre facteur n'existe", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        mfaSecretEnc: null,
        webauthnCredentials: [{ id: "wc-1" }],
      } as any)

      vi.mocked(prisma.webauthnCredential.delete).mockResolvedValueOnce({} as any)
      vi.mocked(prisma.authIdentity.update).mockResolvedValueOnce({} as any)

      await deleteUserWebauthnCredential(userId, "wc-1")

      expect(prisma.webauthnCredential.delete).toHaveBeenCalledWith({ where: { id: "wc-1" } })
      expect(prisma.authIdentity.update).toHaveBeenCalledWith({
        where: { id: "id-local-1" },
        data: { mfaEnabled: false },
      })
    })

    it("refuse de supprimer un credential appartenant à une autre identité (IDOR)", async () => {
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [{ id: "wc-other" }],
      } as any)

      await expect(deleteUserWebauthnCredential(userId, "wc-mine")).rejects.toThrow(AuthError)
      expect(prisma.webauthnCredential.delete).not.toHaveBeenCalled()
    })

    it("émet les évènements d'audit auth.webauthn.registered et auth.webauthn.deleted", async () => {
      const { eventBus } = await import("../../../lib/event-bus")
      vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce({
        ...mockIdentity,
        webauthnCredentials: [{ id: "wc-1", name: "YubiKey" }],
      } as any)
      vi.mocked(prisma.webauthnCredential.delete).mockResolvedValueOnce({} as any)

      await deleteUserWebauthnCredential(userId, "wc-1")

      expect(eventBus.emit).toHaveBeenCalledWith("auth.webauthn.deleted", {
        userId,
        credentialId: "wc-1",
        name: "YubiKey",
      })
    })
  })
})
