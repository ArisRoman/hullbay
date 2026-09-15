import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("../../../lib/prisma", () => ({
  prisma: {
    authIdentity: {
      findFirst: vi.fn(),
      update: vi.fn(() => Promise.resolve({})),
    },
  },
}));

import { prisma } from "../../../lib/prisma";
import { LocalProvider } from "../providers/local/local-provider";
import { AuthError } from "../providers/types";
import { hashPassword } from "../providers/local/password";

const PASSWORD = "F12345678";
const PASSWORD_HASH = hashPassword(PASSWORD);

const IDENTITY = (overrides: Record<string, unknown> = {}) => ({
  id: "i-1",
  userId: "u-1",
  providerId: "local",
  kind: "local",
  issuer: null,
  subject: "local:u-1",
  email: "alice@hullbay.local",
  passwordHash: PASSWORD_HASH,
  mfaEnabled: false,
  mfaSecretEnc: null,
  createdAt: new Date(),
  lastLoginAt: null,
  user: { id: "u-1", role: "owner" },
  ...overrides,
});

describe("LocalProvider.authenticate", () => {
  let provider: LocalProvider;

  beforeEach(() => {
    provider = new LocalProvider("local");
    vi.clearAllMocks();
  });

  it("retourne identity + userId + role quand email/mot de passe sont corrects", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue(IDENTITY() as never);

    const result = await provider.authenticate({ kind: "local", email: "alice@hullbay.local", password: PASSWORD });
    expect(result).toMatchObject({
      mfaRequired: false,
      userId: "u-1",
      role: "owner",
    });
    expect(result.identity.subject).toBe("local:u-1");
    expect(prisma.authIdentity.update).toHaveBeenCalled();
  });

  it("mfaRequired=true quand mfaEnabled sur l'identité", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue(IDENTITY({ mfaEnabled: true }) as never);
    const result = await provider.authenticate({ kind: "local", email: "alice@hullbay.local", password: PASSWORD });
    expect(result.mfaRequired).toBe(true);
  });

  it("rejette un mot de passe incorrect (invalid_credentials)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue(IDENTITY() as never);
    await expect(
      provider.authenticate({ kind: "local", email: "alice@hullbay.local", password: "wrong-pass" }),
    ).rejects.toMatchObject({ code: "invalid_credentials", status: 401 });
  });

  it("rejette un email inconnu (même timing, aucun indice d'existence)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue(null as never);
    const start = Date.now();
    await expect(
      provider.authenticate({ kind: "local", email: "ghost@hullbay.local", password: PASSWORD }),
    ).rejects.toMatchObject({ code: "invalid_credentials" });
    expect(Date.now() - start).toBeLessThan(500);
  });

  it("rejette email ou mot de passe manquant sans toucher la DB", async () => {
    await expect(provider.authenticate({ kind: "local", email: "", password: PASSWORD })).rejects.toMatchObject({
      code: "invalid_credentials",
    });
    await expect(provider.authenticate({ kind: "local", email: "a@b.c", password: "" })).rejects.toMatchObject({
      code: "invalid_credentials",
    });
    expect(prisma.authIdentity.findFirst).not.toHaveBeenCalled();
  });

  it("n'échoue pas si l'identité existe mais n'a pas de hash (dummy timing)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue(IDENTITY({ passwordHash: null }) as never);
    await expect(
      provider.authenticate({ kind: "local", email: "alice@hullbay.local", password: PASSWORD }),
    ).rejects.toBeInstanceOf(AuthError);
  });
});