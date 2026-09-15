import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

vi.mock("../../../lib/prisma", () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
    },
    authIdentity: {
      findFirst: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(() => Promise.resolve({ count: 1 })),
    },
    pendingIdentity: {
      findFirst: vi.fn(() => Promise.resolve(null)),
      create: vi.fn(() => Promise.resolve({})),
    },
  },
}));

import { prisma } from "../../../lib/prisma";
import { processSsoCallback } from "../core/sso-callback";
import type { ExternalIdentity } from "../providers/types";

const SECRET = "test-secret-for-sso-callback";
const KNOWN: ExternalIdentity = {
  providerId: "oidc-test",
  kind: "oidc",
  issuer: "https://keycloak.test/realms/hullbay",
  subject: "sub-42",
  email: "alice@example.test",
};

describe("processSsoCallback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.JWT_SECRET = SECRET;
  });

  afterEach(() => {
    delete process.env.JWT_SECRET;
  });

  it("identité connue → session signée (mfaEnabled=true, pas de 2e MFA locale)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue({ userId: "u-9", providerId: "oidc-test", subject: "sub-42" } as never);
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u-9", role: "admin" } as never);
    const res = await processSsoCallback(KNOWN);

    expect(res.pending).toBe(false);
    if (res.pending) return;
    expect(res.userId).toBe("u-9");
    expect(res.role).toBe("admin");
    expect(res.token).toBeTruthy();
    expect(typeof res.token).toBe("string");
    // mise à jour lastLoginAt demandée
    expect(prisma.authIdentity.updateMany).toHaveBeenCalledWith({
      where: { providerId: "oidc-test", issuer: KNOWN.issuer, subject: "sub-42" },
      data: { lastLoginAt: expect.any(Date) },
    });
    // pas de User créé en auto
    expect(prisma.pendingIdentity.create).not.toHaveBeenCalled();
  });

  it("identité inconnue → résultat pending (jamais d'auto-création de User)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);
    const res = await processSsoCallback(KNOWN);

    expect(res.pending).toBe(true);
    if (!res.pending) return;
    expect(res.identity).toMatchObject({
      providerId: "oidc-test",
      kind: "oidc",
      email: "alice@example.test",
    });
    expect(prisma.authIdentity.updateMany).not.toHaveBeenCalled();
  });

  it("identité inconnue mais pending déjà enregistrée → pas de doublon, résultat pending", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValueOnce({ id: "p-1", status: "pending" } as never);
    const res = await processSsoCallback(KNOWN);
    expect(res.pending).toBe(true);
    expect(prisma.pendingIdentity.create).not.toHaveBeenCalled();
  });

  it("échec si mapping pointe vers un User absent (incohérence DB)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue({ userId: "u-absent", providerId: "oidc-test", subject: "sub-42" } as never);
    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce(null as never);
    await expect(processSsoCallback(KNOWN)).rejects.toThrow(/User absent/);
  });
});