import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("../../../lib/prisma", () => ({
  prisma: {
    authIdentity: {
      findFirst: vi.fn(),
      findUnique: vi.fn(),
    },
    pendingIdentity: {
      findFirst: vi.fn(() => Promise.resolve(null)),
      create: vi.fn(() => Promise.resolve({})),
    },
  },
}));

import { prisma } from "../../../lib/prisma";
import { resolveIdentity, IdentityPendingError } from "../core/identity-mapping";
import type { ExternalIdentity } from "../providers/types";

const KNOWN: ExternalIdentity = {
  providerId: "github",
  kind: "oidc",
  issuer: "https://github.com",
  subject: "octo",
  email: "octo@github.local",
};

describe("resolveIdentity (identity mapping)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("retourne le mapping existant pour une identité connue", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValue({
      userId: "u-9",
      providerId: "github",
      subject: "octo",
      email: "octo@github.local",
    } as never);

    const resolved = await resolveIdentity(KNOWN);
    expect(resolved).toEqual({ userId: "u-9", providerId: "github", subject: "octo", email: "octo@github.local" });
    expect(prisma.pendingIdentity.create).not.toHaveBeenCalled();
  });

  it("crée une PendingIdentity puis lève IdentityPendingError pour une identité inconnue", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);

    await expect(resolveIdentity(KNOWN)).rejects.toBeInstanceOf(IdentityPendingError);

    expect(prisma.pendingIdentity.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ email: "octo@github.local" }),
      }),
    );
  });

  it("ne crée pas de doublon pending déjà existant (state pending déjà enregistré)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);
    vi.mocked(prisma.pendingIdentity.findFirst).mockResolvedValueOnce({
      id: "p-1",
      providerId: "github",
      status: "pending",
    } as never);

    await expect(resolveIdentity(KNOWN)).rejects.toBeInstanceOf(IdentityPendingError);
    expect(prisma.pendingIdentity.create).not.toHaveBeenCalled();
  });

  it("filtre l'identité sur providerId+issuer+subject (issuer nullable)", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);
    const external: ExternalIdentity = {
      providerId: "oidc",
      kind: "oidc",
      issuer: "https://issuer.example",
      subject: "sub-42",
      email: null,
    };

    await expect(resolveIdentity(external)).rejects.toBeInstanceOf(IdentityPendingError);
    expect(prisma.authIdentity.findFirst).toHaveBeenCalledWith({
      where: {
        providerId: "oidc",
        issuer: "https://issuer.example",
        subject: "sub-42",
      },
    });
  });

  it("deux mêmes identités externes distinctes sur des providers différents ne collisionnent pas", async () => {
    vi.mocked(prisma.authIdentity.findFirst).mockResolvedValueOnce(null as never);
    const sameSubjectDifferentIssuer: ExternalIdentity = {
      providerId: "oidc",
      kind: "oidc",
      issuer: "https://other.example",
      subject: "octo",
      email: "octo@other.example",
    };
    await expect(resolveIdentity(sameSubjectDifferentIssuer)).rejects.toBeInstanceOf(IdentityPendingError);
    expect(prisma.pendingIdentity.create).toHaveBeenCalled();

    const data = vi.mocked(prisma.pendingIdentity.create).mock.calls[0]?.[0].data;
    expect(data).toEqual(
      expect.objectContaining({
        providerId: "oidc",
        issuer: "https://other.example",
        subject: "octo",
      }),
    );
  });
});