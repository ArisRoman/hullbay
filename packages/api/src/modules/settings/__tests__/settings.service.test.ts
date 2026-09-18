import { describe, it, expect, beforeEach, vi } from "vitest";

const { mockPrisma, mockApplyDomainToCaddy } = vi.hoisted(() => ({
  mockPrisma: {
    settings: { upsert: vi.fn() },
  },
  mockApplyDomainToCaddy: vi.fn(),
}));

vi.mock("../../../lib/prisma", () => ({ prisma: mockPrisma }));
vi.mock("../caddy-domain", () => ({
  applyDomainToCaddy: mockApplyDomainToCaddy,
}));


import { settingsService } from "../service";

// Phase 5B : settings par tenant (ex-singleton). Tenant par défaut en fallback.
const DEFAULT_TENANT_ID = "tenant-default";

describe("SettingsService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("get", () => {
    it("crée la ligne du tenant via upsert si elle n'existe pas encore", async () => {
      mockPrisma.settings.upsert.mockResolvedValue({
        id: "s-1",
        domain: null,
        updatedAt: new Date(),
      });

      const result = await settingsService.get();

      expect(result).toEqual({ domain: null });
      expect(mockPrisma.settings.upsert).toHaveBeenCalledWith({
        where: { tenantId: DEFAULT_TENANT_ID },
        create: { tenantId: DEFAULT_TENANT_ID },
        update: {},
      });
      expect(mockApplyDomainToCaddy).not.toHaveBeenCalled();
    });

    it("renvoie le domaine existant sans le modifier", async () => {
      mockPrisma.settings.upsert.mockResolvedValue({
        id: "s-1",
        domain: "ops.exemple.com",
        updatedAt: new Date(),
      });

      const result = await settingsService.get();

      expect(result).toEqual({ domain: "ops.exemple.com" });
    });
  });

  describe("setDomain", () => {
    it("applique Caddy PUIS persiste en base, dans cet ordre précis", async () => {
      mockApplyDomainToCaddy.mockResolvedValue(undefined);
      mockPrisma.settings.upsert.mockResolvedValue({
        id: "s-1",
        domain: "ops.exemple.com",
        updatedAt: new Date(),
      });

      const result = await settingsService.setDomain("ops.exemple.com");

      expect(result).toEqual({ 
        domain: "ops.exemple.com",
        url: "https://ops.exemple.com"
      });
      expect(mockApplyDomainToCaddy).toHaveBeenCalledWith("ops.exemple.com", DEFAULT_TENANT_ID);
      expect(mockPrisma.settings.upsert).toHaveBeenCalledWith({
        where: { tenantId: DEFAULT_TENANT_ID },
        create: { tenantId: DEFAULT_TENANT_ID, domain: "ops.exemple.com" },
        update: { domain: "ops.exemple.com" },
      });


      const caddyCallOrder = mockApplyDomainToCaddy.mock.invocationCallOrder[0]!;
      const dbCallOrder = mockPrisma.settings.upsert.mock.invocationCallOrder[0]!;
      expect(caddyCallOrder).toBeLessThan(dbCallOrder);
    });

    it("ne persiste RIEN en base si Caddy refuse le domaine", async () => {
      mockApplyDomainToCaddy.mockRejectedValue(
        new Error("Caddy: route web échouée (500)"),
      );

      await expect(
        settingsService.setDomain("ops.exemple.com"),
      ).rejects.toThrow("Caddy: route web échouée (500)");

     
      expect(mockPrisma.settings.upsert).not.toHaveBeenCalled();
    });

    it("propage fidèlement le message d'erreur de Caddy (pas de erreur générique)", async () => {
      mockApplyDomainToCaddy.mockRejectedValue(
        new Error("Impossible de joindre l'API admin Caddy"),
      );

      await expect(
        settingsService.setDomain("ops.exemple.com"),
      ).rejects.toThrow("Impossible de joindre l'API admin Caddy");
    });
  });
});
