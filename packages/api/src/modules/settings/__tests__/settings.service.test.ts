import { describe, it, expect, beforeEach, vi, afterAll } from "vitest";

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
import { AuthError } from "../../auth/providers/types";

// Settings par tenant (ex-singleton). Tenant par défaut en fallback.
const DEFAULT_TENANT_ID = "tenant-default";

const authSettingsRow = (over: Partial<Record<string, unknown>> = {}) => ({
  id: "s-1",
  domain: null,
  updatedAt: new Date(),
  webauthnEnabled: false,
  webauthnOrigin: null,
  webauthnRpId: null,
  webauthnRpName: "Hullbay",
  ...over,
});

describe("SettingsService", () => {
  const prevNodeEnv = process.env.NODE_ENV;

  afterAll(() => {
    process.env.NODE_ENV = prevNodeEnv;
  });

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NODE_ENV = process.env.NODE_ENV ?? "test";
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

  describe("getWebauthn", () => {
    it("retourne la config du tenant (ligne créée au besoin)", async () => {
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({
          webauthnEnabled: true,
          webauthnOrigin: "https://auth.exemple.com",
          webauthnRpId: "auth.exemple.com",
        }),
      );

      const result = await settingsService.getWebauthn("tenant-x");

      expect(result).toEqual({
        enabled: true,
        origin: "https://auth.exemple.com",
        rpId: "auth.exemple.com",
        rpName: "Hullbay",
      });
      expect(mockPrisma.settings.upsert).toHaveBeenCalledWith({
        where: { tenantId: "tenant-x" },
        create: { tenantId: "tenant-x" },
        update: {},
      });
    });

    it("retombe sur le tenant par défaut si aucun tenant explicite", async () => {
      mockPrisma.settings.upsert.mockResolvedValue(authSettingsRow());

      await settingsService.getWebauthn();

      expect(mockPrisma.settings.upsert).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: DEFAULT_TENANT_ID } }),
      );
    });
  });

  describe("setWebauthn", () => {
    const useProd = () => {
      process.env.NODE_ENV = "production";
    };

    it("normalise et dérive origin/rpId/rpName, puis persiste", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({
          webauthnEnabled: true,
          webauthnOrigin: "https://auth.exemple.com",
          webauthnRpId: "auth.exemple.com",
        }),
      );

      const result = await settingsService.setWebauthn("tenant-x", { enabled: true, origin: "https://auth.exemple.com/" });

      expect(result).toEqual({
        enabled: true,
        origin: "https://auth.exemple.com",
        rpId: "auth.exemple.com",
        rpName: "Hullbay",
      });
      expect(mockPrisma.settings.upsert).toHaveBeenCalledWith({
        where: { tenantId: "tenant-x" },
        create: {
          tenantId: "tenant-x",
          webauthnEnabled: true,
          webauthnOrigin: "https://auth.exemple.com",
          webauthnRpId: "auth.exemple.com",
          webauthnRpName: "Hullbay",
        },
        update: {
          webauthnEnabled: true,
          webauthnOrigin: "https://auth.exemple.com",
          webauthnRpId: "auth.exemple.com",
          webauthnRpName: "Hullbay",
        },
      });
    });

    it("origine persistée prioritaire quand aucun input.origin", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", { enabled: true });

      expect(result.origin).toBe("https://auth.exemple.com");
    });

    it("origin dérivée du domaine public si absente en prod", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ domain: "exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", { enabled: true });

      expect(result.origin).toBe("https://exemple.com");
    });

    it("activation en prod sans domaine public → domain_not_configured", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: true }),
      ).rejects.toMatchObject({ code: "domain_not_configured", status: 400 });
      expect(mockPrisma.settings.upsert).toHaveBeenCalledTimes(1);
    });

    it("désactivation en prod sans domaine autorisée", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());
      mockPrisma.settings.upsert.mockResolvedValue(authSettingsRow({ webauthnEnabled: false }));

      const result = await settingsService.setWebauthn("tenant-x", { enabled: false });

      expect(result.enabled).toBe(false);
    });

    it("activation hors production sans domaine autorisée (fallback dev/test)", async () => {
      process.env.NODE_ENV = "test";
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());
      mockPrisma.settings.upsert.mockResolvedValue(authSettingsRow({ webauthnEnabled: true }));

      const result = await settingsService.setWebauthn("tenant-x", { enabled: true });

      expect(result.enabled).toBe(true);
    });

    it("rejette une origin http:// en production", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: true, origin: "http://auth.exemple.com" }),
      ).rejects.toMatchObject({ code: "webauthn_origin_invalid" });
    });

    it("rejette une origin avec path", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: false, origin: "https://auth.exemple.com/base" }),
      ).rejects.toMatchObject({ code: "webauthn_origin_invalid" });
    });

    it("rejette une origin avec credentials", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: false, origin: "https://user:pass@auth.exemple.com" }),
      ).rejects.toMatchObject({ code: "webauthn_origin_invalid" });
    });

    it("rejette un rpId incompatible avec l'origin", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(authSettingsRow());

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: false, rpId: "evil.com" }),
      ).rejects.toMatchObject({ code: "webauthn_rpid_invalid" });
    });

    it("rpId compatible sous-domaine accepté", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com", webauthnRpId: "exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", { enabled: false, rpId: "exemple.com" });

      expect(result.rpId).toBe("exemple.com");
    });

    it("rpName explicite conservé, sinon défaut Hullbay", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com", webauthnRpName: "Acme" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", {
        enabled: false,
        rpName: "Acme",
      });

      expect(result.rpName).toBe("Acme");
    });

    it("origin modifiée, rpId non fourni : re-dérive si le rpId existant devient incompatible", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com", webauthnRpId: "auth.exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth2.exemple.com", webauthnRpId: "auth2.exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", {
        enabled: false,
        origin: "https://auth2.exemple.com",
      });

      expect(result.rpId).toBe("auth2.exemple.com");
    });

    it("origin modifiée, rpId existant toujours compatible (même racine domaniale) : conservé", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com", webauthnRpId: "exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth2.exemple.com", webauthnRpId: "exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", {
        enabled: false,
        origin: "https://auth2.exemple.com",
      });

      expect(result.rpId).toBe("exemple.com");
    });

    it("rpId vidé + origin modifiée : re-dérivé de la nouvelle origin", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "https://auth.exemple.com", webauthnRpId: "auth.exemple.com" }),
      );
      mockPrisma.settings.upsert.mockResolvedValue(
        authSettingsRow({ webauthnOrigin: "https://auth2.exemple.com", webauthnRpId: "auth2.exemple.com" }),
      );

      const result = await settingsService.setWebauthn("tenant-x", {
        enabled: false,
        origin: "https://auth2.exemple.com",
        rpId: "",
      });

      expect(result.rpId).toBe("auth2.exemple.com");
    });

    it("origin http:// héritée d'un environnement de dev, activation en prod → webauthn_origin_invalid", async () => {
      useProd();
      mockPrisma.settings.upsert.mockResolvedValueOnce(
        authSettingsRow({ webauthnOrigin: "http://auth.exemple.com" }),
      );

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: true }),
      ).rejects.toMatchObject({ code: "webauthn_origin_invalid" });
      expect(mockPrisma.settings.upsert).toHaveBeenCalledTimes(1);
    });

    it("rejette la config si l'upsert de lecture échoue", async () => {
      mockPrisma.settings.upsert.mockRejectedValueOnce(new AuthError("session_invalid", "base indisponible", 500));

      await expect(
        settingsService.setWebauthn("tenant-x", { enabled: true }),
      ).rejects.toThrow("base indisponible");
    });
  });
});
