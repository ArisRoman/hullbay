import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  vi,
} from "vitest";
import { buildTestApp } from "../../../__tests__/helpers/build-test-app";
import { registerSettingsRoutes } from "../routes";
import { registerAuthGuard } from "../../auth/routes";
import { authService } from "../../auth/service";


const { mockSettingsService } = vi.hoisted(() => ({
  mockSettingsService: {
    get: vi.fn(),
    setDomain: vi.fn(),
    getWebauthn: vi.fn(),
    setWebauthn: vi.fn(),
  },
}));

vi.setConfig({ testTimeout: 15000, hookTimeout: 15000 });

vi.mock("../service", () => ({
  settingsService: mockSettingsService,
}));

vi.mock("../../../lib/event-bus", () => ({
  eventBus: { emit: vi.fn() },
}));

vi.mock("../../auth/service", () => ({
  authService: { verifyToken: vi.fn() },
}));

const mockOwnerToken = "mock_owner_token";
const mockOperatorToken = "mock_operator_token";
const mockViewerToken = "mock_viewer_token";
const mockInvalidToken = "mock_invalid_token";

// Le tenant courant (défaut sans header) est passé au service.
const DEFAULT_TENANT_ID = "tenant-default";

describe("Routes /api/settings/domain", () => {
  let app: Awaited<ReturnType<typeof buildTestApp>>;

  beforeAll(async () => {
    app = await buildTestApp({
      routes: async (app) => {
        registerAuthGuard(app);
        await registerSettingsRoutes(app);
      },
    });
  }, 60000);

  afterAll(async () => {
    if (app) await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(authService.verifyToken).mockImplementation((token: string) => {
      if (token === mockOwnerToken)
        return { sub: "owner-id", role: "owner", mfaEnabled: true };
      if (token === mockOperatorToken)
        return { sub: "operator-id", role: "operator", mfaEnabled: true };
      if (token === mockViewerToken)
        return { sub: "viewer-id", role: "viewer", mfaEnabled: true };

      throw new Error("Token invalide");
    });
  });

  //GET /api/settings/domain

  describe("GET /api/settings/domain", () => {
    it("devrait retourner domain: null tant que rien n'a été configuré", async () => {
      mockSettingsService.get.mockResolvedValue({ domain: null });

      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ domain: null });
    });

    it("devrait retourner le domaine une fois configuré", async () => {
      mockSettingsService.get.mockResolvedValue({ domain: "ops.exemple.com" });

      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ domain: "ops.exemple.com" });
    });

    it("devrait retourner 401 sans token", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
      });

      expect(response.statusCode).toBe(401);
    });

    it("devrait retourner 401 avec un token invalide", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockInvalidToken}` },
      });

      expect(response.statusCode).toBe(401);
    });

    it("devrait retourner 403 pour un operator", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOperatorToken}` },
      });

      expect(response.statusCode).toBe(403);
      expect(mockSettingsService.get).not.toHaveBeenCalled();
    });

    it("devrait retourner 403 pour un viewer", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockViewerToken}` },
      });

      expect(response.statusCode).toBe(403);
      expect(mockSettingsService.get).not.toHaveBeenCalled();
    });
  });

  // POST /api/settings/domain

  describe("POST /api/settings/domain", () => {
    it("devrait définir un domaine valide et renvoyer 200", async () => {
      mockSettingsService.setDomain.mockResolvedValue({
        domain: "ops.exemple.com",
      });

      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { domain: "ops.exemple.com" },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ domain: "ops.exemple.com" });
      expect(mockSettingsService.setDomain).toHaveBeenCalledWith(
        "ops.exemple.com",
        DEFAULT_TENANT_ID,
      );
    });

    it.each([
      "ops.exemple.com",
      "mon-site.io",
      "sub.exemple.co.uk", 
    ])(
      "devrait accepter le domaine syntaxiquement valide : %s",
      async (domain) => {
        mockSettingsService.setDomain.mockResolvedValue({ domain });

        const response = await app.inject({
          method: "POST",
          url: "/api/settings/domain",
          headers: { authorization: `Bearer ${mockOwnerToken}` },
          payload: { domain },
        });

        expect(response.statusCode).toBe(200);
        expect(mockSettingsService.setDomain).toHaveBeenCalledWith(domain, DEFAULT_TENANT_ID);
      },
    );

    it.each([
      ["contient des espaces", "pas un domaine valide"],
      ["commence par un tiret", "-ops.exemple.com"],
      ["label vide (double point)", "ops..exemple.com"],
      ["finit par un tiret", "ops.exemple.com-"],
      ["pas de TLD du tout", "localhost"],
      ["TLD inexistant (point manquant)", "ops.exemplecom"],
      ["TLD totalement inventé", "mon-site.faux-tld-invente"],
    ])(
      "devrait retourner 400 si le domaine est mal formé (%s)",
      async (_label, domain) => {
        const response = await app.inject({
          method: "POST",
          url: "/api/settings/domain",
          headers: { authorization: `Bearer ${mockOwnerToken}` },
          payload: { domain },
        });

        expect(response.statusCode).toBe(400);
        expect(mockSettingsService.setDomain).not.toHaveBeenCalled();
      },
    );

    it("devrait retourner 400 si domain est absent du body", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: {},
      });

      expect(response.statusCode).toBe(400);
      expect(mockSettingsService.setDomain).not.toHaveBeenCalled();
    });

    it("devrait retourner 401 sans token", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        payload: { domain: "ops.exemple.com" },
      });

      expect(response.statusCode).toBe(401);
    });

    it("devrait retourner 403 pour un operator", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOperatorToken}` },
        payload: { domain: "ops.exemple.com" },
      });

      expect(response.statusCode).toBe(403);
      expect(mockSettingsService.setDomain).not.toHaveBeenCalled();
    });

    it("devrait retourner 403 pour un viewer", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockViewerToken}` },
        payload: { domain: "ops.exemple.com" },
      });

      expect(response.statusCode).toBe(403);
      expect(mockSettingsService.setDomain).not.toHaveBeenCalled();
    });

    it("devrait retourner 400 si le service lève une erreur", async () => {

      mockSettingsService.setDomain.mockRejectedValue(
        new Error("Caddy injoignable"),
      );

      const response = await app.inject({
        method: "POST",
        url: "/api/settings/domain",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { domain: "ops.exemple.com" },
      });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: "Caddy injoignable" });
    });
  });

  describe("GET /api/settings/webauthn", () => {
    it("retourne la config WebAuthn du tenant", async () => {
      mockSettingsService.getWebauthn.mockResolvedValue({
        enabled: true,
        origin: "https://auth.exemple.com",
        rpId: "auth.exemple.com",
        rpName: "Hullbay",
      });

      const response = await app.inject({
        method: "GET",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        enabled: true,
        origin: "https://auth.exemple.com",
        rpId: "auth.exemple.com",
        rpName: "Hullbay",
      });
      expect(mockSettingsService.getWebauthn).toHaveBeenCalledWith(DEFAULT_TENANT_ID);
    });

    it("retourne 401 sans token", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/settings/webauthn",
      });

      expect(response.statusCode).toBe(401);
    });

    it("retourne 403 pour un operator et un viewer", async () => {
      for (const token of [mockOperatorToken, mockViewerToken]) {
        const response = await app.inject({
          method: "GET",
          url: "/api/settings/webauthn",
          headers: { authorization: `Bearer ${token}` },
        });

        expect(response.statusCode).toBe(403);
      }
      expect(mockSettingsService.getWebauthn).not.toHaveBeenCalled();
    });
  });

  describe("POST /api/settings/webauthn", () => {
    it("enregistre la config et émet l'évènement d'audit", async () => {
      mockSettingsService.setWebauthn.mockResolvedValue({
        enabled: true,
        origin: "https://auth.exemple.com",
        rpId: "auth.exemple.com",
        rpName: "Hullbay",
      });
      const { eventBus } = await import("../../../lib/event-bus");

      const response = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { enabled: true, origin: "https://auth.exemple.com" },
      });

      expect(response.statusCode).toBe(200);
      expect(mockSettingsService.setWebauthn).toHaveBeenCalledWith(DEFAULT_TENANT_ID, {
        enabled: true,
        origin: "https://auth.exemple.com",
      });
      expect(eventBus.emit).toHaveBeenCalledWith("settings.webauthn.set", {
        userId: "owner-id",
        tenantId: DEFAULT_TENANT_ID,
        enabled: true,
      });
    });

    it("retourne 400 si enabled manque du body", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { origin: "https://auth.exemple.com" },
      });

      expect(response.statusCode).toBe(400);
      expect(mockSettingsService.setWebauthn).not.toHaveBeenCalled();
    });

    it("propage code et status d'un AuthError (domain_not_configured)", async () => {
      mockSettingsService.setWebauthn.mockRejectedValue(
        new (await import("../../auth/providers/types")).AuthError(
          "domain_not_configured",
          "activation WebAuthn nécessite un domaine public configuré",
          400,
        ),
      );

      const response = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { enabled: true },
      });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({
        error: "activation WebAuthn nécessite un domaine public configuré",
        code: "domain_not_configured",
      });
    });

    it("retourne 401 sans token et 403 pour operator", async () => {
      const noToken = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        payload: { enabled: true },
      });
      expect(noToken.statusCode).toBe(401);

      const operator = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOperatorToken}` },
        payload: { enabled: true },
      });
      expect(operator.statusCode).toBe(403);
      expect(mockSettingsService.setWebauthn).not.toHaveBeenCalled();
    });

    it("un échec non métier (base indisponible) remonte en 500 réel", async () => {
      mockSettingsService.setWebauthn.mockRejectedValue(new Error("base indisponible"));

      const response = await app.inject({
        method: "POST",
        url: "/api/settings/webauthn",
        headers: { authorization: `Bearer ${mockOwnerToken}` },
        payload: { enabled: true },
      });

      expect(response.statusCode).toBe(500);
      expect(mockSettingsService.setWebauthn).toHaveBeenCalledTimes(1);
      // L'évènement d'audit ne doit pas être émis après un échec persisté.
      const { eventBus } = await import("../../../lib/event-bus");
      expect(eventBus.emit).not.toHaveBeenCalledWith("settings.webauthn.set", expect.anything());
    });
  });
});
