import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Tests E2E de la gestion des clés de sécurité / passkeys (Paramètres).
 * L'API est entièrement stubée ; la cérémonie WebAuthn navigateur est simulée
 * via `navigator.credentials` pour rester sans authentificateur réel.
 */

const OWNER = {
  id: "owner-1",
  email: "owner@hbox.local",
  role: "owner",
  mfaEnabled: true,
};

const registerOptions = {
  challenge: "test-challenge-register",
  rp: { id: "localhost", name: "Hullbay" },
  user: {
    id: "dXNlci0x",
    name: "owner@hbox.local",
    displayName: "Owner",
  },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  timeout: 60000,
  attestation: "none",
  excludeCredentials: [],
};

type Credential = {
  id: string;
  credentialId: string;
  name: string;
  deviceType: string;
  createdAt: string;
  lastUsedAt: string | null;
};

async function mockWebauthn(page: Page) {
  await page.addInitScript(() => {
    if (!("PublicKeyCredential" in window)) {
      Object.defineProperty(window, "PublicKeyCredential", {
        configurable: true,
        value: function PublicKeyCredential() {},
      });
    }
    const raw = new Uint8Array([1, 2, 3, 4]).buffer;
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: {
        create: async () => ({
          id: "browser-cred-1",
          rawId: raw,
          type: "public-key",
          response: {
            clientDataJSON: raw,
            attestationObject: raw,
            getTransports: () => ["internal"],
          },
        }),
        get: async () => ({
          id: "browser-cred-1",
          rawId: raw,
          type: "public-key",
          response: {
            clientDataJSON: raw,
            authenticatorData: raw,
            signature: raw,
            userHandle: raw,
          },
        }),
      },
    });
  });
}

async function login(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("hullbay_token", "e2e-token");
  });
}

type Handler = (route: Route) => void;

function pathMatches(pattern: string, actualPath: string): boolean {
  const patternParts = pattern.split("/").filter(Boolean);
  const actualParts = actualPath.split("/").filter(Boolean);
  if (patternParts.length !== actualParts.length) return false;
  return patternParts.every(
    (part, i) => part.startsWith(":") || part === actualParts[i],
  );
}

async function stubApi(
  page: Page,
  opts: {
    getList: () => Credential[];
    onRegister?: () => void;
    onDelete?: (id: string) => void;
    overrides?: Record<string, Handler>;
  },
) {
  await page.unrouteAll();

  await page.route("**/api/**", (route) => {
    if (route.request().method() === "OPTIONS") return route.continue();

    const method = route.request().method();
    const pathname = new URL(route.request().url()).pathname.replace(/\/$/, "");
    const key = `${method} ${pathname}`;

    const override = opts.overrides?.[key];
    if (override) return override(route);

    if (key === "GET /api/system/environment") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ environment: "development" }),
      });
    }
    if (key === "GET /api/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(OWNER),
      });
    }
    if (key === "GET /api/updates/check") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          updateAvailable: false,
          updateChannel: "stable",
          currentVersion: "1.0.0",
          latestVersion: "1.0.0",
        }),
      });
    }
    if (key === "GET /api/auth/mfa/webauthn/credentials") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(opts.getList()),
      });
    }
    if (key === "POST /api/auth/mfa/webauthn/register/options") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(registerOptions),
      });
    }
    if (key === "POST /api/auth/mfa/webauthn/register/verify") {
      opts.onRegister?.();
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ verified: true, credentialId: "wc-e2e-1" }),
      });
    }
    if (
      method === "DELETE" &&
      pathMatches("/api/auth/mfa/webauthn/credentials/:id", pathname)
    ) {
      opts.onDelete?.(pathname.split("/").pop() ?? "");
      return route.fulfill({ status: 204, body: "" });
    }

    return route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ error: "non stubé" }),
    });
  });
}

test.beforeEach(async ({ page }) => {
  await login(page);
  await mockWebauthn(page);
});

test("affiche les clés enregistrées et leur dernière utilisation", async ({
  page,
}) => {
  await stubApi(page, {
    getList: () => [
      {
        id: "wc-1",
        credentialId: "cred-1",
        name: "YubiKey perso",
        deviceType: "singleDevice",
        createdAt: "2026-01-02T10:00:00.000Z",
        lastUsedAt: "2026-02-01T10:00:00.000Z",
      },
    ],
  });

  await page.goto("/settings");
  await page.getByTestId("settings-tab-security").click();

  await expect(page.getByTestId("passkey-row-wc-1")).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByTestId("passkey-row-wc-1")).toContainText(
    "YubiKey perso",
  );
});

test("ajoute une clé : cérémonie navigateur puis vérification serveur", async ({
  page,
}) => {
  let credentials: Credential[] = [];

  await stubApi(page, {
    getList: () => credentials,
    onRegister: () => {
      credentials = [
        {
          id: "wc-e2e-1",
          credentialId: "browser-cred-1",
          name: "Touch ID test",
          deviceType: "singleDevice",
          createdAt: "2026-09-17T12:00:00.000Z",
          lastUsedAt: null,
        },
        ...credentials,
      ];
    },
  });

  await page.goto("/settings");
  await page.getByTestId("settings-tab-security").click();
  await expect(page.getByTestId("passkey-add")).toBeVisible({ timeout: 15000 });

  await page.getByTestId("passkey-name").fill("Touch ID test");
  await page.getByTestId("passkey-add").click();

  await expect(page.getByTestId("passkey-row-wc-e2e-1")).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByTestId("passkey-row-wc-e2e-1")).toContainText(
    "Touch ID test",
  );
});

test("supprime une clé après confirmation", async ({ page }) => {
  let credentials: Credential[] = [
    {
      id: "wc-del",
      credentialId: "cred-del",
      name: "Ancienne clé",
      deviceType: "singleDevice",
      createdAt: "2026-01-01T00:00:00.000Z",
      lastUsedAt: null,
    },
  ];

  await stubApi(page, {
    getList: () => credentials,
    onDelete: (id) => {
      credentials = credentials.filter((c) => c.id !== id);
    },
  });

  await page.goto("/settings");
  await page.getByTestId("settings-tab-security").click();
  await expect(page.getByTestId("passkey-row-wc-del")).toBeVisible({
    timeout: 15000,
  });

  await page.getByTestId("passkey-delete-wc-del").click();
  await page
    .getByRole("button", { name: /supprimer|remove/i })
    .last()
    .click();

  await expect(page.getByTestId("passkey-row-wc-del")).toHaveCount(0, {
    timeout: 15000,
  });
});
