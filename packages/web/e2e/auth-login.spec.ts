import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Tests E2E des parcours de connexion auth :
 *  - connexion LDAP (formulaire annuaire) ;
 *  - challenge MFA par clé de sécurité / passkey.
 * L'API est stubée ; la cérémonie WebAuthn navigateur est simulée.
 */

const OWNER = {
  id: "owner-1",
  email: "owner@hbox.local",
  role: "owner",
  mfaEnabled: true,
};

const authOptions = {
  challenge: "test-challenge-auth",
  rpId: "localhost",
  timeout: 60000,
  userVerification: "required",
  allowCredentials: [{ id: "cred-1", type: "public-key" }],
};

async function mockWebauthn(page: Page) {
  await page.addInitScript(() => {
    if (!("PublicKeyCredential" in window)) {
      Object.defineProperty(window, "PublicKeyCredential", {
        configurable: true,
        value: function PublicKeyCredential() {},
      });
    }
    const raw = new Uint8Array([5, 6, 7, 8]).buffer;
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

async function stubApi(page: Page, overrides: Record<string, (route: Route) => void>) {
  await page.unrouteAll();

  const defaults: Record<string, (route: Route) => void> = {
    "GET /api/auth/needs-bootstrap": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ needsBootstrap: false }),
      }),
    "GET /api/auth/providers": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { id: "corp-ldap", kind: "ldap", name: "Corporate LDAP", enabled: true },
        ]),
      }),
    "GET /api/system/environment": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ environment: "development" }),
      }),
    "GET /api/auth/me": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(OWNER),
      }),
    "GET /api/updates/check": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          updateAvailable: false,
          updateChannel: "stable",
          currentVersion: "1.0.0",
          latestVersion: "1.0.0",
        }),
      }),
    ...overrides,
  };

  await page.route("**/api/**", (route) => {
    if (route.request().method() === "OPTIONS") return route.continue();
    const method = route.request().method();
    const pathname = new URL(route.request().url())
      .pathname.replace(/\/$/, "");
    const handler = defaults[`${method} ${pathname}`];
    if (handler) return handler(route);
    return route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ error: "non stubé" }),
    });
  });
}

test("connexion LDAP : formulaire annuaire puis session", async ({ page }) => {
  await stubApi(page, {
    "POST /api/auth/ldap/corp-ldap/login": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ mfaRequired: false, token: "e2e-ldap-token" }),
      }),
  });

  await page.goto("/login", { waitUntil: "domcontentloaded" });

  await page
    .getByRole("button", { name: /Continuer avec Corporate LDAP|Continue with Corporate LDAP/i })
    .click();

  await page.getByPlaceholder(/corp\.local/i).fill("jdoe");
  await page.locator('input[type="password"]').fill("secret");
  await page
    .getByRole("button", { name: /Se connecter avec l'annuaire|Sign in with directory/i })
    .click();

  await expect(page).toHaveURL(/\/$/, { timeout: 15000 });
  await expect(page.getByText("hullbay").first()).toBeVisible();

  const token = await page.evaluate(() =>
    window.localStorage.getItem("hullbay_token"),
  );
  expect(token).toBe("e2e-ldap-token");
});

test("connexion locale : challenge MFA par passkey", async ({ page }) => {
  await mockWebauthn(page);
  await stubApi(page, {
    "POST /api/auth/login": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ mfaRequired: true, pendingToken: "pending-e2e" }),
      }),
    "POST /api/auth/mfa/webauthn/auth/options": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(authOptions),
      }),
    "POST /api/auth/mfa/webauthn/auth/verify": (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true, token: "e2e-passkey-token" }),
      }),
  });

  await page.goto("/login", { waitUntil: "domcontentloaded" });

  await page.getByPlaceholder(/owner@/).fill("owner@hbox.local");
  await page.locator('input[type="password"]').fill("secret");
  await page
    .getByRole("button", { name: /^Se connecter$|^Sign in$/i })
    .click();

  const webauthnButton = page.getByRole("button", {
    name: /clé de sécurité ou Passkey|security key or Passkey/i,
  });
  await expect(webauthnButton).toBeVisible({ timeout: 15000 });
  await webauthnButton.click();

  await expect(page).toHaveURL(/\/$/, { timeout: 15000 });

  const token = await page.evaluate(() =>
    window.localStorage.getItem("hullbay_token"),
  );
  expect(token).toBe("e2e-passkey-token");
});
