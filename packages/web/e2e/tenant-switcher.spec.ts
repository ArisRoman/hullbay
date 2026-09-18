import { test, expect, type Page, type Route } from "@playwright/test";

/**
 * Tests E2E du TenantSwitcher (Phase 5B §14).
 * L'API est stubée ; on simule un compte membre de deux tenants (owner sur
 * tenant-a, viewer sur tenant-b) et on vérifie que la bascule re-signe la
 * session (nouveau token), change le rôle affiché/navigation, et que les
 * requêtes suivantes portent le nouveau token (isolation observable depuis l'UI).
 */

let projectsAuthHeaders: string[] = [];

const ME_A = {
  id: "u-1",
  email: "multi@hbox.local",
  role: "owner",
  mfaEnabled: true,
  mfaRequired: false,
  activeTenantId: "tenant-a",
  tenants: [
    { tenantId: "tenant-a", role: "owner", slug: "tenant-a" },
    { tenantId: "tenant-b", role: "viewer", slug: "tenant-b" },
  ],
};

const ME_B = {
  ...ME_A,
  role: "viewer",
  activeTenantId: "tenant-b",
};

async function stubApi(page: Page, meState: { me: typeof ME_A }) {
  await page.unrouteAll();
  projectsAuthHeaders = [];

  await page.route("**/api/**", (route) => {
    if (route.request().method() === "OPTIONS") return route.continue();
    const method = route.request().method();
    const pathname = new URL(route.request().url()).pathname.replace(/\/$/, "");

    if (method === "GET" && pathname === "/api/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(meState.me),
      });
    }

    if (method === "GET" && pathname === "/api/system/environment") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ environment: "development" }),
      });
    }

    if (method === "GET" && pathname === "/api/updates/check") {
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

    if (method === "GET" && pathname === "/api/projects") {
      projectsAuthHeaders.push(route.request().headers()["authorization"] ?? "");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            id: "p-1",
            name: "Projet 1",
            slug: "projet-1",
            clusterId: "c-1",
            status: "draft",
            description: null,
          },
        ]),
      });
    }

    if (method === "GET" && pathname === "/api/clusters") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { id: "c-1", name: "cluster-1", isDefault: true, status: "ready" },
        ]),
      });
    }

    if (method === "POST" && pathname === "/api/auth/session/switch-tenant") {
      meState.me = ME_B;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ token: "e2e-token-b", activeTenantId: "tenant-b" }),
      });
    }

    return route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ error: "non stubé" }),
    });
  });
}

test("bascule de tenant : re-sign de session, rôle et nav suivent, requêtes portent le nouveau token", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("hullbay_token", "e2e-token-a");
  });

  const meState = { me: ME_A };
  await stubApi(page, meState);

  await page.goto("/", { waitUntil: "domcontentloaded" });

  // Le switcher n'apparaît que pour un compte multi-tenant : deux slugs listés.
  const switchButton = page.getByRole("button", { name: /Changer de tenant|Switch tenant/i });
  await expect(switchButton).toBeVisible({ timeout: 15000 });
  await expect(switchButton).toContainText("tenant-a");

  // owner sur tenant-a → les routes owner-only sont visibles.
  await expect(page.getByRole("link", { name: "Serveurs" })).toBeVisible();

  // Bascule vers tenant-b (viewer).
  await switchButton.click();
  await page.getByRole("menuitem", { name: /tenant-b/ }).click();

  // La session est re-signée : le token stocké est remplacé.
  await expect
    .poll(() =>
      page.evaluate(() => window.localStorage.getItem("hullbay_token")),
    )
    .toBe("e2e-token-b");

  // /me refetch : rôle effectif du tenant cible (viewer) → la route owner-only
  // disparaît et le badge de rôle du sidebar change.
  await expect(switchButton).toContainText("tenant-b");
  await expect(page.getByRole("link", { name: "Serveurs" })).toHaveCount(0);
  await expect(page.locator("aside").getByText("viewer", { exact: true })).toBeVisible();

  // Les données rechargées après la bascule portent le nouveau token (isolation
  // de session côté UI : le back scoped par claim verrait le nouveau tenant).
  await expect.poll(() => projectsAuthHeaders.at(-1)).toBe("Bearer e2e-token-b");
});