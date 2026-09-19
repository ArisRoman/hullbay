import { test, expect, type Page } from "@playwright/test"
import { byButton, apiMe, ensureOwner, userRow, shot } from "./helpers"

/**
 * SSO OIDC EN CONDITIONS RÉELLES :
 *   provider configuré via l'UI → découverte OIDC + test de connexion réels
 *   (le fake IdP ferait échouer un issuer erroné) → premier login → identité en
 *   attente → approbation par l'owner → second login → session fédérée.
 * Le lien avec l'IdP est réel : navigateur → authorize (PKCE) → callback →
 *   échange code→tokens → validation RS256 via JWKS.
 */

const PROVIDER = {
  id: "e2e-oidc",
  name: "Corp IdP",
}

const CONFIG = {
  issuer: "http://127.0.0.1:5280",
  clientId: "hullbay-e2e",
  clientSecret: "e2e-oidc-secret",
  redirectUri: "http://localhost:5274/api/auth/sso/e2e-oidc/callback",
}

const FEDERATED_USER = { email: "jdoe@corp.local", sub: "sub-jdoe" }

async function fillField(page: Page, label: RegExp | string, value: string) {
  const container = page.locator("label").filter({ hasText: label }).locator("..")
  await container.locator("input, textarea").first().fill(value)
}

async function createOidcProvider(page: Page) {
  await page.goto("/providers")
  await page.getByRole("button", { name: "Nouveau provider" }).click()
  await fillField(page, "Identifiant", PROVIDER.id)
  await fillField(page, "Nom", PROVIDER.name)
  await page.getByRole("dialog").getByLabel("Activé").click()
  await fillField(page, /Issuer/, CONFIG.issuer)
  await fillField(page, "Client ID", CONFIG.clientId)
  await fillField(page, "Client secret", CONFIG.clientSecret)
  await fillField(page, /Redirect URI/, CONFIG.redirectUri)
  await page.getByRole("button", { name: "Enregistrer" }).click()
  await expect(page.getByText("Provider créé")).toBeVisible({ timeout: 15_000 })
  await shot(page, "oidc-real-provider-cree")
}

test.describe.serial("SSO OIDC — conditions réelles", () => {
  test("provider : création UI + test de connexion (découverte réelle)", async ({ page }) => {
    await ensureOwner(page)
    await createOidcProvider(page)

    const card = page.locator("li").filter({ hasText: PROVIDER.id })
    await card.getByRole("button", { name: "Tester la connexion" }).click()
    await expect(page.getByText("Connexion OK — config valide")).toBeVisible({ timeout: 20_000 })
    await shot(page, "oidc-real-test-connexion-ok")
  })

  test("premier login → /login?pending=1 + bannière d'identité en attente", async ({ page }) => {
    await page.goto("/login")

    await expect(byButton(page, /Continuer avec Corp IdP/)).toBeVisible({ timeout: 15_000 })
    await shot(page, "oidc-real-login-avant")
    await byButton(page, /Continuer avec Corp IdP/).click()

    // Le callback pose réellement le code → state → PKCE contre le fake IdP.
    await expect(page).toHaveURL(/\/login\?pending=1/, { timeout: 20_000 })
    const banner = page.getByRole("status").filter({ hasText: "Compte en attente d'approbation" })
    await expect(banner).toBeVisible()
    await expect(banner).toContainText(FEDERATED_USER.email)
    await shot(page, "oidc-real-pending-banniere")
  })

  test("approbation owner sur l'onglet en attente", async ({ browser }) => {
    // Navigateur owner séparé (le 1er contexte est resté déconnecté).
    const context = await browser.newContext()
    const page = await context.newPage()
    const owner = await ensureOwner(page)

    await page.goto("/providers")
    await page.getByRole("tab", { name: /Approbations en attente/ }).click()
    const pending = page.locator("li").filter({ hasText: FEDERATED_USER.email })
    await expect(pending).toBeVisible({ timeout: 15_000 })
    await shot(page, "oidc-real-approbations-liste")
    await pending.getByRole("button", { name: "Approuver" }).click()

    // Tenant + rôle par défaut (Default / viewer) — le choix est réel.
    await page.getByRole("heading", { name: new RegExp(FEDERATED_USER.email) }).waitFor()
    await page.getByRole("button", { name: "Identité approuvée" }).click()
    await expect(page.getByText("Identité approuvée")).toBeVisible({ timeout: 15_000 })
    await expect(page.locator("li").filter({ hasText: FEDERATED_USER.email })).toHaveCount(0)
    await shot(page, "oidc-real-approbation-faite")

    // Le compte fédéré apparaît dans la liste des utilisateurs (rôle viewer).
    await page.goto("/users")
    const row = userRow(page, FEDERATED_USER.email)
    // Badge de rôle CSS « capitalize » → « Viewer », pas « viewer ».
    await expect(row.getByText(/viewer/i)).toBeVisible({ timeout: 15_000 })
    await shot(page, "oidc-real-utilisateur-federe")

    await expect(byButton(page, /Déconnexion/)).toBeVisible()
    await context.close()
    void owner
  })

  test("second login → session fédérée (rôle viewer)", async ({ page }) => {
    await page.goto("/login")
    await expect(byButton(page, /Continuer avec Corp IdP/)).toBeVisible({ timeout: 15_000 })
    await byButton(page, /Continuer avec Corp IdP/).click()

    await expect(byButton(page, /Déconnexion/)).toBeVisible({ timeout: 20_000 })
    await expect(page).toHaveURL(/\/$/)

    const me = await apiMe(page)
    expect(me.email).toBe(FEDERATED_USER.email)
    expect(me.role).toBe("viewer")
    expect(me.activeTenantId).toBe("tenant-default")
    await shot(page, "oidc-real-session-federe")

    // Le viewer ne voit pas l'admin auth (nav owner-only) — RBAC réel côté UI.
    await expect(page.getByText("Authentification")).toHaveCount(0)
    await expect(page.getByText("Utilisateurs")).toHaveCount(0)
  })
})