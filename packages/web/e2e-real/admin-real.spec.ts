import { test, expect, type Page } from "@playwright/test"
import { byButton, ensureOwner, apiMe, userRow, grantTenantToOwner, emailInput, passwordInput, shot } from "./helpers"

/**
 * Administration EN CONDITIONS RÉELLES (owner) :
 *  - CRUD d'un provider OIDC dans l'UI : création, test de connexion réel,
 *    édition (secret masqué « •••••••• »), activation/désactivation, suppression ;
 *  - gestion des comptes : création d'un operator, changement de rôle, suppression ;
 *  - TenantSwitcher réel : rattachement du owner à un 2e tenant (via la base
 *    e2e — aucune API d'auto-attribution), bascule de session, retour.
 */

const PROVIDER = {
  id: "e2e-admin-crud",
  name: "CRUD Admin IdP",
}

const OIDC_CONFIG = {
  issuer: "http://127.0.0.1:5280",
  clientId: "hullbay-admin-crud",
  clientSecret: "admin-crud-secret",
  redirectUri: "http://localhost:5274/api/auth/sso/e2e-admin-crud/callback",
}

function providerCard(page: Page, id: string) {
  return page.locator("li").filter({ hasText: id })
}

async function openProviderModal(page: Page) {
  await page.goto("/providers")
  await expect(page.getByRole("button", { name: "Nouveau provider" })).toBeVisible()
  await shot(page, "admin-real-providers-liste-initiale")
  await page.getByRole("button", { name: "Nouveau provider" }).click()
  await expect(page.getByRole("heading", { name: "Nouveau provider" })).toBeVisible()
}

async function fillField(page: Page, label: string, value: string | number) {
  const field = page.locator("label").filter({ hasText: label }).locator("..") // container du champ
  const input = field.locator("input, textarea").first()
  await input.fill(String(value))
}

test.describe.serial("admin (owner) — conditions réelles", () => {
  let owner: { email: string; password: string; secret: string }

  // Le storage localStorage n'est PAS partagé entre tests (contexte frais par
  // test) : on ré-authentifie la PAGE de chaque test, pas un contexte jetable.
  test.beforeEach(async ({ page }) => {
    owner = await ensureOwner(page, { logout: false })
  })

  test("provider OIDC : création → test de connexion → édition avec secret masqué → suppression", async ({
    page,
  }) => {
    await openProviderModal(page)

    // Protocole OIDC (défaut du modal). Identifiant + nom + activé.
    await fillField(page, "Identifiant", PROVIDER.id)
    await fillField(page, "Nom", PROVIDER.name)
    await page.getByRole("dialog").getByLabel("Activé").click()

    // Configuration : issuer, clientId, secret (masqué à la saisie), redirectUri.
    await fillField(page, /Issuer/, OIDC_CONFIG.issuer)
    await fillField(page, "Client ID", OIDC_CONFIG.clientId)
    await fillField(page, "Client secret", OIDC_CONFIG.clientSecret)
    await fillField(page, /Redirect URI/, OIDC_CONFIG.redirectUri)

    await page.getByRole("button", { name: "Enregistrer" }).click()
    await expect(page.getByText("Provider créé")).toBeVisible({ timeout: 15_000 })

    // Carte du provider au premier plan de la liste.
    const card = providerCard(page, PROVIDER.id)
    await expect(card).toBeVisible()
    await expect(card.getByText("actif")).toBeVisible()
    await expect(card.getByText("OIDC")).toBeVisible()
    await shot(page, "admin-real-provider-cree")

    // Test de connexion RÉEL : découverte OIDC contre le fake IdP :5280.
    await card.getByRole("button", { name: "Tester la connexion" }).click()
    await expect(page.getByText("Connexion OK — config valide")).toBeVisible({ timeout: 20_000 })

    // Édition : le secret est refusé en clair ; marqueur de présence, non la valeur.
    await card.getByRole("button", { name: "Modifier" }).click()
    await expect(page.getByRole("dialog").getByRole("heading", { name: new RegExp(PROVIDER.name) })).toBeVisible()
    const secretInput = page.locator("label").filter({ hasText: "Client secret" }).locator("..").locator("input")
    await expect(secretInput).toHaveValue(/••••••••/i)
    await fillField(page, "Client ID", "hullbay-admin-crud-v2")
    await page.getByRole("button", { name: "Enregistrer" }).click()
    await expect(page.getByText("Provider mis à jour")).toBeVisible({ timeout: 15_000 })

    // Désactivation (le provider « local » reste actif → autorisé).
    await card.getByLabel("Activé").click()
    await expect(page.getByText("Provider inactif")).toBeVisible({ timeout: 10_000 })
    await shot(page, "admin-real-provider-inactif")

    // Suppression réelle (dialog de confirmation — Prompt/Radix → alertdialog).
    await card.getByRole("button", { name: "Supprimer" }).click()
    await page.getByRole("alertdialog").getByRole("button", { name: "Supprimer" }).click()
    await expect(page.getByText("Provider supprimé")).toBeVisible({ timeout: 15_000 })
    await expect(providerCard(page, PROVIDER.id)).toHaveCount(0)
  })

  test("gestion des comptes : création operator, rôle, suppression", async ({ page }) => {
    const email = "operator@e2e.local"

    await page.goto("/users")
    await expect(page.getByRole("heading", { name: "Utilisateurs" })).toBeVisible()

    await page.getByRole("button", { name: "Nouvel utilisateur" }).click()
    await expect(page.getByRole("heading", { name: /Nouvel utilisateur/i })).toBeVisible()
    await page.locator('input[type="email"]').fill(email)
    await page.locator('input[type="password"]').fill("Operateur#2026")
    // Rôle : operator (sélecteur radix — le trigger est un <button role="combobox">).
    const roleSelect = page.locator("label").filter({ hasText: "Rôle" }).locator("..").getByRole("combobox")
    await roleSelect.click()
    await page.getByRole("option", { name: /operator/ }).click()
    await page.getByRole("button", { name: "Créer le compte" }).click()
    await expect(page.getByText("Compte créé")).toBeVisible({ timeout: 15_000 })

    const row = userRow(page, email)
    await expect(row).toBeVisible()
    await expect(row.getByText("operator", { exact: true })).toBeVisible()
    await shot(page, "admin-real-utilisateur-cree")

    // Rôle → owner (menu d'action), puis suppression.
    await row.getByRole("button").first().click()
    await page.getByRole("menuitem", { name: /owner/ }).click()
    await expect(page.getByText("Rôle changé : owner")).toBeVisible({ timeout: 15_000 })

    await row.getByRole("button").first().click()
    await page.getByRole("menuitem", { name: /Supprimer/ }).click()
    // Dialog de confirmation = Prompt (Radix AlertDialog → role="alertdialog").
    await page.getByRole("alertdialog").getByRole("button", { name: "Supprimer" }).click()
    await expect(page.getByText("Compte supprimé")).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText(email)).toHaveCount(0)
  })

  test("TenantSwitcher réel : rattachement 2e tenant → bascule de session → retour", async ({
    page,
  }) => {
    // Rattachement DIRECT à la base e2e (l'app n'expose pas d'auto-attribution).
    await grantTenantToOwner("tenant-e2e", "viewer")
    await page.reload()

    const switcher = page.getByLabel("Changer de tenant")
    await expect(switcher).toBeVisible({ timeout: 15_000 })
    await expect(switcher).toContainText("default")

    // Bascule → le JWT est re-signé avec le nouveau tenantId (session-scoped).
    await switcher.click()
    await page.getByRole("menuitem", { name: /e2e/ }).click()
    await expect(switcher).toContainText("e2e", { timeout: 15_000 })
    const meE2e = await apiMe(page)
    expect(meE2e.activeTenantId).toBe("tenant-e2e")
    await shot(page, "admin-real-tenant-e2e-actif")

    // Retour au tenant par défaut.
    await switcher.click()
    await page.getByRole("menuitem", { name: /default/ }).click()
    await expect(switcher).toContainText("default", { timeout: 15_000 })
    const meDefault = await apiMe(page)
    expect(meDefault.activeTenantId).toBe("tenant-default")
  })
})