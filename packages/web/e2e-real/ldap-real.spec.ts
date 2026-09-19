import { test, expect, type Page } from "@playwright/test"
import { byButton, apiMe, ensureOwner, userRow, shot } from "./helpers"

/**
 * SSO LDAP EN CONDITIONS RÉELLES :
 *   provider configuré via l'UI → bind service account + recherche + bind
 *   utilisateur réels contre le fake annuaire :1389 → test de connexion →
 *   login par le formulaire « annuaire » → identité en attente → approbation →
 *   second login → session fédérée.
 */

const PROVIDER = {
  id: "e2e-ldap",
  name: "Annuaire e2e",
}

const CONFIG = {
  url: "ldaps://127.0.0.1:1389", // ldapts de l'API force le TLS (tlsOptions) → fake en ldaps.
  bindDn: "cn=admin,dc=e2e,dc=local",
  bindSecret: "admin-secret",
  searchBase: "ou=people,dc=e2e,dc=local",
  searchFilter: "(&(objectClass=person)(uid={{username}}))",
  stableAttr: "objectGUID",
}

const LDAP_USER = { username: "jdoe", password: "jdoe-secret", email: "jdoe@e2e.local" }

async function fillField(page: Page, label: RegExp | string, value: string) {
  const container = page.locator("label").filter({ hasText: label }).locator("..")
  await container.locator("input, textarea").first().fill(value)
}

async function createLdapProvider(page: Page) {
  await page.goto("/providers")
  await page.getByRole("button", { name: "Nouveau provider" }).click()

  // Protocole → LDAP (changement de kind : la config du modal change réellement).
  // Le trigger du sélecteur radix est un <button role="combobox">.
  const kindSelect = page.locator("label").filter({ hasText: "Protocole" }).locator("..").getByRole("combobox")
  await kindSelect.click()
  await page.getByRole("option", { name: "LDAP — annuaire d'entreprise" }).click()

  await fillField(page, "Identifiant", PROVIDER.id)
  await fillField(page, "Nom", PROVIDER.name)
  await page.getByRole("dialog").getByLabel("Activé").click()
  await fillField(page, /LDAP server|URL du serveur LDAP/, CONFIG.url)
  await fillField(page, /DN du compte de service/, CONFIG.bindDn)
  await fillField(page, /Mot de passe du compte de service/, CONFIG.bindSecret)
  await fillField(page, /Base de recherche utilisateurs/, CONFIG.searchBase)
  await fillField(page, /Filtre de recherche/, CONFIG.searchFilter)
  await fillField(page, /Attribut stable/, CONFIG.stableAttr)

  await page.getByRole("button", { name: "Enregistrer" }).click()
  await expect(page.getByText("Provider créé")).toBeVisible({ timeout: 15_000 })
  await shot(page, "ldap-real-provider-cree")
}

async function ldapLogin(page: Page) {
  await page.goto("/login")
  await expect(byButton(page, new RegExp(`Continuer avec ${PROVIDER.name}`))).toBeVisible({ timeout: 15_000 })
  await byButton(page, new RegExp(`Continuer avec ${PROVIDER.name}`)).click()

  // Formulaire annuaire : titre + champs username/password.
  await expect(page.getByRole("heading", { name: new RegExp(PROVIDER.name) })).toBeVisible()
  await page.getByPlaceholder(/jdupont|corp\.local/).fill(LDAP_USER.username)
  await page.locator('input[type="password"]').fill(LDAP_USER.password)
  await shot(page, "ldap-real-formulaire-annuaire")
  await byButton(page, /^Se connecter avec l'annuaire$/).click()
}

test.describe.serial("SSO LDAP — conditions réelles", () => {
  test("provider : création UI + test de connexion (bind service réel)", async ({ page }) => {
    await ensureOwner(page)
    await createLdapProvider(page)

    const card = page.locator("li").filter({ hasText: PROVIDER.id })
    await card.getByRole("button", { name: "Tester la connexion" }).click()
    await expect(page.getByText("Connexion OK — config valide")).toBeVisible({ timeout: 20_000 })
    await shot(page, "ldap-real-test-connexion-ok")
  })

  test("login annuaire → identité en attente (toast réel, pas de session)", async ({ page }) => {
    await page.goto("/login")
    await ldapLogin(page)

    const pendingToast = page.getByText(/en attente de validation par un administrateur/)
    await expect(pendingToast).toBeVisible({ timeout: 15_000 })
    // Le toast reprend l'identifiant SAISI (username), pas l'email de l'annuaire.
    await expect(pendingToast).toContainText(LDAP_USER.username)
    await shot(page, "ldap-real-pending-toast")

    // Toujours déconnecté (compte non approuvé) — aucun token posé.
    await expect(page.getByRole("button", { name: /^Se connecter avec l'annuaire$/ })).toBeVisible()
  })

  test("approbation owner → compte fédéré créé", async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    const owner = await ensureOwner(page)

    await page.goto("/providers")
    await page.getByRole("tab", { name: /Approbations en attente/ }).click()
    const pending = page.locator("li").filter({ hasText: LDAP_USER.email })
    await expect(pending).toBeVisible({ timeout: 15_000 })
    await shot(page, "ldap-real-approbations-liste")
    await pending.getByRole("button", { name: "Approuver" }).click()

    await page.getByRole("heading", { name: new RegExp(LDAP_USER.email) }).waitFor()
    await page.getByRole("button", { name: "Identité approuvée" }).click()
    await expect(page.getByText("Identité approuvée")).toBeVisible({ timeout: 15_000 })

    await page.goto("/users")
    const row = userRow(page, LDAP_USER.email)
    // Badge de rôle CSS « capitalize » → « Viewer », pas « viewer ».
    await expect(row.getByText(/viewer/i)).toBeVisible({ timeout: 15_000 })
    await shot(page, "ldap-real-utilisateur-federe")

    await expect(byButton(page, /Déconnexion/)).toBeVisible()
    await context.close()
    void owner
  })

  test("second login annuaire → session fédérée (rôle viewer)", async ({ page }) => {
    await page.goto("/login")
    await ldapLogin(page)

    await expect(byButton(page, /Déconnexion/)).toBeVisible({ timeout: 20_000 })
    await expect(page).toHaveURL(/\/$/)

    const me = await apiMe(page)
    expect(me.email).toBe(LDAP_USER.email)
    expect(me.role).toBe("viewer")
    await shot(page, "ldap-real-session-federe")

    await expect(page.getByText("Authentification")).toHaveCount(0)
    await expect(page.getByText("Utilisateurs")).toHaveCount(0)
  })
})