import { test, expect } from "@playwright/test"
import {
  byButton,
  addVirtualAuthenticator,
  ensureOwner,
  shot,
} from "./helpers"

/**
 * Passkey EN CONDITIONS RÉELLES (le reste de la campagne couvre bootstrap,
 * code TOTP, sécurité, SSO…) : owner déjà bootstrappé (0-bootstrap), on ajoute
 * une passkey depuis Paramètres → déconnexion → reconnexion par la passkey.
 * Cérémonie WebAuthn réelle via authenticator virtuel CDP, aucune clé physique.
 */
test.describe.serial("auth — passkey réelle", () => {
  test("ajout d'une passkey puis reconnexion via le challenge Passkey", async ({ page }) => {
    const owner = await ensureOwner(page)

    // Authenticator virtuel présent DÈS le départ : la cérémonie réelle en a besoin.
    await addVirtualAuthenticator(page)

    // 1. L'owner (déjà connecté) enregistre une nouvelle passkey.
    await page.goto("/settings")
    await page.getByTestId("settings-tab-security").click()
    await expect(page.locator('[data-testid="passkey-add"]')).toBeVisible()
    await page.locator('[data-testid="passkey-name"]').fill("Clé de test E2E")
    await page.locator('[data-testid="passkey-add"]').click()
    await expect(page.locator('[data-testid^="passkey-row-"]')).toHaveCount(1, {
      timeout: 20_000,
    })
    await expect(page.getByText("Clé de test E2E")).toBeVisible()
    await shot(page, "auth-real-passkey-enregistree")

    // 2. Déconnexion réelle.
    await byButton(page, /Déconnexion|Sign out|Log ?out/).click()
    await expect(page.locator('input[type="password"]')).toBeVisible()

    // 3. Reconnexion : mot de passe → challenge MFA → signature par PASSKEY.
    await page.locator('input[type="email"]').fill(owner.email)
    await page.locator('input[type="password"]').fill(owner.password)
    await byButton(page, /^Se connecter$|^Sign in$/).click()

    const webauthnButton = byButton(page, /clé de sécurité ou Passkey|security key or Passkey/i)
    await expect(webauthnButton).toBeVisible({ timeout: 20_000 })
    await shot(page, "auth-real-challenge-passkey")
    await webauthnButton.click()

    await expect(byButton(page, /Déconnexion|Sign out|Log ?out/)).toBeVisible({ timeout: 20_000 })
    await expect(page).toHaveURL(/\/$/)
    const token = await page.evaluate(() => window.localStorage.getItem("hullbay_token"))
    expect(token).toBeTruthy()
    await shot(page, "auth-real-session-ouverte")
  })
})