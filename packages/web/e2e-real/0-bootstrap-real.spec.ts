import { test, expect } from "@playwright/test"
import { apiMe, bootstrapOwner, byButton, logoutButton, resetOwnerArtifacts, shot } from "./helpers"

/**
 * EXÉCUTÉ EN PREMIER (ordre alphabétique des fichiers, workers=1) :
 * la base `hullbay_e2e` est reset par le webServer à chaque run, donc le
 * 1er owner n'existe JAMAIS — on l'enrôle ici et on persiste son secret TOTP
 * (`.artifacts/owner.json`) pour toutes les autres specs de la campagne.
 */
test.describe.serial("bootstrap — 1er owner en conditions réelles", () => {
  test.beforeAll(() => resetOwnerArtifacts())

  test("bootstrap du compte administrateur + enrôlement TOTP forcé", async ({ page }) => {
    const owner = await bootstrapOwner(page)

    // Dashboard ouvert, session réelle posée.
    await expect(page.getByText("hullbay").first()).toBeVisible()
    await expect(logoutButton(page)).toBeVisible()
    expect(owner.secret).toMatch(/^[A-Z2-7]{16,}$/)

    // /me réel : rôle owner, tenant par défaut, MFA activée.
    await expect.poll(() => page.evaluate(() => window.localStorage.getItem("hullbay_token")))
      .toBeTruthy()
    const me = await apiMe(page)
    expect(me.role).toBe("owner")
    expect(me.mfaEnabled).toBe(true)
    expect(me.activeTenantId).toBe("tenant-default")

    await expect(byButton(page, /Créer le compte administrateur/)).toHaveCount(0)
    await shot(page, "bootstrap-owner-dashboard")
  })
})