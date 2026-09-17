import { test, expect, type Page } from "@playwright/test"
import crypto from "node:crypto"

/**
 * Parcours auth COMPLET en conditions réelles :
 *   bootstrap du 1er owner → enrôlement TOTP (code calculé) → ajout d'une
 *   passkey (authenticator WebAuthn VIRTUEL via CDP, cérémonie réelle) →
 *   déconnexion → reconnexion avec challenge MFA par passkey.
 *
 * Aucun stub réseau, aucun mock de `navigator.credentials`.
 */

const OWNER = {
  email: `owner+${Date.now()}@e2e.local`,
  password: "Sup3rSecret!e2e",
}

// ── TOTP (RFC 6238, SHA-1, 6 chiffres, pas 30 s) ──
function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const c of input.replace(/=+$/, "").toUpperCase()) {
    const idx = alphabet.indexOf(c)
    if (idx === -1) continue
    bits += idx.toString(2).padStart(5, "0")
  }
  const bytes: number[] = []
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2))
  }
  return Buffer.from(bytes)
}

function totp(secret: string): string {
  const counter = Math.floor(Date.now() / 1000 / 30)
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(buf).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3]
  return (bin % 1_000_000).toString().padStart(6, "0")
}

async function addVirtualAuthenticator(page: Page) {
  const client = await page.context().newCDPSession(page)
  await client.send("WebAuthn.enable")
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })
  return { client, authenticatorId }
}

const byName = (page: Page, re: RegExp) => page.getByRole("button", { name: re })

test.describe.serial("auth — conditions réelles", () => {
  test("bootstrap → TOTP → passkey → reconnexion passkey", async ({ page }) => {
    await addVirtualAuthenticator(page)

    // 1. Bootstrap du premier owner.
    await page.goto("/")
    await expect(
      byName(page, /Créer le compte administrateur|Create administrator account/),
    ).toBeVisible()
    await page.locator('input[type="email"]').fill(OWNER.email)
    const pwds = page.locator('input[type="password"]')
    await pwds.nth(0).fill(OWNER.password)
    await pwds.nth(1).fill(OWNER.password)
    await byName(page, /Créer le compte administrateur|Create administrator account/).click()

    // 2. Enrôlement TOTP forcé.
    await expect(page).toHaveURL(/\/activate-mfa/, { timeout: 20_000 })
    const secretEl = page.locator("div.break-all").first()
    await expect
      .poll(async () => (await secretEl.textContent())?.trim() ?? "")
      .toMatch(/^[A-Z2-7]{16,}$/)
    const secret = (await secretEl.textContent())!.trim()

    // 3. La carte d'enrôlement de passkey est proposée pendant l'activation
    //    forcée (autorisée par la garde via MFA_SETUP_PATHS).
    await expect(page.locator('[data-testid="passkey-add"]')).toBeVisible()

    // 4. Confirmation TOTP → tableau de bord.
    await page.getByPlaceholder("123456").fill(totp(secret))
    await byName(page, /Confirmer l'activation|Confirm setup/).click()

    const logoutButton = byName(page, /Déconnexion|Sign out|Log ?out/)
    await expect(logoutButton).toBeVisible({ timeout: 20_000 })
    await expect(page).toHaveURL(/\/$/)

    // 5. Ajout d'une passkey depuis les Paramètres (onglet Sécurité), puis persistance.
    await page.goto("/settings")
    await page.getByTestId("settings-tab-security").click()
    await expect(page.locator('[data-testid="passkey-add"]')).toBeVisible()
    await expect(page.locator('[data-testid^="passkey-row-"]')).toHaveCount(0)
    await page.locator('[data-testid="passkey-name"]').fill("Clé de test E2E")
    await page.locator('[data-testid="passkey-add"]').click()
    await expect(page.locator('[data-testid^="passkey-row-"]')).toHaveCount(1, {
      timeout: 20_000,
    })
    await expect(page.getByText("Clé de test E2E")).toBeVisible()

    // 6. Déconnexion.
    await logoutButton.click()
    await expect(page.locator('input[type="password"]')).toBeVisible()

    // 7. Reconnexion : mot de passe puis challenge MFA par PASSKEY.
    await page.locator('input[type="email"]').fill(OWNER.email)
    await page.locator('input[type="password"]').fill(OWNER.password)
    await byName(page, /^Se connecter$|^Sign in$/).click()

    const webauthnButton = byName(
      page,
      /clé de sécurité ou Passkey|security key or Passkey/i,
    )
    await expect(webauthnButton).toBeVisible({ timeout: 20_000 })
    await webauthnButton.click()

    // 7. Session ouverte via la passkey enregistrée.
    await expect(logoutButton).toBeVisible({ timeout: 20_000 })
    await expect(page).toHaveURL(/\/$/)
    const token = await page.evaluate(() => window.localStorage.getItem("hullbay_token"))
    expect(token).toBeTruthy()
  })
})
