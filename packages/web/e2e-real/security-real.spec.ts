import { test, expect, devices } from "@playwright/test"
import { byButton, ensureOwner, persistOwner, loginLocal, emailInput, passwordInput, totp, shot, e2ePrisma } from "./helpers"

/**
 * Sécurité EN CONDITIONS RÉELLES :
 *  - rate-limit réel sur le formulaire de login (policy seedée : 3 échecs puis
 *    blocage 4 s). Semantique lue dans rate-limit.ts : recordFailure() pousse
 *    l'échec puis arme le blocage quand failures >= maxFailures — le blocage
 *    est donc armé au 3e échec (qui renvoie encore 401) et c'est la 4e
 *    tentative qui reçoit un 429 + Retry-After.
 *  - changement de mot de passe puis reconnexion ;
 *  - révocation d'une session d'un AUTRE appareil (2e contexte navigateur) ;
 *  - journal d'audit réel filtré.
 */

// POST /api/auth/login → code HTTP réel, sans dépendre du texte i18n.
async function attemptLogin(page: import("@playwright/test").Page, email: string, password: string): Promise<number> {
  await emailInput(page).fill(email)
  await passwordInput(page).fill(password)
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/auth/login"), { timeout: 10_000 }),
    byButton(page, /^Se connecter$|^Sign in$/).click(),
  ])
  return res.status()
}

test.describe.serial("sécurité — conditions réelles", () => {
  let owner: { email: string; password: string; secret: string }

  // Contexte frais par test (localStorage non partagé) → authentifier la page
  // de chaque test, comme dans les autres specs. Le succès reset aussi le
  // bucket rate-limit du compte (state déterministe au début de chaque test).
  test.beforeEach(async ({ page }) => {
    owner = await ensureOwner(page, { logout: false })
  })

  test("rate-limit réel : 3e échec arme, 4e tentative → 429 + Retry-After, formulaire verrouillé, débloqué (backoff 4 s)", async ({
    page,
  }) => {
    await byButton(page, /Déconnexion|Sign out/).click()
    await expect(emailInput(page).first()).toBeVisible({ timeout: 15_000 })

    const banner = page.getByRole("alert").filter({ hasText: "Trop de tentatives" })

    // Tentatives réelles → 401 tant que le seuil n'est pas atteint.
    expect(await attemptLogin(page, owner.email, "MauvaisMot2!passe")).toBe(401)
    expect(await attemptLogin(page, owner.email, "MauvaisMot2!passe")).toBe(401)
    expect(await attemptLogin(page, owner.email, "MauvaisMot2!passe")).toBe(401)

    // 4e tentative → 429 réel + Retry-After (backoff armé au 3e échec).
    expect(await attemptLogin(page, owner.email, "MauvaisMot2!passe")).toBe(429)

    await expect(banner).toBeVisible()
    await expect(banner).toContainText(/Réessayez dans \d+ s?\./)
    await expect(emailInput(page)).toBeDisabled()
    await expect(passwordInput(page)).toBeDisabled()
    await shot(page, "security-real-rate-limit-bloque")

    // Backoff expiré → verrou relâché (Réessayez… a disparu).
    await expect(banner).not.toBeVisible({ timeout: 15_000 })
    await expect(emailInput(page)).toBeEnabled()

    // Connexion valide repasse immédiatement (bucket réellement reset par le succès).
    await emailInput(page).fill(owner.email)
    await passwordInput(page).fill(owner.password)
    await byButton(page, /^Se connecter$|^Sign in$/).click()
    await expect(page.getByPlaceholder("123456")).toBeVisible({ timeout: 15_000 })
    await page.getByPlaceholder("123456").fill(totp(owner.secret))
    await byButton(page, /^Valider$/).click()
    await expect(byButton(page, /Déconnexion|Sign out/)).toBeVisible({ timeout: 20_000 })
  })

  test("changement de mot de passe réel, puis reconnexion avec le nouveau", async ({ page }) => {
    const current = owner.password
    const next = "NouveauMdp*2026!"

    await page.goto("/settings")
    await page.getByTestId("settings-tab-security").click()
    const pwds = page.locator('input[type="password"]')
    await pwds.nth(0).fill(current)
    await pwds.nth(1).fill(next)
    await pwds.nth(2).fill(next)
    await byButton(page, /Changer le mot de passe/).click()
    await expect(page.getByText("Mot de passe modifié")).toBeVisible({ timeout: 15_000 })
    await shot(page, "security-real-mot-de-passe-change")
    owner = { ...owner, password: next }
    persistOwner(owner)

    await byButton(page, /Déconnexion|Sign out/).click()
    await expect(emailInput(page).first()).toBeVisible({ timeout: 15_000 })
    await loginLocal(page, owner)
    await expect(page.getByText("hullbay").first()).toBeVisible()
  })

  test("révocation d'une session d'un AUTRE appareil (Appareils connectés)", async ({ page, browser }) => {
    await page.goto("/sessions")

    // 2e appareil (UA iPad) → nouvelle jti réelle, distinguée dans la table.
    const second = await browser.newContext({ userAgent: devices["iPad Mini"].userAgent })
    const pageB = await second.newPage()
    await loginLocal(pageB, owner)
    await expect(byButton(pageB, /Déconnexion|Sign out/)).toBeVisible()

    // Capturer le jti iPad en base : c'est la session la PLUS récente du compte
    // (créée après celles de la page courante). Vérité serveur — l'API ne persiste
    // PAS le user-agent, le tableau ne permet pas d'identifier l'appareil.
    const prisma = e2ePrisma()
    try {
      const ownerDb = await prisma.user.findUnique({ where: { email: owner.email } })
      expect(ownerDb).toBeTruthy()
      const target = await prisma.userSession.findFirst({
        where: { userId: ownerDb!.id, revokedAt: null },
        orderBy: { createdAt: "desc" },
      })
      expect(target).toBeTruthy()
      const targetJti = target!.jti

      // Rechargement pour voir la session iPad (le tableau ne se rafraîchit pas
      // tout seul). L'en-tête est exclu (pas de bouton), la session courante aussi
      // (badge « Cet appareil ») → le top restant est la session iPad la plus récente.
      await page.reload()
      const otherRow = page
        .getByRole("row")
        .filter({ hasText: "Révoquer" })
        .filter({ hasNotText: "Cet appareil" })
        .first()
      await expect(otherRow.getByRole("button", { name: /Révoquer/ })).toBeVisible({ timeout: 15_000 })
      await shot(page, "security-real-sessions-deux-appareils")
      await otherRow.getByRole("button", { name: /Révoquer/ }).click()
      // Confirmation dans le Prompt (Radix AlertDialog → role="alertdialog").
      await page.getByRole("alertdialog").getByRole("button", { name: /Révoquer/ }).click()

      // La session cible est marquée révoquée en base (effet serveur réel).
      // Le store écrit revokedAt de façon asynchrone (non-blocking) → poll.
      await expect
        .poll(
          async () =>
            (await prisma.userSession.findUnique({ where: { jti: targetJti } }))?.revokedAt ?? null,
          { timeout: 10_000 },
        )
        .not.toBeNull()

      // L'appareil courant reste intact.
      await expect(byButton(page, /Déconnexion|Sign out/)).toBeVisible()
    } finally {
      await prisma.$disconnect()
    }
    await second.close()
  })

  test("journal d'audit réel : connexions réussies et échouées filtrées", async ({ page }) => {
    // Le chargement du journal peut trainer en fin de campagne (évènements accumulés).
    test.setTimeout(240_000)
    await byButton(page, /Déconnexion|Sign out/).click()
    await expect(emailInput(page).first()).toBeVisible({ timeout: 15_000 })

    expect(await attemptLogin(page, owner.email, "MauvaisMot2!passe")).toBe(401)

    await loginLocal(page, owner)

    await page.goto("/audit")
    await expect(page.getByRole("heading", { name: /Journal d'audit/i })).toBeVisible()

    // Filtre « Connexion réussie » → au moins une ligne (Radix Select → combobox).
    // En fin de campagne le chargement du journal traîne (évènements accumulés) :
    // le blob header (combobox) ne se monte qu'une fois la liste arrivée.
    // accname d'un combobox reposant sur la VALEUR sélectionnée (rien au premier
    // affichage), getByRole ne matche pas le placeholder → locator textuel.
    const auditFilter = (value: string) =>
      page.locator("[role=combobox]").filter({ hasText: new RegExp(value) }).first()
    await expect(auditFilter("Toutes les actions")).toBeVisible({ timeout: 180_000 })
    await auditFilter("Toutes les actions").click()
    await page.getByRole("option", { name: "Connexion réussie" }).click()
    await expect(page.getByRole("row").filter({ hasText: "Connexion réussie" }).first()).toBeVisible({
      timeout: 15_000,
    })
    await shot(page, "security-real-audit-reussies")

    // Filtre « Connexion échouée » → la tentative réelle ci-dessus.
    await auditFilter("Connexion réussie").click()
    await page.getByRole("option", { name: "Connexion échouée" }).click()
    await expect(page.getByRole("row").filter({ hasText: "Connexion échouée" }).first()).toBeVisible({
      timeout: 15_000,
    })
  })
})