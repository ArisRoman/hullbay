import { test, expect } from "@playwright/test"
import { byButton, ensureOwner, shot } from "./helpers"

/**
 * Smoke des clusters EN CONDITIONS RÉELLES : le navigateur owner ouvre la page
 * Clusters branchée sur le socket Docker VRAI (/var/run/docker.sock, swarm
 * actif). Aucune assertion sur la topologie (environnement) : on vérifie que
 * la page charge et rend l'état réel (liste vide si aucun cluster « Default »
 * n'a été créé par l'API, sinon la liste).
 */

test.describe.serial("clusters — smoke réel", () => {
  test("page Clusters charge avec le swarm réel, aucun crash", async ({ page }) => {
    await ensureOwner(page)

    await page.goto("/clusters")
    await expect(page.getByRole("heading", { name: "Clusters" })).toBeVisible({
      timeout: 20_000,
    })

    // Pas d'erreur réseau : la requête clusters est servie par l'API réelle.
    const errors: string[] = []
    page.on("console", (msg) => msg.type() === "error" && errors.push(msg.text()))
    await page.waitForTimeout(500)

    // L'état est rendu (liste ou vide) — pas de crash de route.
    const body = await page.locator("main").innerText()
    expect(body).toContain("Clusters")
    await shot(page, "clusters-real-page")

    expect(errors.filter((e) => !e.includes("favicon"))).toEqual([])
  })

  test("l'architecture est explorable via la nav (lien Clusters réel)", async ({ page }) => {
    await ensureOwner(page)
    await page.getByRole("link", { name: "Clusters" }).click()
    await expect(page).toHaveURL(/\/clusters/)
    await expect(page.getByRole("heading", { name: "Clusters" })).toBeVisible()
  })
})