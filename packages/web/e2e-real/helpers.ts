/**
 * Helpers partagés des tests E2E « conditions réelles » :
 *  - bootstrap du 1er owner (compte fixe, secret TOTP persisté) ;
 *  - login local complet (mot de passe + challenge TOTP — RFC 6238 calculé) ;
 *  - authenticator WebAuthn virtuel via CDP ;
 *  - accès direct à la base e2e (PrismaClient) pour les fixtures tenant.
 *
 * Le compte owner est FIXE (`owner@e2e.local`) car la base `hullbay_e2e` est
 * reset à chaque run (webServer). Le secret TOTP est écrit dans
 * `.artifacts/owner.json` au bootstrap : `0-bootstrap-real.spec.ts` s'exécute
 * en premier (ordre des fichiers), les autres specs le relisent.
 */

import { expect, type Page } from "@playwright/test"
import { PrismaClient } from "@prisma/client"
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"

export const OWNER = {
  email: "owner@e2e.local",
  password: "Sup3rSecret!e2e",
}

export type Owner = { email: string; password: string; secret: string }

const ARTIFACTS = path.join(import.meta.dirname, ".artifacts")
const OWNER_FILE = path.join(ARTIFACTS, "owner.json")
const SHOTS_DIR = path.join(ARTIFACTS, "screenshots")

/** Persiste le secret TOTP (corrigé après changement de mot de passe, etc.). */
export function persistOwner(owner: Owner): void {
  fs.mkdirSync(ARTIFACTS, { recursive: true })
  fs.writeFileSync(OWNER_FILE, JSON.stringify(owner))
}

/** Purge le secret owner persisté (contexte de run) — bootstrap obligatoire à chaque campagne. */
export function resetOwnerArtifacts(): void {
  fs.rmSync(OWNER_FILE, { force: true })
}

/** Ligne de la liste « Comptes » (UsersPage) : ListRow est un <div>, pas un <li>. */
export const userRow = (page: Page, email: string) =>
  page.getByText(email, { exact: true }).locator("..").locator("..").locator("..").locator("..")

/**
 * GET /api/auth/me en conditions réelles : le fetch brut ne porte PAS
 * l'Authorization (c'est le client API de la SPA qui l'injecte) → on monte
 * l'en-tête depuis le token posé en localStorage (TOKEN_KEY « hullbay_token »).
 */
export async function apiMe(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(async () => {
    const token = window.localStorage.getItem("hullbay_token")
    const res = await fetch("/api/auth/me", {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    return res.json() as Record<string, unknown>
  })
}

/** Capture d'une étape clé du test réel → e2e-real/.artifacts/screenshots/. */
export async function shot(page: Page, label: string): Promise<void> {
  fs.mkdirSync(SHOTS_DIR, { recursive: true })
  await page.screenshot({
    path: path.join(SHOTS_DIR, `${label}.png`),
    fullPage: true,
  })
}

// ── TOTP (RFC 6238, SHA-1, 6 chiffres, pas 30 s) ──────────────────────────
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

export function totp(secret: string): string {
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

// ── Sélecteurs en français (locale par défaut de l'app) ───────────────────
export const byButton = (page: Page, re: RegExp | string) => page.getByRole("button", { name: re })
export const emailInput = (page: Page) => page.locator('input[type="email"]')
export const passwordInput = (page: Page) => page.locator('input[type="password"]')
export const logoutButton = (page: Page) => byButton(page, /Déconnexion|Sign out|Log ?out/)
export const loginButton = (page: Page) => byButton(page, /^Se connecter$|^Sign in$/)

// ── Authenticator WebAuthn virtuel (CDP) ──────────────────────────────────
export async function addVirtualAuthenticator(page: Page) {
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

// ── Base e2e (fixtures tenant) ────────────────────────────────────────────
function loadEnvFile(file: string): Record<string, string> {
  const out: Record<string, string> = {}
  if (!fs.existsSync(file)) return out
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const match = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*)\s*$/)
    if (!match) continue
    out[match[1]] = match[2].trim().replace(/^["']|["']$/g, "")
  }
  return out
}

export function e2eDatabaseUrl(): string {
  const rootEnv = loadEnvFile(path.resolve(import.meta.dirname, "../../.env"))
  const apiEnv = loadEnvFile(path.resolve(import.meta.dirname, "../../api/.env"))
  const pgUser = apiEnv.POSTGRES_USER || rootEnv.POSTGRES_USER || "ops"
  const pgPassword = apiEnv.POSTGRES_PASSWORD || rootEnv.POSTGRES_PASSWORD || ""
  return `postgresql://${pgUser}:${pgPassword}@127.0.0.1:5432/hullbay_e2e`
}

export function e2ePrisma(): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl() } } })
}

/** Rattache l'owner courant à un tenant supplémentaire (fixture du TenantSwitcher). */
export async function grantTenantToOwner(
  tenantId: string,
  role: "owner" | "operator" | "viewer" = "viewer",
): Promise<void> {
  const prisma = e2ePrisma()
  try {
    const account = await prisma.user.findUnique({ where: { email: OWNER.email } })
    if (!account) throw new Error("owner introuvable en base (0-bootstrap absent ?)")
    await prisma.membership.upsert({
      where: { userId_tenantId: { userId: account.id, tenantId } },
      create: { userId: account.id, tenantId, role },
      update: {},
    })
  } finally {
    await prisma.$disconnect()
  }
}

// ── Bootstrap du 1er owner (secret TOTP persisté) ─────────────────────────
export async function bootstrapOwner(page: Page): Promise<Owner> {
  await page.goto("/")
  await expect(
    byButton(page, /Créer le compte administrateur|Create administrator account/),
  ).toBeVisible({ timeout: 30_000 })

  await emailInput(page).fill(OWNER.email)
  const pwds = passwordInput(page)
  await pwds.nth(0).fill(OWNER.password)
  await pwds.nth(1).fill(OWNER.password)
  await byButton(page, /Créer le compte administrateur|Create administrator account/).click()

  // Enrôlement TOTP forcé.
  await expect(page).toHaveURL(/\/activate-mfa/, { timeout: 20_000 })
  const secretEl = page.locator("div.break-all").first()
  await expect
    .poll(async () => (await secretEl.textContent())?.trim() ?? "")
    .toMatch(/^[A-Z2-7]{16,}$/)
  const secret = (await secretEl.textContent())!.trim()

  await page.getByPlaceholder("123456").fill(totp(secret))
  await byButton(page, /Confirmer l'activation|Confirm setup/).click()
  await expect(logoutButton(page)).toBeVisible({ timeout: 20_000 })
  await expect(page).toHaveURL(/\/$/)

  const owner: Owner = { ...OWNER, secret }
  fs.mkdirSync(ARTIFACTS, { recursive: true })
  persistOwner(owner)
  return owner
}

/** Lit le secret TOTP : bootstrap s'il manque (premier run), sinon fichier. */
export async function getOwner(page: Page): Promise<Owner> {
  if (fs.existsSync(OWNER_FILE)) {
    return JSON.parse(fs.readFileSync(OWNER_FILE, "utf8")) as Owner
  }
  return bootstrapOwner(page)
}

// ── Login local complet (mot de passe + TOTP) ─────────────────────────────
export async function loginLocal(page: Page, owner: Owner): Promise<void> {
  await page.goto("/")
  await expect(emailInput(page).first()).toBeVisible({ timeout: 15_000 })
  await emailInput(page).fill(owner.email)
  await passwordInput(page).fill(owner.password)
  await loginButton(page).click()

  await expect(page.getByPlaceholder("123456")).toBeVisible({ timeout: 15_000 })
  await page.getByPlaceholder("123456").fill(totp(owner.secret))
  await byButton(page, /Valider|Confirm|Submit|Valider/).click()

  await expect(logoutButton(page)).toBeVisible({ timeout: 20_000 })
  await expect(page).toHaveURL(/\/$/)
}

export async function logout(page: Page): Promise<void> {
  await logoutButton(page).click()
  await expect(emailInput(page).first()).toBeVisible({ timeout: 15_000 })
}

/** Standalone : owner authentifié + secret (bootstrap si nécessaire). */
export async function ensureOwner(page: Page, opts: { logout?: boolean } = {}): Promise<Owner> {
  const owner = await getOwner(page)
  if ((await logoutButton(page).count()) === 0) {
    await loginLocal(page, owner)
  } else if (opts.logout) {
    await logout(page)
  }
  return owner
}