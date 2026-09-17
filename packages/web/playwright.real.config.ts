import { defineConfig, devices } from "@playwright/test"
import fs from "node:fs"
import path from "node:path"

/**
 * Playwright « condition réelle » : pas de stub d'API, pas de mock WebAuthn.
 *
 * Démarre un stack isolé et jetable :
 *   - API reelle sur :4100 branchée sur la base `hullbay_e2e` (NODE_ENV=development) ;
 *   - Vite (config `vite.real.config.ts`) sur :5274 proxifiant vers :4100.
 * Le navigateur est un Chromium réel, headed, piloté avec un authenticator
 * WebAuthn virtuel (CDP) — cérémonie réelle, aucune clé physique requise.
 *
 * La base `hullbay_e2e` doit exister et être migrée :
 *   DATABASE_URL=...hullbay_e2e npx prisma migrate deploy   (dans packages/api)
 */

const WEB_DIR = import.meta.dirname
const API_DIR = path.resolve(import.meta.dirname, "../api")
const ROOT_DIR = path.resolve(import.meta.dirname, "../..")

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

const fileEnv = { ...loadEnvFile(path.join(ROOT_DIR, ".env")), ...loadEnvFile(path.join(API_DIR, ".env")) }

const pgUser = fileEnv.POSTGRES_USER || "ops"
const pgPassword = fileEnv.POSTGRES_PASSWORD || ""
const pgDb = "hullbay_e2e"
const databaseUrl = `postgresql://${pgUser}:${pgPassword}@127.0.0.1:5432/${pgDb}`

export default defineConfig({
  testDir: "./e2e-real",
  outputDir: "./e2e-real/.artifacts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://localhost:5274",
    headless: false,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: [
    {
      command: "npx prisma migrate reset --force --skip-seed && npx tsx src/server.ts",
      cwd: API_DIR,
      url: "http://127.0.0.1:4100/api/auth/needs-bootstrap",
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        NODE_ENV: "development",
        API_HOST: "127.0.0.1",
        API_PORT: "4100",
        DATABASE_URL: databaseUrl,
        REDIS_URL: fileEnv.REDIS_URL || "redis://127.0.0.1:6379",
        JWT_SECRET: fileEnv.JWT_SECRET || "e2e-real-jwt-secret-not-for-production",
        MFA_ENCRYPTION_KEY: fileEnv.MFA_ENCRYPTION_KEY || "e2e-real-mfa-key-not-for-production",
        WEB_ORIGIN: "http://localhost:5274",
        PUBLIC_URL: "http://localhost:5274",
      },
    },
    {
      command: "npx vite --config vite.real.config.ts",
      cwd: WEB_DIR,
      url: "http://127.0.0.1:5274",
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
})
