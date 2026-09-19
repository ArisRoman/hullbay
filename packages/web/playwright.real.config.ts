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

// Fixtures E2E réelles : tenants + policy rate-limit rapide (3 échecs / 4 s),
// injectées APRÈS `prisma migrate reset` et AVANT le boot de l'API (l'API
// charge la policy de la DB au démarrage — cf. security-policy.service.ts).
const SEED_SQL = path.join(WEB_DIR, "e2e-real/fixtures/seed.sql")

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
      // Génère le cert du fake LDAP AVANT le boot (NODE_EXTRA_CA_CERTS est lu au
      // démarrage du process) puis reset/seed/boot. L'API ldapts fait TOUJOURS
      // du TLS (options tlsOptions → ldaps), on ne la relie donc qu'en ldaps.
      command: `mkdir -p /tmp/hullbay-e2e-ldap && { [ -s /tmp/hullbay-e2e-ldap/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/hullbay-e2e-ldap/key.pem -out /tmp/hullbay-e2e-ldap/cert.pem -days 1 -subj "/CN=hullbay-e2e" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null; } && npx prisma migrate reset --force --skip-seed && npx prisma db execute --url "${databaseUrl}" --file "${SEED_SQL}" && npx tsx src/server.ts`,
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
        NODE_EXTRA_CA_CERTS: "/tmp/hullbay-e2e-ldap/cert.pem",
      },
    },
    {
      command: "npx vite --config vite.real.config.ts",
      cwd: WEB_DIR,
      url: "http://127.0.0.1:5274",
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: "npx tsx e2e-real/fakes/fake-oidc.ts",
      cwd: WEB_DIR,
      url: "http://127.0.0.1:5280/health",
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "npx tsx e2e-real/fakes/fake-ldap.ts",
      cwd: WEB_DIR,
      url: "http://127.0.0.1:1289/health",
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
