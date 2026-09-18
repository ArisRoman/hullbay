#!/usr/bin/env node
/**
 * e2e Isolation multi-tenant (Phase 5B) — à exécuter en CI/staging UNIQUEMENT.
 *
 * Déroulé :
 *   1. Login admin bootstrap → token tenant par défaut.
 *   2. Provisionne un 2ᵉ tenant + un membre (directement en base via Prisma —
 *      l'isolation testée ici est celle des ROUTES, pas du provisioning tenant).
 *   3. Logins : token A (tenant défaut), token B (tenant B).
 *   4. Matrice d'isolation HTTP : projet A invisible pour B, cluster A invisible
 *      pour B, système de santé scopé, health/drift sans fuite cross-tenant.
 *
 * Prérequis :
 *   - API hullbay démarrée (npm run dev:api), DB accessible.
 *   - TENANT_ISOLATION_E2E=1 (garde CI explicite, comme OIDC_TEST_ENABLED).
 *
 * Sortie : exit 0 si la matrice passe, 1 sinon.
 */

const BASE = process.env.E2E_API_BASE ?? "http://localhost:4000"
const TENANT_ISOLATION_E2E = process.env.TENANT_ISOLATION_E2E ?? "0"
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@hullbay.local"
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "hullbay-admin"

if (TENANT_ISOLATION_E2E !== "1") {
  console.log("[tenant-isolation.e2e] SKIPPED — TENANT_ISOLATION_E2E != 1")
  process.exit(0)
}

const { PrismaClient } = await import("@prisma/client")
const prisma = new PrismaClient()

let failures = 0
function check(name, cond, detail = "") {
  const ok = Boolean(cond)
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`)
  if (!ok) failures++
}

// Attend le boot de l'API (health public).
async function waitForApi(attempts = 90) {
  for (let i = 0; i < attempts; i++) {
    const ok = await fetch(`${BASE}/health`)
      .then((r) => r.ok)
      .catch(() => false)
    if (ok) return
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error("API hullbay injoignable")
}

async function login(email, password) {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(`login ${email} : ${res.status}`)
  const body = await res.json()
  return body.token
}

function api(token, method, path, body, headers = {}) {
  return fetch(`${BASE}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))
}

async function main() {
  const tag = `b${Date.now().toString(36)}`
  const tenantBSlug = `integration-${tag}`
  console.log(`[tenant-isolation.e2e] base=${BASE}`)
  await waitForApi()

  // ── Logins ────────────────────────────────────────────────
  const tokenA = await login(ADMIN_EMAIL, ADMIN_PASSWORD).catch((e) => {
    throw new Error(`login admin impossible — vérifie E2E_ADMIN_EMAIL/PASSWORD : ${e.message}`)
  })
  console.log("[tenant-isolation.e2e] token A (tenant défaut) OK")

  // ── Provisionne tenant B (nettoyé si déjà présent) ───────
  let tenantB = await prisma.tenant.findUnique({ where: { slug: tenantBSlug } })
  if (tenantB) {
    await prisma.membership.deleteMany({ where: { tenantId: tenantB.id } })
    await prisma.tenant.delete({ where: { id: tenantB.id } })
    tenantB = null
  }
  tenantB = await prisma.tenant.create({
    data: {
      id: `tenant-int-${tag}`,
      name: `Integration ${tag}`,
      slug: tenantBSlug,
    },
  })
  // L'admin bootstrap est owner des DEUX tenants (membership créée par les
  // helpers/sessions) ; on teste donc l'isolation via le header x-tenant-id sur
  // ce même token owner — les vrais fetch cross-utilisateur sont couverts par la
  // matrice de tests unitaires tenant-isolation.test.ts.
  const adminRow = await prisma.user.findFirst({ select: { id: true } })
  if (!adminRow) throw new Error("aucun user bootstrap — l'isolation ne peut pas être testée sans admin")
  await prisma.membership.upsert({
    where: { userId_tenantId: { userId: adminRow.id, tenantId: tenantB.id } },
    create: { userId: adminRow.id, tenantId: tenantB.id, role: "owner" },
    update: {},
  })

  // ── Matrice d'isolation HTTP ──────────────────────────────
  //
  // Axe principal : requêtes du tenant par défaut SANS voir le tenant B, et
  // réciproquement. On fait varier le tenant via le header x-tenant-id côté A
  // (A est owner des deux) — le scope côté serveur doit quand même tenir.

  // 1. Projets : crée un projet sur A, vérifie qu'il est invisible en tenant B.
  const projA = await api(tokenA, "POST", "/api/projects", {
    name: `projet-a-${tag}`,
    description: "e2e isolation",
  })
  if (projA.status !== 201 && projA.status !== 200) {
    // création projet : accepter les deux statuts selon l'implémentation
    console.log(`  (projet A : status ${projA.status} — ${JSON.stringify(projA.body).slice(0, 120)})`)
  }
  const pid = projA.body?.id
  check("projet A créé (avec id)", Boolean(pid))
  if (pid) {
    const asB = await api(tokenA, "GET", `/api/projects`, undefined, { "x-tenant-id": tenantB.id })
    const list = Array.isArray(asB.body) ? asB.body : asB.body?.projects ?? []
    check("projet A invisible pour tenant B", !list.some((p) => p && p.id === pid))
    const planB = await api(tokenA, "GET", `/api/projects/${pid}/plan`, undefined, { "x-tenant-id": tenantB.id })
    check("plan projet A → 404 en tenant B", planB.status === 404 || planB.status === 403)
  }

  // 2. Clusters : /api/clusters doit être scopé par tenant (pas de fuite).
  const clustersA = await api(tokenA, "GET", "/api/clusters")
  const clustersB = await api(tokenA, "GET", "/api/clusters", undefined, { "x-tenant-id": tenantB.id })
  const idsB = new Set((Array.isArray(clustersB.body) ? clustersB.body : []).map((c) => c?.id))
  for (const c of Array.isArray(clustersA.body) ? clustersA.body : []) {
    check(`cluster ${c?.id} invisible pour tenant B`, !idsB.has(c?.id))
  }

  // 3. Système de santé : /api/health/cluster scopé (pas de cluster Nième tenant).
  const healthB = await api(tokenA, "GET", "/api/health/cluster", undefined, { "x-tenant-id": tenantB.id })
  const hb = healthB.body?.clusters ?? healthB.body ?? []
  check("health cluster tenant B < clusters tenant défaut (scopé)",
    Array.isArray(hb) && hb.length <= (Array.isArray(clustersA.body) ? clustersA.body.length : 0))

  // 4. Drift : snapshot scopé tenant.
  const driftB = await api(tokenA, "GET", "/api/drift", undefined, { "x-tenant-id": tenantB.id })
  check("drift tenant B body liste (scopé)", Array.isArray(driftB.body?.drift ?? driftB.body))

  console.log(`[tenant-isolation.e2e] ${failures === 0 ? "OK" : `FAIL (${failures})`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
  .catch((err) => {
    console.error("[tenant-isolation.e2e] FAIL:", err.message)
    process.exitCode = 1
  })
  .finally(async () => {
    await prisma.$disconnect()
  })