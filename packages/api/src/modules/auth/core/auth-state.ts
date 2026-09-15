/**
 * Auth State Stores (nonce / state / PKCE) — stubs Phase 2.
 * Utilisés en Phase 3 (OIDC/OAuth2) et Phase 4 (SAML RelayState).
 * En Phase 2 seule la logique locale fonctionne, ces stores restent inutilisés.
 */

export class AuthStateStore<T = unknown> {
  private store = new Map<string, { value: T; expiresAt: number }>()

  /** Génère une clé aléatoire, stocke la valeur avec TTL, retourne la clé. */
  put(value: T, ttlMs: number): string {
    const key = crypto.randomUUID()
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs })
    if (this.store.size % 64 === 0) this.purge()
    return key
  }

  /** Consomme la valeur une seule fois (suppression atomique). Retourne undefined si absent/expiré. */
  consume(key: string): T | undefined {
    const entry = this.store.get(key)
    if (!entry) return undefined
    this.store.delete(key)
    if (Date.now() > entry.expiresAt) return undefined
    return entry.value
  }

  /** Purge les entrées expirées (appel périodique optionnel). */
  purge(): number {
    const now = Date.now()
    let removed = 0
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key)
        removed++
      }
    }
    return removed
  }
}

export const nonceStore = new AuthStateStore<string>()
export const stateStore = new AuthStateStore<{ redirectUri: string }>()
export const pkceStore = new AuthStateStore<{ codeVerifier: string; redirectUri: string }>()

// ── Stores SSO (Phase 3) : state/pkce avec TTL 10 min, consommation unique ──
export interface OidcStateRecord {
  providerId: string
  redirectUri: string
  codeVerifier: string
  nonce: string
}

export interface Oauth2StateRecord {
  providerId: string
  redirectUri: string
}

export const oidcStateStore = new AuthStateStore<OidcStateRecord>()
export const oauth2StateStore = new AuthStateStore<Oauth2StateRecord>()
