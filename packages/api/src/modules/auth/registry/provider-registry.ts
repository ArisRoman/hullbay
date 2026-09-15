/**
 * Provider Registry : registre central des providers configurés.
 * Initialise au démarrage à partir des seeds (seeds.ts) — CRUD effectif Phase 5A.
 * Phase 2 : seuls les providers activés sont enregistrés (local = activé).
 */

import { createProvider } from "../providers/protocol-adapter"
import type { AuthProviderContract } from "../providers/types"
import { PROVIDER_SEEDS } from "./seeds"

export class ProviderRegistry {
  private providers = new Map<string, AuthProviderContract>()

  /** Enregistre un provider (écrase si même id). */
  register(provider: AuthProviderContract): void {
    this.providers.set(provider.id, provider)
  }

  /** Enregistre les presets activés depuis les seeds. */
  registerSeeds(): void {
    for (const seed of PROVIDER_SEEDS) {
      if (seed.enabled) {
        this.register(createProvider(seed.kind, seed.id))
      }
    }
  }

  /** Récupère un provider par id. Renvoie undefined si absent. */
  get(id: string): AuthProviderContract | undefined {
    return this.providers.get(id)
  }

  /** Récupère un provider par id, lève si absent. */
  require(id: string): AuthProviderContract {
    const p = this.providers.get(id)
    if (!p) throw new Error(`provider ${id} introuvable ou désactivé`)
    return p
  }

  /** Liste tous les providers enregistrés. */
  list(): AuthProviderContract[] {
    return [...this.providers.values()]
  }

  /** Supprime tous les providers (utile pour les tests). */
  clear(): void {
    this.providers.clear()
  }
}

export const providerRegistry = new ProviderRegistry()

// Initialisation au chargement du module — seuls les providers activés sont
// enregistrés (Phase 2 : local uniquement).
providerRegistry.registerSeeds()
