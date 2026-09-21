/**
 * Anti-replay SAML : enregistre les assertions déjà consommées.
 *
 * Un IdP peut rejouer une SAMLResponse identique (ou une assertion valide
 * copiée). On empreinte la réponse brute (SHA-256) et on refuse toute réponse
 * dont l'empreinte a déjà été validée. TTL = durée de validité max d'une
 * assertion (10 min) — au-delà, l'empreinte est purgée (la réponse serait de
 * toute façon rejetée par NotOnOrAfter).
 *
 * La validation InResponseTo est déléguée à node-saml (cacheProvider) ; ce
 * store complète la protection pour les réponses SANS InResponseTo que
 * certains IdP n'émettent pas.
 *
 * CONTRAINTE DE DÉPLOIEMENT : store process-local (Map mémoire). Voir
 * auth-state.ts — en multi-instance, l'empreinte d'une assertion validée sur A
 * est invisible sur B (rejeu possible). Même exigence : single-instance ou
 * affinité sticky pour le callback SAML.
 */

import { createHash } from "node:crypto"
import { AuthError } from "../providers/types"

const REPLAY_TTL_MS = 10 * 60 * 1000

export class SamlReplayStore {
  private seen = new Map<string, number>()

  /** Marque l'empreinte d'une réponse. Lève si déjà consommée (replay). */
  mark(rawResponse: string): void {
    this.purge()
    const fingerprint = createHash("sha256").update(rawResponse).digest("hex")
    const now = Date.now()
    if (this.seen.has(fingerprint)) {
      throw new AuthError("invalid_credentials", "SAMLResponse déjà consommée (anti-replay)", 400)
    }
    this.seen.set(fingerprint, now + REPLAY_TTL_MS)
  }

  /** Vide le store (tests uniquement). */
  reset(): void {
    this.seen.clear()
  }

  private purge(): void {
    const now = Date.now()
    for (const [key, expiresAt] of this.seen) {
      if (now > expiresAt) this.seen.delete(key)
    }
  }
}

export const samlReplayStore = new SamlReplayStore()