import type { Readable } from "node:stream"

/**
 * Contrat de stockage du Backup Engine.
 *
 * Le cœur du moteur ne connaît que cette interface : Rclone est une
 * implémentation parmi d'autres (un backend local suffit à le prouver).
 * Les divergences entre backends (rename atomique, checksum natif) sont
 * exposées explicitement par `capabilities()` — jamais supposées.
 */

/**
 * Erreur d'un backend de stockage, porteuse d'un code métier stable
 * (`checksum_mismatch`, `commit_failed`, `destination_unreachable`, …).
 * Le Backup Engine s'appuie sur `code`, jamais sur le message brut.
 */
export class StorageProviderError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message)
    this.name = "StorageProviderError"
  }
}

export interface StorageCapabilities {
  read: boolean
  write: boolean
  delete: boolean
  move: boolean
  checksum: boolean
  atomicCommit: boolean
  serverSideEncryption: boolean
}

export interface ObjectStat {
  key: string
  size: number
  modifiedAt?: string
}

export interface PutOptions {
  /** Taille connue à l'avance (permet aux backends de streamer sans buffer). */
  size?: number
  contentType?: string
}

export interface PutResult {
  key: string
  size: number
  checksum?: string
}

export type HashAlgorithm = "sha256"

export interface StorageProvider {
  readonly id: string
  capabilities(): StorageCapabilities
  put(key: string, data: Readable | Buffer, opts?: PutOptions): Promise<PutResult>
  get(key: string): Promise<Readable>
  stat(key: string): Promise<ObjectStat | null>
  list(prefix: string): Promise<ObjectStat[]>
  delete(key: string): Promise<void>
  /** `false` = non supporté par le backend (l'appelant dégrade en copy+verify+delete). */
  move(from: string, to: string): Promise<boolean>
  hash(key: string, algorithm?: HashAlgorithm): Promise<string | null>
  /**
   * Promotion d'un payload de staging vers sa clé finale, avec vérification
   * distante du checksum avant promotion (un payload corrompu n'est jamais
   * promu). Le mécanisme — `atomic-rename` (moveto) ou `copy-verify-delete`
   * (fallback si le backend n'expose pas de rename) — est choisi par
   * l'implémentation selon SES capacités ; la valeur renvoyée est le mode
   * RÉELLEMENT exécuté et doit être consignée telle quelle dans le manifest
   * (`commit.mode`). Le Backup Engine ne suppose jamais le mode : il l'interroge.
   */
  commitPayload(
    stagingKey: string,
    finalKey: string,
    expectedChecksum: string,
  ): Promise<"atomic-rename" | "copy-verify-delete">
}

/**
 * Contrat minimal pour la sortie de staging du producteur.
 *
 * Le producteur (extraction) doit envoyer son flux vers un objet de staging.
 * Pour que le Backup Engine ne connaisse pas rclone, c'est l'adapter de stockage
 * qui fournit la commande d'upload ; le runner se contente de composer
 * `extraction | <commande fournie>`. Rclone reste donc confiné à l'adapter.
 */
export interface StagingSink {
  /** Commande shell qui uploade stdin vers `key` (credentials via secret). */
  stagingUploadScript(key: string): string
  /** Remote-string (credentials incluses) à monter en secret pour le task. */
  remoteString(): string
  /** Secret de transport additionnel (clé SFTP / JSON GCS), s'il en faut un. */
  transportSecret(): { material: string; target: string } | null
}

/** Capacités minimales d'un backend en lecture seule (jamais utilisé tel quel). */
export const READ_ONLY_CAPABILITIES: StorageCapabilities = {
  read: true,
  write: false,
  delete: false,
  move: false,
  checksum: false,
  atomicCommit: false,
  serverSideEncryption: false,
}
