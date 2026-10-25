import type { Readable } from "node:stream"

/**
 * Contrat de stockage du Backup Engine.
 *
 * Le cœur du moteur ne connaît que cette interface : Rclone est une
 * implémentation parmi d'autres (un backend local suffit à le prouver).
 * Les divergences entre backends (rename atomique, checksum natif) sont
 * exposées explicitement par `capabilities()` — jamais supposées.
 */

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
