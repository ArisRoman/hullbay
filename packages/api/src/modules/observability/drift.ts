/**
 * Suivi du drift en mémoire vive (par projet, SCOPÉ PAR TENANT), alimenté par
 * le job de détection périodique (jobs/reconcile-drift.ts). Volontairement séparé
 * d'ObservabilityService (qui lui est désormais lié à un cluster précis via
 * forCluster()) : le drift est un concept par PROJET, jamais par cluster.
 *
 * La clé de stockage inclut le tenantId — un tenant ne voit JAMAIS le
 * drift d'un autre tenant, même si un event d'un autre process transite par Redis.
 */

type DriftRecord = { projectId: string; count: number; actions: string[]; at: number };

/** Clé = `${tenantId}:${projectId}` — isolation tenant stricte même sur clé. */
function key(tenantId: string, projectId: string): string {
  return `${tenantId}:${projectId}`;
}

const driftByProject = new Map<string, DriftRecord>();

export const driftTracker = {
  record(tenantId: string, projectId: string, count: number, actions: string[]): void {
    const k = key(tenantId, projectId);
    if (count <= 0) driftByProject.delete(k);
    else driftByProject.set(k, { projectId, count, actions, at: Date.now() });
  },

  clear(tenantId: string, projectId: string): void {
    driftByProject.delete(key(tenantId, projectId));
  },

  /** Snapshot des seuls projects du tenant demandé. */
  snapshot(tenantId: string): DriftRecord[] {
    const prefix = `${tenantId}:`;
    return Array.from(driftByProject.entries())
      .filter(([k]) => k.startsWith(prefix))
      .map(([, v]) => v);
  },
};