// What changed since the previous scan (stored by the scan in `analysis.changes`).
import type { Analysis, ScanChanges } from "./types";

/** The comparison with the previous scan, or null for a first scan. Missing lists read as empty. */
export function changesOf(analysis: Analysis | null | undefined): ScanChanges | null {
  const c = analysis?.changes as Partial<ScanChanges> | undefined;
  if (!c || typeof c !== "object") return null;
  return {
    previous: { started: String(c.previous?.started ?? ""), path: String(c.previous?.path ?? "") },
    new: Array.isArray(c.new) ? c.new : [],
    gone: Array.isArray(c.gone) ? c.gone : [],
    changed: Array.isArray(c.changed) ? c.changed.map((x) => ({ id: String(x.id), what: Array.isArray(x.what) ? x.what : [] })) : [],
    posture: Array.isArray(c.posture) ? c.posture : [],
  };
}

/** How one finding differs from the previous scan; null when it is unchanged or there is no previous scan. */
export function sinceLast(changes: ScanChanges | null, id: string): { isNew: boolean; what: string[] } | null {
  if (!changes) return null;
  if (changes.new.includes(id)) return { isNew: true, what: [] };
  const entry = changes.changed.find((c) => c.id === id);
  return entry ? { isNew: false, what: entry.what } : null;
}
