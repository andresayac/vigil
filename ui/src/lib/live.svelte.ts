// Live data shared by the pages: the latest snapshot and process list, plus five minutes of history
// per resource so charts are already filled when the user switches pages. Only real samples are kept
// (no zeros invented before the first one): charts draw what was measured.
import { onLive, setLive } from "./api";
import type { ProcessRow, Snapshot } from "./types";

/** Samples kept per resource: five minutes at one sample per second. */
export const HISTORY = 300;

export const live = $state({
  snapshot: null as Snapshot | null,
  processes: [] as ProcessRow[],
  error: "",
  history: {} as Record<string, number[]>,
});

function push(key: string, value: number): void {
  const current = live.history[key] ?? [];
  const next = current.length >= HISTORY ? current.slice(current.length - HISTORY + 1) : current.slice();
  next.push(Math.max(0, value || 0));
  live.history[key] = next;
}

/** The last `count` samples of a resource (fewer right after the app starts). */
export function series(key: string, count = 60): number[] {
  return (live.history[key] ?? []).slice(-count);
}

let users = 0;
let unlisten: (() => void) | null = null;

/** A page that shows live data calls acquire() when it opens and release() when it closes. */
export async function acquire(): Promise<void> {
  users += 1;
  if (!unlisten) {
    unlisten = await onLive((payload) => {
      live.error = payload.error ?? "";
      if (payload.processes) live.processes = payload.processes;
      const snap = payload.snapshot;
      if (!snap) return;
      live.snapshot = snap;
      push("cpu", snap.cpu);
      const m = snap.memory;
      push("memory", m.total ? (m.used / m.total) * 100 : 0);
      for (const gpu of snap.gpus) {
        push(`gpu:${gpu.luid}`, gpu.utilization);
        push(`vram:${gpu.luid}`, gpu.dedicatedTotal ? (gpu.dedicatedUsed / gpu.dedicatedTotal) * 100 : 0);
      }
      for (const disk of snap.disks) {
        push(`disk:${disk.key}`, disk.active);
        push(`disk:${disk.key}:read`, disk.readBps);
        push(`disk:${disk.key}:write`, disk.writeBps);
      }
      for (const net of snap.nets) {
        push(`net:${net.name}:recv`, net.recvBps);
        push(`net:${net.name}:sent`, net.sentBps);
      }
    });
  }
  if (users === 1) await setLive(true);
}

export async function release(): Promise<void> {
  users = Math.max(0, users - 1);
  if (users === 0) await setLive(false);
}
