// Task Manager's grouping of the process list.
//
// Apps: programs that own a visible window on the desktop, one entry per executable, together with the
//   processes they started (a terminal inside an editor belongs to the editor). Explorer is a boundary:
//   everything started from the Start menu descends from it, so its children are never pulled into it.
// Background processes / Windows processes: the rest, split by where the file lives (the Windows folder,
//   or no file at all, as for System and Registry). A process and the processes it started from the same
//   file form one entry ("Steam Client WebHelper (4)").
import type { ProcessRow } from "./types";

export type Section = "apps" | "background" | "windows";
export const SECTIONS: Section[] = ["apps", "background", "windows"];

export interface Entry {
  /** Selection key: "pid:created" for a single process, "g:pid:created" (its main process) for a group. */
  key: string;
  section: Section;
  label: string;
  /** The process actions apply to; for a group, the root of its main process tree. */
  main: ProcessRow;
  members: ProcessRow[];
  /** Executable whose icon stands for the entry. */
  icon: string;
}

/** What the selection in the process table stands for. */
export interface Picked {
  row: ProcessRow;
  label: string;
  /** Processes in the selected entry: more than one for a group. */
  count: number;
}

export const processKey = (r: ProcessRow): string => `${r.pid}:${r.createdMs}`;
export const displayName = (r: ProcessRow): string => r.description || r.name.replace(/\.exe$/i, "");

const WINDOWS_DIR = /^[a-z]:\\windows\\/i;
const SHELL = /^[a-z]:\\windows\\explorer\.exe$/i;

export function groupProcesses(rows: ProcessRow[]): { entries: Entry[]; byKey: Map<string, Entry>; of: Map<string, Entry> } {
  const byPid = new Map(rows.map((r) => [r.pid, r]));
  // A parent must have started before its child; otherwise the PID was reused.
  const parentOf = (r: ProcessRow): ProcessRow | undefined => {
    const p = byPid.get(r.ppid);
    return p && p.pid !== r.pid && p.createdMs <= r.createdMs ? p : undefined;
  };
  const exeOf = (r: ProcessRow) => r.exe.toLowerCase();
  const appExes = new Set(rows.filter((r) => r.window && r.exe).map(exeOf));

  const groups = new Map<string, ProcessRow[]>();
  for (const r of rows) {
    const exe = exeOf(r);
    let id = exe && appExes.has(exe) ? `app:${exe}` : "";
    for (let p = parentOf(r), depth = 0; !id && p && depth < 8 && !SHELL.test(p.exe); p = parentOf(p), depth++) {
      if (appExes.has(exeOf(p))) id = `app:${exeOf(p)}`;
    }
    if (!id) {
      let root = r;
      for (let p = parentOf(r), depth = 0; exe && p && depth < 64 && exeOf(p) === exe; p = parentOf(p), depth++) root = p;
      id = `run:${processKey(root)}`;
    }
    const list = groups.get(id);
    if (list) list.push(r);
    else groups.set(id, [r]);
  }

  const entries: Entry[] = [];
  for (const [id, members] of groups) {
    const inGroup = new Set(members);
    const roots = members.filter((m) => {
      const parent = parentOf(m);
      return !parent || !inGroup.has(parent);
    });
    const app = id.startsWith("app:");
    const owner = app ? members.find((m) => m.window) : undefined;
    const candidates = app ? roots.filter((m) => exeOf(m) === id.slice(4)) : roots;
    const main = (candidates.length ? candidates : roots.length ? roots : members)
      .reduce((a, b) => (b.window && !a.window) || (b.window === a.window && b.createdMs < a.createdMs) ? b : a);
    const section: Section = app ? "apps" : !main.exe || WINDOWS_DIR.test(main.exe) ? "windows" : "background";
    entries.push({
      key: members.length > 1 ? `g:${processKey(main)}` : processKey(main),
      section,
      label: displayName(owner ?? main),
      main,
      members,
      icon: (owner ?? main).exe,
    });
  }
  const byKey = new Map(entries.map((e) => [e.key, e]));
  const of = new Map(entries.flatMap((e) => e.members.map((m) => [processKey(m), e] as const)));
  return { entries, byKey, of };
}
