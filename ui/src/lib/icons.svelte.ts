// Program icons for the process list. Each executable is read once (the backend caches it too) and only
// when a row that shows it is on screen; requests are batched so a scroll asks once, not per row.
import { processIcons } from "./api";

const icons = $state<Record<string, string>>({});
const asked = new Set<string>();
let queue: string[] = [];
let timer: ReturnType<typeof setTimeout> | null = null;

async function flush(): Promise<void> {
  timer = null;
  const batch = queue.splice(0, 256);
  if (queue.length) timer = setTimeout(() => void flush(), 0);
  let found: Record<string, string> = {};
  try {
    found = await processIcons(batch);
  } catch {
    // No icon is not an error: the row shows the generic one.
  }
  for (const path of batch) icons[path.toLowerCase()] = found[path] ?? "";
}

/** The icon of an executable as a data URL; "" while it is being read and when the file has none. */
export function iconOf(path: string): string {
  if (!path) return "";
  const key = path.toLowerCase();
  const known = icons[key];
  if (known !== undefined) return known;
  if (!asked.has(key)) {
    asked.add(key);
    queue.push(path);
    timer ??= setTimeout(() => void flush(), 30);
  }
  return "";
}
