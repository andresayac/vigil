// The background watch as the pages see it: one status shared by the sidebar, Overview, the Alerts page
// and Settings, kept current by the "watch" events Rust sends after every check.
import * as api from "./api";
import { locale, t, type Key } from "./i18n/index.svelte";
import type { AlertKind, WatchAlert, WatchStatus } from "./types";

export const watch = $state<{ status: WatchStatus | null }>({ status: null });

export async function refreshWatch(): Promise<void> {
  try {
    watch.status = await api.watchStatus();
  } catch {
    // Keep the last status: the watch is a convenience, never a reason for an error on screen.
  }
}

/** Loads the status and follows its changes; returns the function that stops following. */
export async function followWatch(): Promise<() => void> {
  await refreshWatch();
  return api.onWatch((status) => (watch.status = status));
}

export function setStatus(status: WatchStatus): void {
  watch.status = status;
}

export const KIND_LABEL: Record<AlertKind, Key> = {
  startup: "watch.kind.startup",
  service: "watch.kind.service",
  task: "watch.kind.task",
  security: "watch.kind.security",
  port: "watch.kind.port",
  hook: "watch.kind.hook",
  driver: "watch.kind.driver",
  hosts: "watch.kind.hosts",
  event: "watch.kind.event",
  watch: "watch.kind.watch",
};

/** Pages an alert can open, with the name of the link. */
export const TARGET_LABEL: Record<string, Key> = {
  startup: "page.startup",
  services: "page.services",
  tasks: "page.tasks",
  network: "page.network",
  protection: "page.protection",
  posture: "page.posture",
  firewall: "page.firewall",
  accounts: "page.accounts",
};

/** The glyph and state colour of a severity (info is plain ink). */
export function severityLook(alert: WatchAlert): { icon: string; tone: "" | "warn" | "bad" } {
  if (alert.severity === "critical") return { icon: "", tone: "bad" };
  if (alert.severity === "warning") return { icon: "", tone: "warn" };
  return { icon: "", tone: "" };
}

const relative = new Map<string, Intl.RelativeTimeFormat>();
/** "2 min ago", "hace 3 h", "yesterday". */
export function since(ms: number | null): string {
  if (!ms) return "";
  const tag = locale();
  let format = relative.get(tag);
  if (!format) {
    format = new Intl.RelativeTimeFormat(tag, { numeric: "auto", style: "short" });
    relative.set(tag, format);
  }
  const seconds = Math.max(0, (Date.now() - ms) / 1000);
  if (seconds < 45) return t("watch.justNow");
  if (seconds < 3600) return format.format(-Math.round(seconds / 60), "minute");
  if (seconds < 86_400) return format.format(-Math.round(seconds / 3600), "hour");
  return format.format(-Math.round(seconds / 86_400), "day");
}

/** A moment as a short local time, with the date when it is not today. */
export function clock(ms: number): string {
  const date = new Date(ms);
  const today = new Date().toDateString() === date.toDateString();
  return new Intl.DateTimeFormat(locale(), today ? { timeStyle: "short" } : { dateStyle: "medium", timeStyle: "short" }).format(date);
}

/** The one-line state of the watch (sidebar, Overview, Alerts page). */
export function stateLine(status: WatchStatus | null): string {
  if (!status) return "";
  if (!status.owner) return t("watch.otherWindow");
  if (!status.watching) return t("watch.paused");
  return status.lastCheck ? t("watch.checked", { when: since(status.lastCheck) }) : t("watch.starting");
}
