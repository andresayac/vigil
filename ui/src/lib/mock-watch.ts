// Fictitious background-watch data for previewing the UI in a browser. Nothing here describes a real computer.
import type { WatchAlert, WatchSettings, WatchStatus } from "./types";

const now = Date.now();
const minutes = (n: number) => now - n * 60_000;

let settings: WatchSettings = {
  watching: true, closeToTray: true, notifyStartup: true, notifyServices: true, notifyTasks: true, notifySecurity: true,
  notifyPorts: true, trayNoticeShown: true,
};
let pausedUntil: number | null = null;
let autostart = false;

let alerts: WatchAlert[] = [
  { id: 6, time: minutes(3), kind: "startup", severity: "warning", target: "startup", read: false,
    title: "New startup entry: OddHelper",
    detail: "C:\\Users\\jdoe\\AppData\\Roaming\\OddHelper\\helper.exe --hidden (in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)" },
  { id: 5, time: minutes(42), kind: "port", severity: "warning", target: "network", read: false,
    title: "Port 5900 (VNC) is open to the network", detail: "winvnc.exe accepts connections on every network interface." },
  { id: 4, time: minutes(95), kind: "service", severity: "warning", target: "services", read: false,
    title: "New service: Contoso Update Service", detail: "\"C:\\Program Files\\Contoso\\Update\\cupdate.exe\" /svc" },
  { id: 3, time: minutes(60 * 26), kind: "security", severity: "critical", target: "alerts", read: true,
    title: "The firewall is off for public networks",
    detail: "Programs on this computer can be reached from the network without the firewall's rules." },
  { id: 2, time: minutes(60 * 30), kind: "task", severity: "warning", target: "tasks", read: true,
    title: "New scheduled task: ContosoSync", detail: "\\Contoso\\ContosoSync" },
  { id: 1, time: minutes(60 * 49), kind: "service", severity: "warning", target: "services", read: true,
    title: "Service now starts automatically: Example Telemetry", detail: "C:\\Program Files\\Example\\telemetry.exe" },
];

export function watchStatus(): WatchStatus {
  return {
    owner: true, watching: settings.watching, lastCheck: now - 25_000, unread: alerts.filter((a) => !a.read).length,
    notifyPausedUntil: pausedUntil && pausedUntil > Date.now() ? pausedUntil : null, tasksWatched: false, settings: { ...settings },
    autostart, recent: alerts.slice(0, 5), error: null,
  };
}

export function watchAlerts(): WatchAlert[] {
  return alerts.map((a) => ({ ...a }));
}

export function watchMarkRead(ids: number[] | null): WatchStatus {
  alerts = alerts.map((a) => (ids === null || ids.includes(a.id) ? { ...a, read: true } : a));
  return watchStatus();
}

export function watchClear(): WatchStatus {
  alerts = [];
  return watchStatus();
}

export function watchSetWatching(on: boolean): WatchStatus {
  settings = { ...settings, watching: on };
  return watchStatus();
}

export function watchPauseNotifications(pause: boolean): WatchStatus {
  pausedUntil = pause ? Date.now() + 3_600_000 : null;
  return watchStatus();
}

export function watchConfigure(next: WatchSettings): WatchStatus {
  settings = { ...next, trayNoticeShown: settings.trayNoticeShown };
  return watchStatus();
}

/** The preview has no action engine: the switch just flips. */
export function setAutostart(on: boolean): void {
  autostart = on;
}
