// Fictitious background-watch data for previewing the UI in a browser. Nothing here describes a real computer.
import type { WatchAlert, WatchSettings, WatchStatus } from "./types";

const now = Date.now();
const minutes = (n: number) => now - n * 60_000;

let settings: WatchSettings = {
  watching: true, closeToTray: true, notifyStartup: true, notifyServices: true, notifyTasks: true, notifySecurity: true,
  notifyPorts: true, notifyHooks: true, notifyEvents: true, trayNoticeShown: true,
  scanSchedule: "daily", scanDay: 1, scanTime: "12:30",
};
let pausedUntil: number | null = null;
let autostart = false;

let alerts: WatchAlert[] = [
  { id: 10, time: minutes(1), kind: "scan", severity: "critical", target: "findings", read: false,
    title: "New since the last scan: winupd.exe",
    detail: "It is not signed, lives in a user folder and starts at sign-in." },
  { id: 9, time: minutes(1), kind: "hook", severity: "critical", target: "alerts", read: false,
    title: "A program now starts instead of sethc.exe",
    detail: "Windows runs C:\\Windows\\System32\\cmd.exe whenever sethc.exe is started (in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options)." },
  { id: 8, time: minutes(2), kind: "event", severity: "critical", target: "protection", read: false,
    title: "Microsoft Defender found a threat: Trojan:Win32/Contoso.A", detail: "C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe" },
  { id: 7, time: minutes(2), kind: "driver", severity: "warning", target: "alerts", read: false,
    title: "New driver outside the Windows driver folders: fabrikamfs", detail: "\\??\\D:\\Tools\\Fabrikam\\fabrikamfs.sys" },
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
    notifyPausedUntil: pausedUntil && pausedUntil > Date.now() ? pausedUntil : null, tasksWatched: false, logsHidden: ["Security"], settings: { ...settings },
    autostart, recent: alerts.slice(0, 5), error: null,
    autoScan: {
      schedule: settings.scanSchedule, next: now + 20 * 3_600_000, lastRun: minutes(2), status: "done", found: 1,
      partial: true, report: true, running: false,
    },
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
