// Fictitious event log data for previewing the Reliability page in a browser.
// Nothing here describes a real computer.
import type {
  Reliability, ReliabilityAppGroup, ReliabilityCategory, ReliabilityEvent, ReliabilityHint,
} from "./types";

const DAY = 86_400_000;
const CATEGORIES: ReliabilityCategory[] = [
  "bluescreen", "shutdown", "app_crash", "app_hang", "service", "hardware", "disk", "update", "install",
];

function iso(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

let record = 1000;
function event(daysAgo: number, hour: number, extra: Partial<ReliabilityEvent>): ReliabilityEvent {
  const now = new Date();
  const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() - daysAgo, hour, (daysAgo * 7) % 60, 12).getTime();
  const timeMs = Math.min(day, now.getTime() - 60_000);
  record += 1;
  const log = extra.log ?? "System";
  return {
    id: `${log}:${record}`, category: "app_crash", kind: "crash", severity: "error", timeMs, time: iso(timeMs), log,
    provider: "", eventId: 0, recordId: record, subject: "", version: "", module: "", moduleVersion: "", code: "",
    codeName: "", parameters: "", path: "", pathExists: null, publisher: "", count: 0, message: "", ...extra,
  };
}

const NOTES = "C:\\Program Files\\Contoso\\Notes\\notes.exe";
const RACING = "C:\\Program Files\\Fabrikam\\Racing\\racing.exe";
const PAINT = "C:\\Program Files\\Litware\\Paint\\paint.exe";

const crash = (daysAgo: number, hour: number, app: string, path: string, module: string, code: string, codeName: string) =>
  event(daysAgo, hour, {
    log: "Application", provider: "Application Error", eventId: 1000, subject: app, version: "4.2.1.0", module,
    moduleVersion: "10.0.26100.1", code, codeName, parameters: "0x000000000004c2f8", path,
    message: `Faulting application name: ${app}, version: 4.2.1.0\nFaulting module name: ${module}, version: 10.0.26100.1\n` +
      `Exception code: ${code.toLowerCase()}\nFault offset: 0x000000000004c2f8\nFaulting application path: ${path}`,
  });

function build(): ReliabilityEvent[] {
  record = 1000;
  return [
    event(2, 21, {
      category: "bluescreen", kind: "bugcheck", severity: "critical", provider: "Microsoft-Windows-WER-SystemErrorReporting",
      eventId: 1001, subject: "VIDEO_TDR_FAILURE", code: "0x00000116", codeName: "VIDEO_TDR_FAILURE",
      parameters: "0xffffd30a5e4c7010, 0xfffff8043a0e3ac0, 0xffffffffc000009a, 0x0000000000000004",
      path: "C:\\Windows\\Minidump\\010626-14062-01.dmp", pathExists: true,
      message: "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116 (0xffffd30a5e4c7010, 0xfffff8043a0e3ac0, " +
        "0xffffffffc000009a, 0x0000000000000004). A dump was saved in: C:\\Windows\\Minidump\\010626-14062-01.dmp.",
    }),
    event(19, 9, {
      category: "bluescreen", kind: "bugcheck", severity: "critical", provider: "Microsoft-Windows-WER-SystemErrorReporting",
      eventId: 1001, subject: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", code: "0x000000D1", codeName: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
      parameters: "0x0000000000000028, 0x0000000000000002, 0x0000000000000000, 0xfffff80450a2c4e1",
      path: "C:\\Windows\\MEMORY.DMP", pathExists: false,
      message: "The computer has rebooted from a bugcheck. The bugcheck was: 0x000000d1. A dump was saved in: C:\\Windows\\MEMORY.DMP.",
    }),
    event(8, 23, {
      category: "shutdown", kind: "power_loss", provider: "Microsoft-Windows-Kernel-Power", eventId: 41,
      message: "The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped " +
        "responding, crashed, or lost power unexpectedly.",
    }),
    event(14, 18, {
      category: "shutdown", kind: "power_button", provider: "Microsoft-Windows-Kernel-Power", eventId: 41,
      message: "The system has rebooted without cleanly shutting down first.",
    }),
    crash(0, 10, "notes.exe", NOTES, "contoso.spell.dll", "0xC0000005", "ACCESS_VIOLATION"),
    crash(1, 16, "notes.exe", NOTES, "contoso.spell.dll", "0xC0000005", "ACCESS_VIOLATION"),
    crash(4, 11, "notes.exe", NOTES, "ntdll.dll", "0xC0000374", "HEAP_CORRUPTION"),
    crash(6, 20, "notes.exe", NOTES, "contoso.spell.dll", "0xC0000005", "ACCESS_VIOLATION"),
    crash(2, 20, "racing.exe", RACING, "nvwgf2umx.dll", "0xC0000005", "ACCESS_VIOLATION"),
    crash(12, 22, "racing.exe", RACING, "nvwgf2umx.dll", "0xC0000409", "STACK_BUFFER_OVERRUN"),
    crash(9, 14, "paint.exe", PAINT, "contoso.spell.dll", "0xC0000005", "ACCESS_VIOLATION"),
    event(3, 15, {
      category: "app_hang", kind: "hang", severity: "warning", log: "Application", provider: "Application Hang", eventId: 1002,
      subject: "paint.exe", version: "2.0.0.0", path: PAINT, parameters: "Top level window is idle",
      message: "The program paint.exe version 2.0.0.0 stopped interacting with Windows and was closed.",
    }),
    event(10, 13, {
      category: "app_hang", kind: "hang", severity: "warning", log: "Application", provider: "Application Hang", eventId: 1002,
      subject: "paint.exe", version: "2.0.0.0", path: PAINT, parameters: "Quiesce",
      message: "The program paint.exe version 2.0.0.0 stopped interacting with Windows and was closed.",
    }),
    ...[1, 5, 11].map((d) => event(d, 8, {
      category: "service", kind: "crashed", provider: "Service Control Manager", eventId: 7031, subject: "Contoso Updater",
      count: 1, message: "The Contoso Updater service terminated unexpectedly. It has done this 1 time(s).",
    })),
    event(7, 8, {
      category: "service", kind: "start_failed", severity: "warning", provider: "Service Control Manager", eventId: 7000,
      subject: "Fabrikam License Service", code: "2",
      message: "The Fabrikam License Service service failed to start due to the following error:\nThe system cannot find the file specified.",
    }),
    event(16, 10, {
      category: "hardware", kind: "corrected", severity: "warning", provider: "Microsoft-Windows-WHEA-Logger", eventId: 17,
      subject: "PCI Express Root Port",
      message: "A corrected hardware error has occurred.\n\nComponent: PCI Express Root Port\nError Source: Advanced Error Reporting (PCI Express)",
    }),
    ...[0, 0, 3, 3, 3, 13].map((d, i) => event(d, 9 + i, {
      category: "disk", kind: "retried", severity: "warning", provider: "disk", eventId: 153, subject: "\\Device\\Harddisk2\\DR3",
      message: "The IO operation at logical block address 0x1d4c0 for Disk 2 (PDO name: \\Device\\0000004e) was retried.",
    })),
    ...[2, 9, 16, 23].map((d) => event(d, 3, {
      category: "update", kind: "install_failed", severity: "warning", provider: "Microsoft-Windows-WindowsUpdateClient",
      eventId: 20, subject: "Contoso Notes 4.2 - Store update", code: "0x80073D02",
      message: "Installation Failure: Windows failed to install the following update with error 0x80073D02: Contoso Notes 4.2 - Store update.",
    })),
    event(5, 17, {
      category: "install", kind: "installed", severity: "info", log: "Application", provider: "MsiInstaller", eventId: 1033,
      subject: "Contoso Notes", version: "4.2.1", publisher: "Contoso Ltd.",
      message: "Windows Installer installed the product. Product Name: Contoso Notes. Product Version: 4.2.1. Manufacturer: Contoso Ltd. " +
        "Installation success or error status: 0.",
    }),
    event(18, 12, {
      category: "install", kind: "removed", severity: "info", log: "Application", provider: "MsiInstaller", eventId: 1034,
      subject: "Litware Paint Toolbar", version: "1.0.3", publisher: "Litware",
      message: "Windows Installer removed the product. Product Name: Litware Paint Toolbar. Removal success or error status: 0.",
    }),
    event(26, 12, {
      category: "install", kind: "install_failed", severity: "warning", log: "Application", provider: "MsiInstaller", eventId: 1033,
      subject: "Fabrikam Racing Launcher", version: "3.1.0", publisher: "Fabrikam", code: "1603",
      message: "Windows Installer installed the product. Product Name: Fabrikam Racing Launcher. Installation success or error status: 1603.",
    }),
  ];
}

function group(events: ReliabilityEvent[], category: ReliabilityCategory): ReliabilityAppGroup[] {
  const groups = new Map<string, ReliabilityAppGroup>();
  const modules = new Map<string, Map<string, number>>();
  for (const e of events.filter((x) => x.category === category)) {
    const key = e.subject.toLowerCase();
    let g = groups.get(key);
    if (!g) {
      g = { key, name: e.subject, path: e.path, count: 0, firstMs: e.timeMs, lastMs: e.timeMs, versions: [], topModule: "", topModuleCount: 0, events: [] };
      groups.set(key, g);
      modules.set(key, new Map());
    }
    g.count += 1;
    g.firstMs = e.timeMs;
    if (e.version && !g.versions.includes(e.version)) g.versions.push(e.version);
    g.events.push(e.id);
    if (e.module) modules.get(key)!.set(e.module, (modules.get(key)!.get(e.module) ?? 0) + 1);
  }
  for (const [key, g] of groups) {
    const top = [...modules.get(key)!.entries()].sort((a, b) => b[1] - a[1])[0];
    if (top) [g.topModule, g.topModuleCount] = top;
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || b.lastMs - a.lastMs);
}

export function reliability(days: number): Reliability {
  const now = Date.now();
  const since = now - days * DAY;
  const events = build().filter((e) => e.timeMs >= since).sort((a, b) => b.timeMs - a.timeMs);
  const counts = Object.fromEntries(CATEGORIES.map((c) => [c, events.filter((e) => e.category === c).length])) as Record<ReliabilityCategory, number>;
  const ids = (test: (e: ReliabilityEvent) => boolean) => events.filter(test).map((e) => e.id);
  const hints: ReliabilityHint[] = [];
  const add = (hint: Omit<ReliabilityHint, "events" | "count">, test: (e: ReliabilityEvent) => boolean) => {
    const found = ids(test);
    if (found.length) hints.push({ ...hint, count: found.length, events: found });
  };
  add({ code: "graphics_driver", severity: "warn", subject: "VIDEO_TDR_FAILURE", detail: "", title: "Graphics driver",
        text: "3 problems involve the graphics driver (VIDEO_TDR_FAILURE). Install the latest driver from the graphics card maker " +
              "(NVIDIA, AMD or Intel); if they started after a driver update, go back to the previous version." },
      (e) => e.codeName === "VIDEO_TDR_FAILURE" || e.module === "nvwgf2umx.dll");
  add({ code: "shared_module", severity: "warn", subject: "contoso.spell.dll", detail: "2", title: "One module in several crashes",
        text: "4 crashes in 2 different programs happened inside contoso.spell.dll. That points to contoso.spell.dll (or the add-in, " +
              "overlay, security program or driver it belongs to) rather than to the programs themselves." },
      (e) => e.module === "contoso.spell.dll");
  add({ code: "power_loss", severity: "info", subject: "", detail: "", title: "Shutdowns without a blue screen",
        text: "The computer stopped once without shutting down properly and without a blue screen. That usually means a power cut, " +
              "a forced restart or the computer freezing completely. If it happens while you use it normally, check the power supply " +
              "and temperatures." },
      (e) => e.kind === "power_loss");
  add({ code: "disk_retries", severity: "info", subject: "\\Device\\Harddisk2\\DR3", detail: "", title: "Disk retries",
        text: "Windows retried 6 reads or writes on disk 2. Occasional retries are harmless; many can mean a loose cable, " +
              "a USB drive without enough power or a disk that is wearing out." },
      (e) => e.kind === "retried");
  add({ code: "update_repeat", severity: "info", subject: "Contoso Notes 4.2 - Store update", detail: "0x80073D02", title: "An update keeps failing",
        text: "Contoso Notes 4.2 - Store update failed to install 4 times (error 0x80073D02). Windows tries again on its own; if it " +
              "keeps failing, the Windows Update troubleshooter in Settings can repair the update components." },
      (e) => e.category === "update");
  return {
    days, sinceMs: since, readMs: now, events, counts,
    crashingApps: group(events, "app_crash"), hangingApps: group(events, "app_hang"),
    boots: [2, 5, 9, 14, 20].map((d, i) => {
      const timeMs = now - d * DAY;
      return { timeMs, time: iso(timeMs), bootMs: 28_400 + i * 2_100, mainPathMs: 11_200 + i * 400, postBootMs: 17_200 + i * 1_700 };
    }).filter((b) => b.timeMs >= since),
    hints, unreadLogs: [], truncated: false,
  };
}
