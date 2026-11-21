// Fictitious data for previewing the UI in a browser (`npm run dev`), where the Rust backend
// is not available. Nothing here describes a real computer.
import type { AppInfo, Connection, LivePayload, ProcessRow, Snapshot } from "./types";

const NAMES = [
  ["System", 4, 0], ["Registry", 120, 4], ["smss.exe", 480, 4], ["csrss.exe", 640, 600], ["wininit.exe", 700, 600],
  ["services.exe", 820, 700], ["lsass.exe", 840, 700], ["svchost.exe", 1010, 820], ["svchost.exe", 1044, 820],
  ["svchost.exe", 1180, 820], ["MsMpEng.exe", 3120, 820], ["dwm.exe", 1400, 1300], ["explorer.exe", 5200, 5100],
  ["chrome.exe", 6100, 5200], ["chrome.exe", 6150, 6100], ["chrome.exe", 6160, 6100], ["chrome.exe", 6170, 6100],
  ["Code.exe", 7200, 5200], ["Code.exe", 7230, 7200], ["Code.exe", 7260, 7200], ["Discord.exe", 8100, 5200],
  ["Spotify.exe", 8400, 5200], ["steam.exe", 9100, 5200], ["steamwebhelper.exe", 9150, 9100], ["OneDrive.exe", 9500, 5200],
  ["nvcontainer.exe", 2400, 820], ["audiodg.exe", 2600, 1044], ["SearchHost.exe", 4100, 1010], ["Taskmgr.exe", 9900, 5200],
] as const;

const PATHS: Record<string, string> = {
  "explorer.exe": "C:\\Windows\\explorer.exe", "chrome.exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "Code.exe": "C:\\Users\\jdoe\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
  "svchost.exe": "C:\\Windows\\System32\\svchost.exe", "MsMpEng.exe": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
  "Discord.exe": "C:\\Users\\jdoe\\AppData\\Local\\Discord\\app-1.0\\Discord.exe", "steam.exe": "C:\\Program Files (x86)\\Steam\\steam.exe",
};

let t = 0;
const BOOT = Date.now() - 12 * 3600 * 1000;   // stable start times, so selections survive refreshes
const wave = (base: number, amp: number, speed: number, phase = 0) =>
  Math.max(0, base + amp * Math.sin(t * speed + phase) + (Math.random() - 0.5) * amp * 0.6);

export function appInfo(): AppInfo {
  return {
    version: "1.0.0 (preview)", elevated: false, cpuName: "Example 8-Core Processor", language: "en",
    adapters: [{ luid: "0x00000000_0x0000A1B2", name: "Example GPU 16 GB", vendorId: 0x10de, dedicatedTotal: 16 * 2 ** 30,
                 sharedTotal: 31 * 2 ** 30, software: false }],
    dataDir: "C:\\Users\\jdoe\\AppData\\Local\\Vigil", dataWarning: null,
  };
}

function processes(): ProcessRow[] {

  return NAMES.map(([name, pid, ppid], i) => ({
    pid, ppid, name, exe: PATHS[name] ?? (pid > 100 ? `C:\\Windows\\System32\\${name}` : ""),
    user: pid < 2000 ? "NT AUTHORITY\\SYSTEM" : "PC-EXAMPLE\\jdoe", cmdline: PATHS[name] ?? name,
    cpu: name === "chrome.exe" || name === "Code.exe" ? wave(2, 2, 0.7, i) : wave(0.15, 0.2, 0.5, i),
    privateBytes: (20 + ((i * 37) % 400)) * 2 ** 20, workingSet: (40 + ((i * 53) % 600)) * 2 ** 20,
    threads: 4 + (i % 30), handles: 100 + i * 17, session: pid < 2000 ? 0 : 1,
    createdMs: BOOT + i * 600_000, ioBps: i % 5 === 0 ? wave(200_000, 150_000, 0.4, i) : 0,
    status: name === "SearchHost.exe" ? "suspended" : "running",
  }));
}

function snapshot(): Snapshot {
  t += 1;
  const perCore = Array.from({ length: 16 }, (_, i) => Math.min(100, wave(14, 12, 0.3 + i * 0.05, i)));
  const total = 64 * 2 ** 30, used = wave(21, 1.5, 0.05) * 2 ** 30;
  return {
    timeMs: Date.now(), cpu: perCore.reduce((a, b) => a + b, 0) / perCore.length, perCore,
    freqMhz: wave(4800, 300, 0.2), baseMhz: 3800, processes: 342, threads: 6400, handles: 176000, uptimeS: 44000 + t,
    memory: { total, available: total - used, used, commit: used * 1.2, commitLimit: total * 1.5, standby: 38 * 2 ** 30,
              modified: 1.5 * 2 ** 30, free: total - used - 38 * 2 ** 30 - 1.5 * 2 ** 30, compressed: 2.1 * 2 ** 30,
              pagedPool: 1.1 * 2 ** 30, nonpagedPool: 0.6 * 2 ** 30 },
    gpus: [{ luid: "0x00000000_0x0000A1B2", name: "Example GPU 16 GB", utilization: wave(12, 10, 0.25),
             engines: [["3D", wave(12, 10, 0.25)], ["Copy", wave(1, 1, 0.6)], ["VideoDecode", wave(4, 3, 0.4)]],
             dedicatedUsed: wave(1.6, 0.2, 0.1) * 2 ** 30, dedicatedTotal: 16 * 2 ** 30, sharedUsed: 0.3 * 2 ** 30,
             sharedTotal: 31 * 2 ** 30 }],
    disks: [{ key: "0 C:", label: "Disk 0 (C:)", readBps: wave(4e6, 4e6, 0.5), writeBps: wave(2e6, 2e6, 0.7),
              active: Math.min(100, wave(8, 7, 0.5)), queue: 0.1 },
            { key: "1 D:", label: "Disk 1 (D:)", readBps: 0, writeBps: wave(1e4, 1e4, 0.2), active: wave(0.5, 0.5, 0.3), queue: 0 }],
    nets: [{ name: "Ethernet", sentBps: wave(40_000, 30_000, 0.6), recvBps: wave(400_000, 300_000, 0.45), linkBps: 1e9 }],
    gpuByPid: [{ pid: 6100, utilization: wave(6, 4, 0.3), dedicated: 420 * 2 ** 20 },
               { pid: 1400, utilization: wave(3, 2, 0.4), dedicated: 210 * 2 ** 20 }],
  };
}

export function payload(): LivePayload {
  return { snapshot: snapshot(), processes: processes(), error: null };
}

export function connections(): Connection[] {
  return [
    { pid: 6100, process: "chrome.exe", exe: PATHS["chrome.exe"], protocol: "TCP", local: "192.168.1.20:52114",
      remote: "203.0.113.10:443", remoteIp: "203.0.113.10", state: "ESTABLISHED", public: true },
    { pid: 8100, process: "Discord.exe", exe: PATHS["Discord.exe"], protocol: "TCP", local: "192.168.1.20:52200",
      remote: "203.0.113.25:443", remoteIp: "203.0.113.25", state: "ESTABLISHED", public: true },
    { pid: 1044, process: "svchost.exe", exe: PATHS["svchost.exe"], protocol: "UDP", local: "0.0.0.0:5353", remote: "",
      remoteIp: "", state: "", public: false },
    { pid: 840, process: "lsass.exe", exe: "C:\\Windows\\System32\\lsass.exe", protocol: "TCP", local: "0.0.0.0:49664",
      remote: "", remoteIp: "", state: "LISTEN", public: false },
  ];
}

export * from "./mock-pages";
