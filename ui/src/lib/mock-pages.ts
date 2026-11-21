// Fictitious data for previewing the security and maintenance pages in a browser.
// Nothing here describes a real computer.
import type {
  ActionSpec, AiProvider, AiStatus, Analysis, CleanupTarget, Hardware, Insight, Item, JournalRecord, ProcessDetails, ReviewOffer,
  Service, Settings, SpaceNode, SpaceScan, TuningState, Volume,
} from "./types";

function item(id: string, kind: string, title: string, verdict: string, score: number, extra: Partial<Item> = {}): Item {
  return {
    kind, title, subtitle: "", id, path: kind === "executable" ? `C:\\Users\\jdoe\\AppData\\Roaming\\${title}` : null,
    file: kind === "executable" ? { exists: true, sig_status: "NotSigned", size: 182_272 } : null,
    roles: [{ kind: "startup", label: `startup entry "${title}" in HKCU Run`, detail: {}, command: "", persistent: true,
              privileged: false, active: true }],
    commands: [], decoded: [], network: {}, flags: score ? [{ code: "unsigned", weight: score, text: "no digital signature" }] : [],
    score, trusted: verdict === "trusted", facts: {}, members: [], sha256: null, vt: null, verdict, verdict_source: "ai",
    confidence: "high", what: "A small program that starts with Windows.", reason: "It is not signed and lives in a user folder.",
    action: "Remove it completely.", remediation: [], actions_taken: [],
    level: verdict === "trusted" ? "trusted" : score >= 70 ? "critical" : score >= 40 ? "suspicious" : score >= 15 ? "attention" : "no_signals",
    ...extra,
  };
}

export function services(): Service[] {
  const sys = "C:\\Windows\\System32\\";
  const hosted = (name: string, displayName: string, description: string, state: string, startType: string, pid: number,
                  group: string, dll: string, account = "LocalSystem"): Service => ({
    name, displayName, description, state, startType, pid, serviceType: "share", path: `${sys}svchost.exe -k ${group} -p`,
    executable: `${sys}svchost.exe`, dll: sys + dll, account, group: group.toLowerCase(), protected: true,
  });
  const own = (name: string, displayName: string, description: string, state: string, startType: string, pid: number,
               path: string, account = "LocalSystem", locked = false): Service => ({
    name, displayName, description, state, startType, pid, serviceType: "own", path,
    executable: path.startsWith('"') ? path.slice(1, path.indexOf('"', 1)) : path.split(" ")[0], dll: "", account, group: "",
    protected: locked,
  });
  return [
    hosted("AudioSrv", "Windows Audio", "Manages audio for Windows-based programs.", "running", "auto", 1044,
           "LocalServiceNetworkRestricted", "Audiosrv.dll", "NT AUTHORITY\\LocalService"),
    hosted("BITS", "Background Intelligent Transfer Service", "Transfers files in the background using idle network bandwidth.",
           "stopped", "demand", 0, "netsvcs", "qmgr.dll"),
    hosted("Dnscache", "DNS Client", "Caches Domain Name System (DNS) names and registers the full computer name.", "running", "auto",
           1180, "NetworkService", "dnsrslvr.dll", "NT AUTHORITY\\NetworkService"),
    hosted("EventLog", "Windows Event Log", "Manages events and event logs.", "running", "auto", 1010, "LocalServiceNetworkRestricted",
           "wevtsvc.dll", "NT AUTHORITY\\LocalService"),
    own("WinDefend", "Microsoft Defender Antivirus Service", "Helps protect users from malware and other potentially unwanted software.",
        "running", "auto", 3120, "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe\"", "LocalSystem", true),
    own("Spooler", "Print Spooler", "Spools print jobs and handles interaction with the printer.", "running", "auto", 2210,
        `${sys}spoolsv.exe`, "LocalSystem", true),
    hosted("TermService", "Remote Desktop Services", "Allows users to connect interactively to a remote computer.", "stopped", "demand",
           0, "NetworkService", "termsrv.dll", "NT AUTHORITY\\NetworkService"),
    hosted("Themes", "Themes", "Provides user experience theme management.", "running", "auto", 1010, "netsvcs", "themeservice.dll"),
    hosted("wuauserv", "Windows Update", "Enables the detection, download and installation of updates for Windows and other programs.",
           "stopped", "demand", 0, "netsvcs", "wuaueng.dll"),
    own("WSearch", "Windows Search", "Provides content indexing, property caching and search results.", "running", "delayed-auto", 3900,
        `${sys}SearchIndexer.exe /Embedding`, "LocalSystem", true),
    own("NVDisplay.ContainerLocalSystem", "NVIDIA Display Container LS", "Container service for NVIDIA root features.", "running", "auto",
        2400, "\"C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe\" -s NVDisplay.ContainerLocalSystem"),
    own("Steam Client Service", "Steam Client Service", "Steam Client Service monitors and updates Steam content.", "stopped", "demand", 0,
        "\"C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe\" /RunAsService"),
    own("gupdate", "Google Update Service (gupdate)", "Keeps your Google software up to date.", "stopped", "delayed-auto", 0,
        "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc"),
    own("ContosoSync", "Contoso Sync Agent", "", "running", "auto", 4480, "C:\\ProgramData\\Contoso\\syncagent.exe --service"),
    own("OddHelper", "Odd Helper", "", "stopped", "disabled", 0, "C:\\Users\\jdoe\\AppData\\Roaming\\OddHelper\\helper.exe"),
    own("MySQL80", "MySQL80", "", "running", "auto", 3300,
        "\"C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqld.exe\" --defaults-file=\"C:\\ProgramData\\MySQL\\my.ini\" MySQL80",
        "NT AUTHORITY\\NetworkService"),
  ].sort((a, b) => a.displayName.localeCompare(b.displayName));
}

export function processDetails(pid: number): ProcessDetails {
  const system = "C:\\Windows\\System32\\";
  const modules = ["ntdll.dll", "kernel32.dll", "KernelBase.dll", "user32.dll", "win32u.dll", "gdi32.dll", "combase.dll", "rpcrt4.dll"]
    .map((name, i) => ({ name, path: system + name, size: (400 + i * 230) * 1024, userWritable: false }));
  if (pid === 7260) {
    modules.push({ name: "helper.dll", path: "C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.dll", size: 184 * 1024, userWritable: true });
  }
  const services = pid === 1044
    ? [{ name: "Dnscache", displayName: "DNS Client" }, { name: "LanmanWorkstation", displayName: "Workstation" },
       { name: "NlaSvc", displayName: "Network Location Awareness" }]
    : [];
  return { modules, modulesError: null, services };
}

export function analysis(): Analysis {
  const items = [
    item("B1", "executable", "winupd.exe", "remove", 85), item("B2", "executable", "helper.exe", "remove", 60),
    item("X1", "extension", "Free VPN Unlimited", "remove", 40),
    item("C1", "command", "powershell.exe -NoP -W Hidden -Enc SQBFAFgA", "disable", 55),
    item("P1", "program", "Old Updater 1.2", "disable", 20), item("B3", "executable", "tool.exe", "review", 30),
    item("S1", "config", "Remote Desktop is on", "review", 25), item("E1", "event", "Security log cleared", "review", 45),
    item("B4", "executable", "Code.exe", "safe", 0), item("B5", "executable", "explorer.exe", "trusted", 0),
  ];
  return {
    meta: { started: "2026-01-01T10:00:00", is_admin: true, user: "jdoe", computer: "PC-EXAMPLE" },
    stats: { elements: 1316, auto_trusted: 1020, to_analyze: 296 },
    summary: {
      risk_level: "high", headline: "Two programs look like malware and an extension can read your logins.",
      summary: "Example report shown in the browser preview. Nothing here describes a real computer.",
      priority_actions: [
        { title: "Remove winupd.exe and helper.exe", detail: "Both start with Windows from your user folder and are not signed.", ids: ["B1", "B2"] },
        { title: "Remove the Free VPN extension", detail: "It can read and change data on every site.", ids: ["X1"] },
      ],
      good_practices: ["Run a Defender full scan once a month.", "Install extensions only from the official stores."],
    },
    ai: { model: "claude-opus-5-5", with_verdict: 296 },
    posture: {
      system: "Windows 11 Pro (example)",
      defender: { realtime_protection: true, tamper_protection: true, signature_age_days: 0, last_full_scan: "never" },
      firewall: { Domain: true, Private: true, Public: true }, uac: "enabled", remote_desktop: "enabled",
    },
    notes: [{ area: "tasks", message: "8 Microsoft tasks use COM objects whose file could not be resolved." }],
    items,
  };
}

export function reviewOffer(): ReviewOffer {
  const status = aiStatus();
  return { pending: 296, destination: status.destination, problem: status.problem, redact: current.ai.redact, local: status.local,
           preview: [{ id: "B1", kind: "executable", title: "winupd.exe", path: "C:\\Users\\<user>\\AppData\\Roaming\\winupd.exe" }] };
}

export function plan(itemId: string): ActionSpec[] {
  const base = { group: "remove", destructive: true, reversible: true, admin: true, warning: "", steps: [] as ActionSpec[] };
  return [
    { ...base, op: "plan.remove", label: "Remove completely", target: itemId, explain: "Ends it, turns off every way it starts and quarantines its file." },
    { ...base, op: "startup.disable", label: "Disable startup entry", target: itemId, explain: "Turns the entry off.", group: "disable", destructive: false },
    { ...base, op: "file.quarantine", label: "Quarantine file", target: itemId, explain: "Moves the file into quarantine." },
    { ...base, op: "shell.location", label: "Open file location", target: itemId, explain: "", group: "inspect", destructive: false, admin: false },
  ];
}

const PREVIEW_START = Date.now();
/** Local ISO time (what the journal stores), `seconds` after the preview started. */
function localIso(ms: number): string {
  const d = new Date(ms);
  const two = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}

export function journal(): JournalRecord[] {
  return [{ id: "r2", batch: null, time: localIso(PREVIEW_START + 4000), op: "memory.purge_standby", label: "Free standby memory",
            target: "Windows memory", item: "", ok: true, message: "freed 2.1 GB of standby memory", undone: false, can_undo: false,
            op_label: "Free standby memory" },
          { id: "r1", batch: null, time: "2026-01-01T10:05:00", op: "startup.disable", label: "Disable startup entry", target: "Updater",
            item: "winupd.exe", ok: true, message: "turned the entry off", undone: false, can_undo: true, op_label: "Disable startup entry" }];
}

export function volumes(): Volume[] {
  return [{ mount: "C:\\", label: "", fs: "NTFS", total: 2e12, used: 1.2e12, free: 0.8e12, removable: false, network: false },
          { mount: "D:\\", label: "Data", fs: "NTFS", total: 5e11, used: 4.6e11, free: 0.4e11, removable: false, network: false }];
}

export function cleanup(): CleanupTarget[] {
  const t = (key: string, label: string, group: string, size: number, selected: boolean): CleanupTarget =>
    ({ key, label, description: `${label} (example).`, group, roots: ["C:\\Example"], kind: "files", size,
       files: Math.round(size / 80_000), admin: false, selected, note: "", minAgeHours: 0 });
  return [t("user_temp", "Temporary files (your account)", "Windows", 7.3e9, true), t("thumbnails", "Thumbnail cache", "Windows", 1.7e8, true),
          t("recycle_bin", "Recycle Bin", "Recycle Bin", 2.5e10, false), t("browser_chrome", "Google Chrome cache", "Browsers", 2.1e9, false),
          t("nvidia_cache", "NVIDIA shader cache", "Graphics", 2.7e10, false)];
}

export function space(root: string): SpaceScan {
  const leaf = (name: string, size: number, dir = true): SpaceNode =>
    ({ name, path: `${root}\\${name}`, size, files: dir ? Math.round(size / 1e6) : 1, isDir: dir, children: [], other: 0 });
  const children = [leaf("Users", 6e11), leaf("Program Files", 2e11), leaf("Windows", 6e10), leaf("Games", 3e11),
                    leaf("pagefile.sys", 3.4e10, false), leaf("ProgramData", 2.5e10)];
  return { root: { name: root, path: root, size: children.reduce((a, c) => a + c.size, 0) + 1e9, files: 900_000, isDir: true, children, other: 1e9 },
           largestFiles: [{ size: 3.4e10, path: `${root}\\pagefile.sys`, modifiedMs: Date.now() }], files: 900_000, folders: 120_000,
           errors: 3, seconds: 9.2, cancelled: false, mergedBelow: 0 };
}

export function hardware(): Hardware {
  return {
    cpu: { name: "Example 8-Core Processor", cores: 8, logical: 16, maxMhz: 3800, l2Kb: 8192, l3Kb: 32768, socket: "AM5", virtualization: true },
    memory: { slots: 4, maxCapacity: 137438953472, modules: [
      { capacity: 34359738368, speed: 6000, configuredSpeed: 6000, bank: "CHANNEL A", type: "DDR5", manufacturer: "Example", partNumber: "EX-32G" },
      { capacity: 34359738368, speed: 6000, configuredSpeed: 6000, bank: "CHANNEL B", type: "DDR5", manufacturer: "Example", partNumber: "EX-32G" }] },
    gpus: [{ name: "Example GPU 16 GB", driverVersion: "32.0.1", driverDate: "2026-09-16", vendorId: "10DE", width: 2560, height: 1440, refreshRate: 165 }],
    disks: [{ number: 0, name: "Example NVMe 2TB", media: "SSD", bus: "NVMe", size: 2e12, health: "Healthy", letters: ["C:"], temperature: 41, wear: 2 }],
    os: { caption: "Windows 11 Pro", version: "10.0.26100", build: "26100", arch: "64-bit", installed: "2026-01-01" },
    board: { manufacturer: "Example", product: "B650" }, bios: { manufacturer: "Example", version: "1.0", date: "2025-06-01" },
    computer: { manufacturer: "Example", model: "Desktop" }, pagefiles: [], battery: null, trim: { ntfs: true },
  };
}

export function insights(): Insight[] {
  return [{ level: "warn", area: "Graphics", text: "The Example GPU driver is 14 months old.", fix: "Install the current driver." },
          { level: "ok", area: "Storage", text: "Every disk reports a healthy status.", fix: "" }];
}

export function tuning(): TuningState {
  return { powerPlans: [{ guid: "381b4222-f694-41f0-9685-ff5bb260df2e", name: "Balanced", active: true },
                        { guid: "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", name: "High performance", active: false }],
           hibernation: { enabled: true, fileSize: 2.6e10 }, gameMode: true, hags: null, memoryIntegrity: true, visualEffects: null,
           gpuPreferences: [] };
}

let current: Settings = {
  theme: "system", language: "auto",
  ai: { provider: "auto", model: "", endpoint: "", effort: "high", redact: true },
  days: 30, virustotal: false, restorePoint: true, autoRefresh: true, secrets: { "openai-compatible": false, "anthropic-compatible": false, virustotal: false },
};

export function settings(): Settings {
  return JSON.parse(JSON.stringify(current));
}

export function saveSettings(next: Settings): Settings {
  current = JSON.parse(JSON.stringify(next));
  return settings();
}

const PROVIDERS: AiProvider[] = [
  { id: "auto", name: "Automatic", kind: "auto", secret: null, needsEndpoint: false, defaultEndpoint: null, defaultModel: "",
    suggestedModels: [], supportsEffort: false, available: true, note: "Uses the first available: Claude Code." },
  { id: "openai-compatible", name: "OpenAI-compatible API", kind: "api", secret: "openai-compatible", needsEndpoint: true,
    defaultEndpoint: "https://api.openai.com/v1", defaultModel: "", suggestedModels: [], supportsEffort: false, available: false,
    note: "Add an API key in Settings (or set OPENAI_API_KEY)." },
  { id: "anthropic-compatible", name: "Anthropic-compatible API", kind: "api", secret: "anthropic-compatible", needsEndpoint: true,
    defaultEndpoint: "https://api.anthropic.com", defaultModel: "claude-opus-5-5",
    suggestedModels: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"], supportsEffort: true, available: false,
    note: "Add an API key in Settings (or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN)." },
  { id: "claude-code", name: "Claude Code", kind: "local-agent", secret: null, needsEndpoint: false, defaultEndpoint: null,
    defaultModel: "claude-opus-5-5", suggestedModels: ["claude-opus-5-5", "claude-sonnet-5-5"], supportsEffort: true,
    available: true, note: "Signed in on this computer." },
  { id: "codex-cli", name: "Codex CLI", kind: "local-agent", secret: null, needsEndpoint: false, defaultEndpoint: null,
    defaultModel: "", suggestedModels: [], supportsEffort: false, available: false, note: "Not installed." },
  { id: "gemini-cli", name: "Gemini CLI", kind: "local-agent", secret: null, needsEndpoint: false, defaultEndpoint: null,
    defaultModel: "", suggestedModels: [], supportsEffort: false, available: false, note: "Not installed." },
  { id: "off", name: "Off", kind: "off", secret: null, needsEndpoint: false, defaultEndpoint: null, defaultModel: "",
    suggestedModels: [], supportsEffort: false, available: true, note: "" },
];

const isLocalhost = (endpoint: string) => /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(endpoint);

export function aiProviders(): AiProvider[] {
  return PROVIDERS.map((p) => {
    // The configured API standard on this computer: an Ollama server with local models.
    if (p.kind === "api" && p.id === current.ai.provider && isLocalhost(current.ai.endpoint)) {
      return { ...p, available: true,
               note: `Ollama answers at ${current.ai.endpoint}. Your data stays on this computer: Ollama cloud models are never used.` };
    }
    if (p.secret && current.secrets[p.secret]) {
      const host = (p.defaultEndpoint ?? "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      return { ...p, available: true, note: `API key saved. The findings to review go to ${host}.` };
    }
    return p;
  });
}

export function aiModels(provider: string, endpoint = ""): string[] {
  if (isLocalhost(endpoint)) return ["example-model:8b", "example-model:14b", "example-coder:7b"];
  return provider === "anthropic-compatible" ? ["claude-haiku-5-5", "claude-opus-5-5", "claude-sonnet-5-5"] : ["example-large", "example-small"];
}

export function aiStatus(): AiStatus {
  const id = current.ai.provider === "auto" ? "claude-code" : current.ai.provider;
  const provider = aiProviders().find((p) => p.id === id);
  if (!provider || id === "off") return { provider: id, destination: null, local: false, problem: "The AI review is turned off." };
  if (!provider.available) return { provider: id, destination: null, local: false, problem: provider.note };
  const model = current.ai.model || provider.defaultModel;
  const endpoint = current.ai.endpoint || provider.defaultEndpoint || "";
  const local = provider.kind === "api" && isLocalhost(endpoint);
  return { provider: id, destination: `${provider.name}${model ? ` (${model})` : ""}${endpoint ? ` · ${endpoint}` : ""}`, local, problem: null };
}
