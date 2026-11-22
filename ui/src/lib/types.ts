// Mirrors of the Rust structs (serde camelCase). Keep in sync with crates/vigil-sys.

export type ProcessStatus = "running" | "suspended";

export interface ProcessRow {
  pid: number;
  ppid: number;
  name: string;
  exe: string;
  user: string;
  cmdline: string;
  cpu: number;
  privateBytes: number;
  workingSet: number;
  threads: number;
  handles: number;
  session: number;
  createdMs: number;
  ioBps: number;
  status: ProcessStatus;
  /** Owns a window on the desktop (Task Manager lists it under Apps). */
  window: boolean;
  /** File description of the program ("Google Chrome"); empty when the file has none. */
  description: string;
}

export interface GpuAdapter {
  luid: string;
  name: string;
  vendorId: number;
  dedicatedTotal: number;
  sharedTotal: number;
  software: boolean;
}

export interface MemoryState {
  total: number;
  available: number;
  used: number;
  commit: number;
  commitLimit: number;
  standby: number;
  modified: number;
  free: number;
  compressed: number;
  pagedPool: number;
  nonpagedPool: number;
}

export interface GpuState {
  luid: string;
  name: string;
  utilization: number;
  engines: [string, number][];
  dedicatedUsed: number;
  dedicatedTotal: number;
  sharedUsed: number;
  sharedTotal: number;
}

export interface DiskState {
  key: string;
  label: string;
  readBps: number;
  writeBps: number;
  active: number;
  queue: number;
}

export interface NetState {
  name: string;
  sentBps: number;
  recvBps: number;
  linkBps: number;
}

export interface GpuUse {
  pid: number;
  utilization: number;
  dedicated: number;
}

export interface Snapshot {
  timeMs: number;
  cpu: number;
  perCore: number[];
  freqMhz: number;
  baseMhz: number;
  processes: number;
  threads: number;
  handles: number;
  uptimeS: number;
  memory: MemoryState;
  gpus: GpuState[];
  disks: DiskState[];
  nets: NetState[];
  gpuByPid: GpuUse[];
}

export interface Connection {
  pid: number;
  process: string;
  exe: string;
  protocol: string;
  local: string;
  remote: string;
  remoteIp: string;
  state: string;
  public: boolean;
}

export interface AppInfo {
  version: string;
  elevated: boolean;
  cpuName: string;
  adapters: GpuAdapter[];
  /** Where scans, quarantine, backups and the journal are stored. */
  dataDir: string;
  /** Set when the data folder could not be protected or had to fall back. */
  dataWarning: string | null;
  /** The language Rust writes its own texts in (findings, actions, confirmations). */
  language: string;
  /** Started at sign-in with --tray: the window stays hidden until it is opened from the tray. */
  startHidden: boolean;
}

/** Emitted by the Rust sampler once a second while a live page is open. */
export interface LivePayload {
  snapshot: Snapshot | null;
  processes: ProcessRow[] | null;
  error: string | null;
}

// ---------------------------------------------------------------- scan report (keys of the report JSON)

export interface Flag { code: string; weight: number; text: string }

export interface Role {
  kind: string; label: string; detail: Record<string, unknown>; command: string;
  persistent: boolean; privileged: boolean; active: boolean;
}

export interface ActionTaken { time: string; label: string; ok: boolean; message: string }

export interface Item {
  kind: string; title: string; subtitle: string; id: string; path: string | null;
  file: Record<string, unknown> | null; roles: Role[]; commands: string[]; decoded: string[];
  network: Record<string, unknown>; flags: Flag[]; score: number; trusted: boolean;
  facts: Record<string, unknown>; members: Record<string, unknown>[]; sha256: string | null;
  vt: Record<string, unknown> | null; verdict: string; verdict_source: string; confidence: string;
  what: string; reason: string; action: string; remediation: { title?: string; steps?: string[]; [k: string]: unknown }[];
  actions_taken: ActionTaken[]; level: string;
}

export interface PriorityAction { title?: string; detail?: string; ids?: string[] }

export interface Summary {
  risk_level?: string; headline?: string; summary?: string;
  priority_actions?: PriorityAction[]; good_practices?: string[];
}

export interface Analysis {
  meta: Record<string, unknown>; stats: Record<string, unknown>; summary: Summary | null;
  ai: Record<string, unknown>; posture: Record<string, unknown>; notes: { area?: string; message?: string }[];
  items: Item[];
  /** What changed since the previous scan in the same folder; absent for a first scan. */
  changes?: ScanChanges;
}

/** Comparison with the previous scan. `new` and `changed[].id` are ids of this scan's items; texts are already localized. */
export interface ScanChanges {
  previous: { started: string; path: string };
  new: string[];
  gone: { title: string; kind: string; path: string | null; verdict: string }[];
  changed: { id: string; what: string[] }[];
  posture: string[];
}

// ---------------------------------------------------------------- actions, journal, quarantine

export interface ActionSpec {
  op: string; label: string; target: string; explain: string; group: string;
  destructive: boolean; reversible: boolean; admin: boolean; warning: string; steps: ActionSpec[];
}

/** A journal record (one line of the action journal). */
export interface JournalRecord {
  id: string; batch: string | null; time: string; op: string; label: string; target: string; item: string;
  ok: boolean; message: string; undone: boolean; undo_message?: string; can_undo: boolean; op_label: string;
}

/** The process inspector: loaded modules and hosted services (read-only). */
export interface ProcessModule { name: string; path: string; size: number; userWritable: boolean }
export interface ProcessDetails {
  modules: ProcessModule[]; modulesError: string | null; services: { name: string; displayName: string }[];
}

export interface QuarantineEntry {
  id: string; name: string; original_path: string; quarantined_at: string; size: number;
  sha256: string; reason: string; state?: string; present: boolean;
}

/** A Windows service, as the Services page shows it. */
export interface Service {
  name: string;
  displayName: string;
  description: string;
  /** running, stopped, start_pending, stop_pending, continue_pending, pause_pending or paused. */
  state: string;
  /** auto, delayed-auto, demand, disabled (boot and system are drivers). */
  startType: string;
  /** 0 while stopped. */
  pid: number;
  /** "own" (its own process) or "share" (a service host shared with other services). */
  serviceType: string;
  /** The command line, environment variables expanded. */
  path: string;
  executable: string;
  /** For services hosted by svchost: the DLL that really runs. */
  dll: string;
  account: string;
  /** The svchost group ("netsvcs"), when there is one. */
  group: string;
  /** An essential Windows service or a Windows component: Vigil refuses to change it. */
  protected: boolean;
}

export type ServiceOp = "start" | "stop" | "restart" | "start_type";

/** A program Windows starts at sign-in (Startup apps page), read live. */
export interface StartupEntry {
  /** `reg:<key>\<value>` or `file:<path>`; what an enable/disable request names. */
  id: string;
  /** The registry value name, or the file name without its extension. */
  name: string;
  /** What Windows runs. */
  command: string;
  /** The program the command starts ("" when it cannot be told). */
  executable: string;
  /** The registry key (HKCU\…\Run) or the Startup folder. */
  location: string;
  /** "run", "run_once", "policy" (a Run key set by policy: no on/off switch) or "folder". */
  kind: string;
  /** "user" (this account) or "machine" (every user). */
  scope: string;
  enabled: boolean;
  /** When it was turned off, if Windows recorded it. */
  disabledAtMs: number | null;
  /** RunOnce entries and Run keys set by policy have no on/off switch. */
  canToggle: boolean;
  approvedKey: string;
  value: string;
  /** The file in the Startup folder (folder entries only). */
  file: string;
  /** CompanyName and FileDescription of the program. */
  publisher: string;
  description: string;
  /** The program file exists. */
  exists: boolean;
  /** A Windows host (rundll32, wscript, powershell…) runs what the command names: its publisher and
   *  signature would be the host's, so they are not shown. */
  host: boolean;
  /** Vigil's own sign-in entry (Settings > Start Vigil in the tray when I sign in). */
  own: boolean;
}

export interface StartupSignature {
  status: "valid" | "unsigned" | "broken" | "untrusted" | "missing" | "unknown";
  signer: string;
}

/** An installed program, read from its Uninstall key (vigil_app::programs::ProgramView). */
export interface InstalledProgram {
  /** The full path of its Uninstall key; what program requests name. */
  id: string;
  keyName: string;
  name: string;
  publisher: string;
  version: string;
  /** Local day, YYYY-MM-DD ("" when unknown). */
  installed: string;
  /** The day is the key's last change: the installer wrote no date. */
  installedEstimated: boolean;
  /** Bytes the installer declared (0: none). */
  size: number;
  location: string;
  locationExists: boolean;
  locationEmpty: boolean;
  uninstall: string;
  quietUninstall: string;
  uninstaller: string;
  uninstallerExists: boolean;
  /** msiexec, rundll32…: a Windows host runs the uninstall. */
  uninstallerHost: boolean;
  /** An .exe or .ico for the row's icon. */
  icon: string;
  /** The program's own executable, when the entry names one. */
  executable: string;
  msi: boolean;
  productCode: string;
  msiKnown: boolean;
  noRemove: boolean;
  scope: "machine" | "machine32" | "user";
  /** Another account's program: its SID and name. */
  sid: string;
  account: string;
  /** Its uninstaller and files are gone; only the entry is left. */
  leftover: boolean;
  /** A remote access, remote control or tunnelling tool. */
  remote: boolean;
  microsoft: boolean;
}

/** When a scheduled task starts (vigil_sys::tasks::TaskTrigger). */
export interface TaskTrigger {
  /** "logon", "boot", "idle", "time", "daily", "weekly", "monthly", "monthly_dow", "event", "registration", "session", "custom". */
  kind: string;
  enabled: boolean;
  /** Start boundary as written in the task: local, or with Z / an offset. */
  start: string;
  end: string;
  /** Daily: every N days; weekly: every N weeks. */
  every: number;
  /** Weekday names ("monday"…), or day numbers and "last" for monthly triggers. */
  days: string[];
  /** "1".."4" and "last" (monthly_dow). */
  weeks: string[];
  /** Month names; empty means every month. */
  months: string[];
  repeatSecs: number;
  /** 0 = repeats indefinitely. */
  repeatForSecs: number;
  delaySecs: number;
  randomDelaySecs: number;
  /** Logon: the user. Event: the logs watched. Session: the change ("session_lock"…). */
  detail: string;
}

/** What a scheduled task does. */
export interface TaskAction {
  /** "exec", "com", "email" or "message". */
  kind: string;
  command: string;
  arguments: string;
  workingDir: string;
  classId: string;
  data: string;
  /** The file that really runs (resolved program or COM DLL); "" when unknown. */
  program: string;
}

/** A scheduled task (Scheduled tasks page), read live from Task Scheduler. */
export interface ScheduledTask {
  /** `\Vendor\Updater`: what task requests name. */
  path: string;
  name: string;
  folder: string;
  /** "ready", "running", "disabled", "queued" or "unknown". */
  state: string;
  enabled: boolean;
  hidden: boolean;
  author: string;
  description: string;
  created: string;
  triggers: TaskTrigger[];
  actions: TaskAction[];
  account: string;
  /** "system", "service", "group", "user" or "". */
  accountKind: string;
  /** "highest" or "least". */
  runLevel: string;
  /** "interactive", "password", "s4u", "service", "group" or "". */
  logonType: string;
  /** Highest run level, or runs as SYSTEM. */
  elevated: boolean;
  /** Local ISO times; "" when never / none. */
  lastRun: string;
  /** Exit code or HRESULT of the last run. */
  lastResult: number | null;
  nextRun: string;
  /** The definition file under %SystemRoot%\System32\Tasks. */
  file: string;
  program: string;
  programExists: boolean;
  /** Under \Microsoft\: shown, never changed. */
  microsoft: boolean;
  /** A program (or host script) it runs is in a folder standard users can change. */
  userWritable: boolean;
}

/** A Windows Defender Firewall profile (Firewall rules page). */
export interface FirewallProfile {
  /** "domain", "private" or "public". */
  name: string;
  enabled: boolean;
  /** The computer is on a network of this type now. */
  active: boolean;
  /** "allow" or "block": what happens to traffic no rule matches. */
  defaultInbound: string;
  defaultOutbound: string;
  blockAllInbound: boolean;
}

/** Why a rule deserves a look. `warn` is false for housekeeping (a leftover rule). */
export interface FirewallFlag {
  code: "open_public" | "remote_access" | "writable_program" | "missing_program";
  /** The remote-access port (0 for the other flags). */
  port: number;
  warn: boolean;
}

/** A firewall rule, read live through the firewall API. */
export interface FirewallRule {
  /** What firewall-rule requests name. */
  key: string;
  name: string;
  description: string;
  group: string;
  /** A rule of a group Windows defines: can be turned off, never deleted. */
  builtin: boolean;
  /** Declared by a Microsoft Store app. */
  appPackage: boolean;
  /** "in" or "out". */
  direction: string;
  /** "allow" or "block". */
  action: string;
  enabled: boolean;
  /** "domain", "private", "public". */
  profiles: string[];
  /** "" for every program. */
  program: string;
  programExists: boolean;
  service: string;
  protocol: number;
  protocolName: string;
  /** "" or "*" means any. */
  localPorts: string;
  remotePorts: string;
  localAddresses: string;
  remoteAddresses: string;
  interfaceTypes: string;
  edgeTraversal: boolean;
  /** Created by Vigil's "Block network access". */
  vigil: boolean;
  /** Another rule has the same key: Vigil does not act on either. */
  duplicate: boolean;
  flags: FirewallFlag[];
}

export interface FirewallSummary {
  total: number; enabled: number; inbound: number; outbound: number; inboundAllow: number;
  /** Rules with a warning flag. */
  flagged: number;
  /** Allow rules for programs that no longer exist. */
  missing: number;
  vigil: number;
}

export interface FirewallView { profiles: FirewallProfile[]; rules: FirewallRule[]; summary: FirewallSummary }

/** A Microsoft Defender protection switch (Protection page). */
export interface DefenderSwitch {
  key: "realtime" | "behavior" | "tamper" | "cloud" | "samples" | "pua" | "network" | "cfa";
  state: "on" | "off" | "audit" | "unknown";
}
/** Unix ms; 0 when it never ran. */
export interface DefenderScanTimes { startMs: number; endMs: number; ageDays: number | null }
export interface DefenderThreat {
  id: string; name: string;
  severity: "low" | "moderate" | "high" | "severe" | "unknown";
  category: "virus" | "trojan" | "backdoor" | "ransomware" | "worm" | "spyware" | "exploit" | "tool" | "pua" | "other";
  resources: string[];
  /** Detected and not dealt with yet. */
  active: boolean;
  executed: boolean;
  status: "detected" | "cleaned" | "quarantined" | "removed" | "allowed" | "blocked" | "failed" | "abandoned" | "unknown";
  actionSuccess: boolean; detectedMs: number; changedMs: number; process: string; detections: number;
}
export interface DefenderExclusion {
  kind: "path" | "process" | "extension"; value: string;
  flags: ("drive" | "writable" | "executable" | "anyFolder")[];
}
/** The last scan Vigil started in this session (also the payload of `defender-scan` events). */
export interface DefenderScan {
  id: number; kind: "quick" | "full"; startedMs: number; running: boolean; finishedMs: number;
  /** MpCmdRun's exit code: 0 nothing needs attention, 2 something does. */
  code: number | null; cancelled: boolean;
}
export interface DefenderScanEvent extends DefenderScan { elapsedSecs: number; found: number | null }
export interface Protection {
  available: boolean; problem: string; serviceEnabled: boolean; antivirusEnabled: boolean;
  mode: "normal" | "passive" | "edr" | "off" | "";
  switches: DefenderSwitch[];
  signatureVersion: string; signatureUpdatedMs: number; signatureAgeDays: number | null; signatureOutOfDate: boolean;
  engineVersion: string; platformVersion: string;
  quickScan: DefenderScanTimes; fullScan: DefenderScanTimes; fullScanRequired: boolean;
  /** A scan started (by anyone) and has not ended yet. */
  runningScan: { kind: "quick" | "full"; startMs: number } | null;
  tamperSource: string;
  otherAntivirus: { name: string; enabled: boolean; upToDate: boolean }[];
  defenderRegistered: boolean | null;
  threats: DefenderThreat[]; exclusions: DefenderExclusion[];
  /** Defender hides the exclusions from standard users. */
  exclusionsHidden: boolean;
  scan: DefenderScan | null;
}

// ---------------------------------------------------------------- security posture (read-only)

/** What Vigil can do to raise a setting (Rust checks it against a fresh read). */
export type PostureOp =
  | "uac-default" | "rdp-nla" | "rdp-off" | "smb1-off" | "ps2-off" | "autorun-off" | "driver-blocklist-on" | "lsa-on"
  | "remote-registry-off";
export type PostureCheckId =
  | "secure_boot" | "tpm" | "memory_integrity" | "credential_guard" | "lsa" | "driver_blocklist" | "bitlocker" | "uac" | "rdp"
  | "remote_registry" | "smb1" | "firewall" | "smartscreen" | "powershell2" | "autorun" | "defender" | "defender_updates"
  | "windows_update";
export interface PostureCheck {
  id: PostureCheckId;
  group: "device" | "data" | "signin" | "network" | "apps" | "protection";
  /** on = as recommended; na = does not apply to this computer. */
  state: "on" | "partial" | "off" | "unknown" | "na";
  /** How much it counts in the score (1-3). */
  weight: number;
  /** What exactly was found ("legacy_bios", "pending_restart"...); "" for the plain case. */
  detail: string;
  facts: Record<string, string>;
  /** It could not be read without administrator rights. */
  needsAdmin: boolean;
  fixes: PostureOp[];
  /** A Windows Security or Settings link, "tool:<name>", "page:<key>" or "". */
  open: string;
}
export interface PostureVolume {
  letter: string; kind: "os" | "fixed" | "removable"; protection: "on" | "off" | "unknown";
  encryption: "decrypted" | "encrypted" | "encrypting" | "decrypting" | "paused" | "unknown";
}
export interface Posture {
  checks: PostureCheck[];
  score: { on: number; partial: number; off: number; counted: number; percent: number };
  volumes: PostureVolume[];
  elevated: boolean; edition: string; build: number;
}

/** One logical processor (a Windows CPU Set). `index` is what affinity requests use. */
export interface LogicalProcessor {
  index: number; id: number; group: number; number: number;
  /** Physical core: processors that share it are SMT siblings. */
  core: number;
  /** Higher is faster: on hybrid CPUs the performance cores have the highest class. */
  efficiencyClass: number;
  numaNode: number;
}

export interface Affinity { processors: LogicalProcessor[]; allowed: number[] }

/** What the UI may ask Rust to do. Rust builds the real action from this and confirms it natively. */
export type ActionRequest =
  | { kind: "finding"; itemId: string; index: number }
  | {
      kind: "process"; op: string; pid: number; createdMs: number; priority?: string;
      /** End task on a group: every process of the group (Rust checks each one again). */
      pids?: { pid: number; createdMs: number }[];
      /** Processor affinity: logical-processor indexes. */
      cores?: number[];
    }
  | { kind: "run"; path: string; args: string; admin: boolean }
  | { kind: "role"; op: "startup.disable" | "task.disable" | "service.manual"; itemId: string; role: number }
  | { kind: "journal"; op: "undo" | "undo_batch" | "restore" | "delete"; id: string }
  | { kind: "tuning"; op: string; params: Record<string, unknown> }
  | { kind: "cleanup"; keys: string[] }
  | { kind: "recycle"; paths: string[] }
  | { kind: "shell"; op: string; path?: string; url?: string; name?: string }
  | { kind: "service"; op: ServiceOp; name: string; startType?: string }
  | { kind: "startup"; op: "enable" | "disable" | "delete"; id: string }
  | { kind: "task"; op: "enable" | "disable" | "run" | "delete"; path: string }
  | { kind: "program"; op: "uninstall" | "remove_entry" | "folder"; id: string }
  /** Browser extensions page: the browser's extensions page (of an extension, by key, or of a browser by name) or an extension's folder. */
  | { kind: "extension"; op: "page" | "folder"; key?: string; browser?: string }
  /** Browser extensions page: remove a browser policy, read again by Rust. */
  | { kind: "browser-policy"; op: "remove"; id: string }
  /** Accounts page: Rust reads the accounts again and applies the action engine's guards. */
  | { kind: "account"; op: "disable" | "remove_member" | "logoff"; sid?: string; group?: AccountGroupKey; session?: number }
  | { kind: "firewall-rule"; op: "enable" | "disable" | "delete"; key: string }
  /** Security posture page: raise one setting (only what a fresh read offers). */
  | { kind: "posture"; op: PostureOp }
  | {
      kind: "defender";
      op: "quick-scan" | "full-scan" | "cancel-scan" | "offline-scan" | "update" | "turn-on" | "remove-exclusion" | "remove-threats";
      /** turn-on: realtime, pua, cloud or samples. */
      setting?: string;
      /** remove-exclusion: the list (path, process, extension) and the value, checked against a fresh read. */
      list?: string; value?: string;
    };

export interface ActionOutcome { cancelled: boolean; records: JournalRecord[]; message: string; error?: boolean }

// ---------------------------------------------------------------- browser extensions

export type ExtensionSource = "store" | "outside_store" | "external" | "policy" | "unpacked" | "component" | "unknown";
export type ExtensionFlag =
  | "all_sites" | "history" | "tabs" | "cookies" | "web_request" | "native" | "debugger" | "proxy" | "management"
  | "policy" | "outside_store" | "external" | "unpacked" | "mv2" | "not_signed" | "store_flagged" | "delisted";
export type ExtensionDisableReason =
  | "user" | "permissions" | "not_verified" | "flagged" | "corrupted" | "sideload" | "external" | "policy"
  | "unsupported_manifest" | "incompatible" | "other";

/** One extension of one browser profile. */
export interface BrowserExtension {
  /** browser|account|profile folder|id: names it in requests. */
  key: string;
  browser: string;
  /** The profile's name as the browser shows it. */
  profile: string;
  profileDir: string;
  /** Empty for this account; another account's name otherwise. */
  account: string;
  id: string;
  name: string;
  version: string;
  description: string;
  enabled: boolean;
  disableReasons: ExtensionDisableReason[];
  /** Unix ms; 0 when unknown. */
  installedMs: number;
  source: ExtensionSource;
  updateUrl: string;
  manifestVersion: number;
  permissions: string[];
  hosts: string[];
  flags: ExtensionFlag[];
  path: string;
  pathExists: boolean;
  /** Path of a PNG icon in its folder (loaded through extensionIcons). */
  icon: string;
  /** Part of the browser itself. */
  component: boolean;
}

export type BrowserPolicyKind =
  | "force_install" | "extension_settings" | "install_sources" | "allow" | "block" | "search" | "homepage" | "startup"
  | "new_tab" | "proxy" | "devtools" | "safe_browsing" | "other";

/** One browser policy value (registry) or entry of Firefox's policies.json. */
export interface BrowserPolicy {
  id: string;
  key: string;
  value: string;
  browser: string;
  scope: "machine" | "user" | "file";
  name: string;
  data: string;
  kind: BrowserPolicyKind;
  /** What adware and malware set. */
  flagged: boolean;
  extensionIds: string[];
  store: boolean;
  /** Vigil can remove it (and put it back from History). */
  removable: boolean;
}

export interface BrowserInfo { name: string; profiles: number; extensions: number }

export interface BrowserExtensions {
  extensions: BrowserExtension[];
  policies: BrowserPolicy[];
  browsers: BrowserInfo[];
  /** Other accounts' profiles were read too (elevated). */
  otherAccounts: boolean;
}

// ---------------------------------------------------------------- maintenance

export interface Volume { mount: string; label: string; fs: string; total: number; used: number; free: number; removable: boolean; network: boolean }

export interface CleanupTarget {
  key: string; label: string; description: string; group: string; roots: string[]; kind: string;
  size: number; files: number; admin: boolean; selected: boolean; note: string; minAgeHours: number;
}

export interface SpaceNode { name: string; path: string; size: number; files: number; isDir: boolean; children: SpaceNode[]; other: number }

export interface SpaceScan {
  root: SpaceNode; largestFiles: { size: number; path: string; modifiedMs: number }[]; files: number; folders: number;
  errors: number; seconds: number; cancelled: boolean; mergedBelow: number;
}

export interface Insight { level: "ok" | "info" | "warn" | "bad"; area: string; text: string; fix: string }

export interface PowerPlan { guid: string; name: string; active: boolean }

export interface TuningState {
  powerPlans: PowerPlan[]; hibernation: { enabled: boolean; fileSize: number };
  gameMode: boolean | null; hags: boolean | null; memoryIntegrity: boolean | null; visualEffects: number | null;
  gpuPreferences: { exe: string; preference: number }[];
}

export type Hardware = Record<string, any>;   // shape of hardware.ps1 (camelCase); see vigil-maint

export type Language = "auto" | "en" | "es" | "fr" | "pt" | "zh";
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";

export interface AiSettings { provider: string; model: string; endpoint: string; effort: Effort; redact: boolean }

export interface Settings {
  theme: "system" | "light" | "dark"; language: Language; ai: AiSettings;
  days: number; virustotal: boolean; restorePoint: boolean; autoRefresh: boolean;
  /** Which secrets are stored (values never come back): "openai-compatible", "anthropic-compatible", "virustotal". */
  secrets: Record<string, boolean>;
}

/** settings_set: a string stores the secret, "" deletes it, a missing key or null keeps it. */
export type SecretChanges = Record<string, string | null>;

/** A way to reach an AI model for the review. */
export interface AiProvider {
  /** "auto" | "openai-compatible" | "anthropic-compatible" | "claude-code" | "codex-cli" | "gemini-cli" | "off" */
  id: string;
  /** Display name, e.g. "OpenAI-compatible API", "Claude Code". */
  name: string;
  /** "api": one of the two API standards (a cloud service, or a server on this computer such as Ollama). */
  kind: "api" | "local-agent" | "auto" | "off";
  /** Secret it can use ("openai-compatible", "anthropic-compatible"), or null. */
  secret: string | null;
  needsEndpoint: boolean;
  defaultEndpoint: string | null;
  defaultModel: string;
  suggestedModels: string[];
  supportsEffort: boolean;
  /** CLI installed / server reachable / key present. */
  available: boolean;
  /** Short reason or hint, already in the user's language. */
  note: string;
}

export interface AiStatus { provider: string; destination: string | null; local: boolean; problem: string | null }

export interface ScanProgress { phase: "collect" | "ai" | "done" | "failed"; text: string }

/** Returned when the inventory is analysed locally and the AI review is next. */
export interface ReviewOffer {
  pending: number; destination: string | null; problem: string | null; redact: boolean; preview: unknown[];
  /** The model runs on this computer: nothing leaves it. */
  local: boolean;
}

// ---------------------------------------------------------------- background watch

/** Settings > Background watch (saved by Rust in its own watch file). */
export interface WatchSettings {
  watching: boolean;
  /** Closing the window keeps Vigil in the tray; off: closing quits. */
  closeToTray: boolean;
  notifyStartup: boolean;
  notifyServices: boolean;
  notifyTasks: boolean;
  notifySecurity: boolean;
  notifyPorts: boolean;
  /** Registry hooks, drivers and the hosts file. */
  notifyHooks: boolean;
  /** Events read from the Windows logs. */
  notifyEvents: boolean;
  trayNoticeShown: boolean;
}

/** "watch": about the background watch itself (its saved state was damaged and reset). */
export type AlertKind =
  | "startup" | "service" | "task" | "security" | "port" | "hook" | "driver" | "hosts" | "event" | "watch";

/** One change the background watch noticed. Title and detail are plain text from Rust. */
export interface WatchAlert {
  id: number;
  /** ms since 1970 */
  time: number;
  kind: AlertKind;
  title: string;
  detail: string;
  severity: "info" | "warning" | "critical";
  /** The page that shows it: "startup", "services", "tasks", "network", "protection", "posture",
   *  "firewall", "accounts" or "alerts". */
  target: string;
  read: boolean;
}

export interface WatchStatus {
  /** This window's copy of Vigil runs the checks (false: another Vigil window does). */
  owner: boolean;
  watching: boolean;
  lastCheck: number | null;
  unread: number;
  notifyPausedUntil: number | null;
  /** Scheduled tasks are watched only when Vigil runs as administrator. */
  tasksWatched: boolean;
  /** Windows logs the last check could not read (the Security log without administrator rights). */
  logsHidden: string[];
  settings: WatchSettings;
  /** Vigil starts in the tray at sign-in. */
  autostart: boolean;
  /** The newest alerts (at most five). */
  recent: WatchAlert[];
  error: string | null;
}

// ---------------------------------------------------------------- reliability (event logs, read-only)

export type ReliabilityCategory =
  | "bluescreen" | "shutdown" | "app_crash" | "app_hang" | "service" | "hardware" | "disk" | "update" | "install";

/** One event from the Windows event logs, interpreted. Every text in it comes from the logs (untrusted). */
export interface ReliabilityEvent {
  /** Unique within a read: "System:12345". */
  id: string;
  category: ReliabilityCategory;
  /** What happened within the category: "bugcheck", "kernel_power", "power_loss", "power_button", "unexpected",
   *  "crash", "hang", "crashed", "start_failed", "start_timeout", "stopped_with_error", "fatal", "corrected",
   *  "bad_block", "controller_error", "paging_error", "retried", "corruption", "needs_repair", "install_failed",
   *  "installed", "removed", "remove_failed". */
  kind: string;
  severity: "critical" | "error" | "warning" | "info";
  /** ms since 1970 */
  timeMs: number;
  /** Local ISO time. */
  time: string;
  log: string;
  provider: string;
  eventId: number;
  recordId: number;
  /** The program, service, update, product, device or volume ("" when none). */
  subject: string;
  version: string;
  module: string;
  moduleVersion: string;
  code: string;
  codeName: string;
  parameters: string;
  /** The program's path, or the memory dump of a blue screen. */
  path: string;
  /** The memory dump still exists (blue screens only). */
  pathExists: boolean | null;
  publisher: string;
  /** How many times a service has terminated so far. */
  count: number;
  /** As Windows formats it, in the system's language. */
  message: string;
}

/** Crashes or hangs of one program. */
export interface ReliabilityAppGroup {
  key: string;
  name: string;
  path: string;
  count: number;
  firstMs: number;
  lastMs: number;
  versions: string[];
  topModule: string;
  topModuleCount: number;
  /** Event ids, newest first. */
  events: string[];
}

export interface ReliabilityBoot { timeMs: number; time: string; bootMs: number; mainPathMs: number; postBootMs: number }

/** A plain-language pointer; title and text are written by Rust in the user's language. */
export interface ReliabilityHint {
  code: string;
  severity: "warn" | "info";
  subject: string;
  count: number;
  detail: string;
  /** The events behind it, newest first. */
  events: string[];
  title: string;
  text: string;
}

export interface Reliability {
  days: number;
  sinceMs: number;
  readMs: number;
  /** Newest first. */
  events: ReliabilityEvent[];
  counts: Record<ReliabilityCategory, number>;
  crashingApps: ReliabilityAppGroup[];
  hangingApps: ReliabilityAppGroup[];
  boots: ReliabilityBoot[];
  hints: ReliabilityHint[];
  /** Logs that could not be read (the boot performance log needs administrator rights). */
  unreadLogs: string[];
  truncated: boolean;
}

// ---------------------------------------------------------------- accounts and sign-ins (read-only)

export type AccountGroupKey = "administrators" | "remote_desktop_users";

export interface LocalAccount {
  sid: string; rid: number; name: string; fullName: string; comment: string;
  enabled: boolean; locked: boolean;
  /** False when the account may have an empty password (PASSWD_NOTREQD). */
  passwordRequired: boolean;
  /** False when the password never expires. */
  passwordExpires: boolean;
  passwordSet: string; lastLogon: string; lastLogonMs: number; logons: number; badPasswords: number;
  admin: boolean; remoteDesktop: boolean;
  /** "administrator" (RID 500), "guest" (501), "default" (503), "wdag" (504) or "". */
  builtin: string;
  onlineProvider: string; onlineName: string;
  /** The account running Vigil. */
  current: boolean;
}

export interface GroupMember {
  sid: string;
  /** "DOMAIN\name", "" when the SID no longer resolves. */
  name: string;
  kind: "user" | "group" | "alias" | "well_known" | "deleted" | "unknown" | "other";
  local: boolean; enabled: boolean | null; current: boolean;
}

export interface LocalGroup { sid: string; name: string; members: GroupMember[]; error: string }

export interface UserSession {
  id: number; station: string;
  state: "active" | "connected" | "disconnected" | "idle" | "other";
  user: string; protocol: "console" | "rdp" | "other" | "";
  clientAddress: string; clientName: string; logonTime: string; disconnectTime: string; current: boolean;
}

export type SigninKind =
  | "success" | "failure" | "lockout" | "created" | "deleted" | "member_added" | "member_removed" | "log_cleared"
  | "remote_auth" | "remote_logon" | "remote_reconnect" | "session_logon";

export interface SigninEvent {
  id: string; time: string; timeMs: number; kind: SigninKind; eventId: number; log: string;
  account: string; sid: string; logonType: number;
  logon: "interactive" | "network" | "unlock" | "remote" | "cached" | "batch" | "service" | "other" | "";
  address: string; public: boolean; workstation: string; process: string;
  reason: string; status: string; group: string; groupSid: string; member: string; memberSid: string; by: string;
}

export interface SigninSource {
  address: string; public: boolean; count: number; accounts: string[]; accountCount: number; first: string; last: string;
}

export interface RemoteSignin {
  time: string; timeMs: number; account: string; address: string; public: boolean;
  how: "remote_desktop" | "network"; events: string[];
}

export interface Signins {
  days: number; readMs: number; events: SigninEvent[];
  daily: { date: string; success: number; failure: number }[];
  success: number; failure: number; sources: SigninSource[];
  failedAccounts: { account: string; count: number; sources: number; last: string }[];
  remote: RemoteSignin[];
  /** The Security log could be read (it needs administrator rights). */
  securityReadable: boolean; unreadLogs: string[]; truncated: boolean;
}

export type AccountWarningCode =
  | "guessing_address" | "guessing_names" | "internet_signin" | "log_cleared" | "admin_added" | "account_created"
  | "lockouts" | "no_password_required" | "guest_enabled" | "builtin_admin_enabled" | "unknown_admin";

export interface AccountWarning {
  code: AccountWarningCode; severity: "bad" | "warn" | "info"; subject: string; detail: string; count: number; events: string[];
}

/** A change Vigil made that is still in place; History can undo it (journal record id). */
export interface VigilAccountChange { recordId: string; time: string; sid: string; name: string; groupSid: string; groupName: string }

export interface AccountsView {
  machineSid: string; currentSids: string[]; accounts: LocalAccount[];
  administrators: LocalGroup; remoteDesktopUsers: LocalGroup; sessions: UserSession[];
  domainJoined: boolean; lusrmgr: boolean; errors: string[];
  signins: Signins | null; signinsError: string; warnings: AccountWarning[];
  disabledByVigil: VigilAccountChange[]; removedByVigil: VigilAccountChange[];
}

// ---------------------------------------------------------------- AI investigation

/** One read-only tool call the AI agent made (shown afterwards, saved with the investigation). */
export interface InvestigationCall {
  step: number; name: string; input: unknown; ok: boolean; bytes: number; ms: number; note: string;
}
export interface InvestigationEvidence { text: string; page: string }
/** The validated result of "Investigate with AI" (the model never acts; actions stay Vigil's own). */
export interface InvestigationView {
  findingId: string; verdict: string; confidence: "low" | "medium" | "high"; conclusion: string;
  evidence: InvestigationEvidence[]; suggestedAction: string; openQuestions: string[]; guardNote: string;
  calls: InvestigationCall[]; steps: number; limit: string; destination: string; local: boolean;
  anonymized: boolean; saved: string;
}
export interface InvestigationProgress { phase: "tool" | "done"; text: string }
