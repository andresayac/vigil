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
  /** "run", "run_once" or "folder". */
  kind: string;
  /** "user" (this account) or "machine" (every user). */
  scope: string;
  enabled: boolean;
  /** When it was turned off, if Windows recorded it. */
  disabledAtMs: number | null;
  /** RunOnce entries have no on/off switch. */
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
  | { kind: "startup"; op: "enable" | "disable"; id: string }
  | { kind: "task"; op: "enable" | "disable" | "run" | "delete"; path: string }
  | { kind: "firewall-rule"; op: "enable" | "disable" | "delete"; key: string };

export interface ActionOutcome { cancelled: boolean; records: JournalRecord[]; message: string; error?: boolean }

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
  trayNoticeShown: boolean;
}

export type AlertKind = "startup" | "service" | "task" | "security" | "port";

/** One change the background watch noticed. Title and detail are plain text from Rust. */
export interface WatchAlert {
  id: number;
  /** ms since 1970 */
  time: number;
  kind: AlertKind;
  title: string;
  detail: string;
  severity: "info" | "warning" | "critical";
  /** The page that shows it: "startup", "services", "tasks", "network" or "alerts". */
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
  settings: WatchSettings;
  /** Vigil starts in the tray at sign-in. */
  autostart: boolean;
  /** The newest alerts (at most five). */
  recent: WatchAlert[];
  error: string | null;
}
