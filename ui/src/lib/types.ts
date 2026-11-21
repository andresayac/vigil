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

/** What the UI may ask Rust to do. Rust builds the real action from this and confirms it natively. */
export type ActionRequest =
  | { kind: "finding"; itemId: string; index: number }
  | { kind: "process"; op: string; pid: number; createdMs: number; priority?: string }
  | { kind: "role"; op: "startup.disable" | "task.disable" | "service.manual"; itemId: string; role: number }
  | { kind: "journal"; op: "undo" | "undo_batch" | "restore" | "delete"; id: string }
  | { kind: "tuning"; op: string; params: Record<string, unknown> }
  | { kind: "cleanup"; keys: string[] }
  | { kind: "recycle"; paths: string[] }
  | { kind: "shell"; op: string; path?: string; url?: string; name?: string }
  | { kind: "service"; op: ServiceOp; name: string; startType?: string };

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
