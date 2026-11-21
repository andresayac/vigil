// The only module that talks to the Rust backend. In a plain browser (UI preview) it falls
// back to fictitious data from mock.ts.
import * as mock from "./mock";
import type {
  ActionOutcome, ActionRequest, ActionSpec, AiProvider, AiStatus, Analysis, AppInfo, CleanupTarget, Connection, Hardware,
  Insight, JournalRecord, LivePayload, ProcessDetails, QuarantineEntry, ReviewOffer, ScanProgress, SecretChanges, Settings,
  SpaceScan, TuningState, Volume,
} from "./types";

export const inApp = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(command, args);
}

export async function appInfo(): Promise<AppInfo> {
  return inApp ? call<AppInfo>("app_info") : mock.appInfo();
}

/** Tells the backend whether a live page is open (it samples only while one is). */
export async function setLive(active: boolean): Promise<void> {
  if (inApp) await call("set_live", { active });
}

export async function onLive(handler: (payload: LivePayload) => void): Promise<() => void> {
  if (inApp) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<LivePayload>("live", (event) => handler(event.payload));
  }
  handler(mock.payload());
  const timer = setInterval(() => handler(mock.payload()), 1000);
  return () => clearInterval(timer);
}

export async function connections(): Promise<Connection[]> {
  return inApp ? call<Connection[]>("connections") : mock.connections();
}

/** Asks Windows for administrator rights (UAC); the app restarts elevated if granted. */
export async function restartElevated(): Promise<boolean> {
  return inApp ? call<boolean>("restart_elevated") : false;
}

export async function showWindow(): Promise<void> {
  if (!inApp) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().show();
}

/** The title bar and the Mica material follow this theme ("system" = follow Windows). */
export async function setWindowTheme(theme: "system" | "light" | "dark"): Promise<void> {
  if (!inApp) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().setTheme(theme === "system" ? null : theme);
}

/** True on Windows 11 inside the app, where the window draws Mica behind the page (see tauri.conf.json).
 *  Windows 10 has no Mica: the page keeps its solid background there. */
export async function hasMica(): Promise<boolean> {
  if (!inApp) return false;
  try {
    const data = (navigator as Navigator & {
      userAgentData?: { getHighEntropyValues(hints: string[]): Promise<{ platform?: string; platformVersion?: string }> };
    }).userAgentData;
    const values = await data?.getHighEntropyValues(["platformVersion"]);
    // Chromium reports Windows 11 as platform version 13 or later (Windows 10 is 10 or lower).
    return values?.platform === "Windows" && Number((values.platformVersion ?? "0").split(".")[0]) >= 13;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- scans and reports

export async function onEvent<T>(name: string, handler: (payload: T) => void): Promise<() => void> {
  if (!inApp) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(name, (event) => handler(event.payload));
}

export const onScanProgress = (handler: (p: ScanProgress) => void) => onEvent<ScanProgress>("scan", handler);

export async function currentReport(): Promise<Analysis | null> {
  return inApp ? call<Analysis | null>("report_current") : mock.analysis();
}
/** Asks for a report file in a native dialog and opens it. */
export async function openReport(): Promise<Analysis | null> {
  return inApp ? call<Analysis | null>("report_open") : null;
}
/** Asks where to save in a native dialog; returns the path written. */
export async function exportHtml(): Promise<string | null> {
  return inApp ? call<string | null>("report_export_html") : null;
}
/** Collects the inventory and runs the local rules; the AI review is offered next. */
export async function scanCollect(days: number, virustotal: boolean): Promise<ReviewOffer> {
  return inApp ? call<ReviewOffer>("scan_collect", { days, virustotal }) : mock.reviewOffer();
}
/** Finishes the scan: with the AI review (review = true) or without it. Saves the report.
 *  selected: the AI review was chosen in the scan dialog (the report says why it did not run). */
export async function scanFinish(review: boolean, selected = true): Promise<Analysis> {
  return inApp ? call<Analysis>("scan_finish", { review, selected }) : mock.analysis();
}

// ---------------------------------------------------------------- findings and actions
export async function planActions(itemId: string): Promise<ActionSpec[]> {
  return inApp ? call<ActionSpec[]>("plan_actions", { itemId }) : mock.plan(itemId);
}
/** Rust rebuilds the action from the request, confirms it in a native dialog and runs it. */
export async function runAction(request: ActionRequest): Promise<ActionOutcome> {
  return inApp ? call<ActionOutcome>("run_action", { request }) : { cancelled: true, records: [], message: "" };
}
export async function ignored(): Promise<string[]> {
  return inApp ? call<string[]>("ignored_list") : [];
}
export async function setIgnored(itemId: string, value: boolean): Promise<string[]> {
  return inApp ? call<string[]>("ignored_set", { itemId, value }) : [];
}

// ---------------------------------------------------------------- history and quarantine
// Undo, restore and delete go through runAction ({ kind: "journal" }), like every change.
export async function journal(): Promise<JournalRecord[]> {
  return inApp ? call<JournalRecord[]>("journal") : mock.journal();
}
/** Modules (DLLs) loaded by a process and the services it hosts. */
export async function processDetails(pid: number): Promise<ProcessDetails> {
  return inApp ? call<ProcessDetails>("process_details", { pid }) : mock.processDetails(pid);
}
export async function quarantine(): Promise<QuarantineEntry[]> {
  return inApp ? call<QuarantineEntry[]>("quarantine_list") : [];
}

// ---------------------------------------------------------------- maintenance
export async function volumes(): Promise<Volume[]> {
  return inApp ? call<Volume[]>("volumes") : mock.volumes();
}
export async function cleanupMeasure(): Promise<CleanupTarget[]> {
  return inApp ? call<CleanupTarget[]>("cleanup_measure") : mock.cleanup();
}
export async function spaceScan(root: string): Promise<SpaceScan> {
  return inApp ? call<SpaceScan>("space_scan", { root }) : mock.space(root);
}
export async function spaceCancel(): Promise<void> {
  if (inApp) await call("space_cancel");
}
export async function chooseFolder(): Promise<string | null> {
  return inApp ? call<string | null>("choose_folder") : null;
}
export async function chooseExe(): Promise<string | null> {
  return inApp ? call<string | null>("choose_exe") : null;
}
export async function hardware(force = false): Promise<Hardware> {
  return inApp ? call<Hardware>("hardware", { force }) : mock.hardware();
}
export async function insights(): Promise<Insight[]> {
  return inApp ? call<Insight[]>("insights") : mock.insights();
}
export async function tuningState(): Promise<TuningState> {
  return inApp ? call<TuningState>("tuning_state") : mock.tuning();
}

// ---------------------------------------------------------------- settings
export async function getSettings(): Promise<Settings> {
  return inApp ? call<Settings>("settings_get") : mock.settings();
}
/** secrets: a string stores it, "" deletes it, a missing key or null keeps it. Values never come back. */
export async function saveSettings(settings: Settings, secrets: SecretChanges | null = null): Promise<Settings> {
  if (inApp) return call<Settings>("settings_set", { settings, secrets });
  const plain: Settings = JSON.parse(JSON.stringify(settings));
  for (const [id, value] of Object.entries(secrets ?? {})) if (value !== null) plain.secrets[id] = value !== "";
  return mock.saveSettings(plain);
}
/** Every way to reach an AI model, with whether it is usable on this computer right now. */
export async function aiProviders(): Promise<AiProvider[]> {
  return inApp ? call<AiProvider[]>("ai_providers") : mock.aiProviders();
}
/** Models an API endpoint offers (a local Ollama server lists only the models installed on this computer). */
export async function aiModels(provider: string, endpoint: string): Promise<string[]> {
  return inApp ? call<string[]>("ai_models", { provider, endpoint }) : mock.aiModels(provider, endpoint);
}
/** The provider the next scan will use (after "auto" is resolved). */
export async function aiStatus(): Promise<AiStatus> {
  return inApp ? call<AiStatus>("ai_status") : mock.aiStatus();
}
