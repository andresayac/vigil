// Fictitious investigation result for the browser preview (no AI is called).
import type { InvestigationView } from "./types";

export function investigation(findingId: string): InvestigationView {
  return {
    findingId,
    verdict: "remove",
    confidence: "high",
    conclusion:
      "The updater in AppData\\Roaming has no signature, starts at sign-in from the Run key and from a scheduled task, " +
      "and keeps a connection open to 203.0.113.45 on port 443. No installed program owns it. It behaves like the " +
      "persistence part of a downloader rather than a real updater.",
    evidence: [
      { text: "Not signed; the file was created the same minute as the scheduled task.", page: "tasks" },
      { text: "Starts at sign-in from HKCU\\…\\Run as \"Contoso Updater\".", page: "startup" },
      { text: "Process 4388 has an established connection to 203.0.113.45:443.", page: "network" },
      { text: "No installed program lists this folder.", page: "" },
    ],
    suggestedAction: "Remove completely: end the process, turn off the Run entry and the task, quarantine the file.",
    openQuestions: ["Which program downloaded it? The browser history may tell."],
    guardNote: "",
    calls: [
      { step: 1, name: "get_finding", input: { id: findingId }, ok: true, bytes: 1840, ms: 2, note: "" },
      { step: 1, name: "inspect_process", input: { pid: 4388 }, ok: true, bytes: 1210, ms: 640, note: "" },
      { step: 2, name: "list_tasks", input: { query: "updater" }, ok: true, bytes: 860, ms: 310, note: "" },
      { step: 2, name: "check_file", input: { path: "C:\\Users\\jdoe\\AppData\\Roaming\\updater.exe" }, ok: true, bytes: 520, ms: 420, note: "" },
      { step: 3, name: "list_connections", input: { public_only: true }, ok: true, bytes: 690, ms: 25, note: "" },
    ],
    steps: 4,
    limit: "",
    destination: "The model server on this computer at http://localhost:11434/v1 (model qwen3:14b)",
    local: true,
    anonymized: false,
    saved: "",
  };
}
