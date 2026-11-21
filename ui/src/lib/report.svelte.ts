// The current scan report, the ignored findings and the scan workflow, shared by every page.
import * as api from "./api";
import { t, type Key } from "./i18n/index.svelte";
import type { ActionOutcome, ActionRequest, Analysis, Item, ReviewOffer } from "./types";

export const report = $state({
  analysis: null as Analysis | null,
  ignored: [] as string[],
  loaded: false,
  scanning: false,
  /** What the scan is doing (a catalog key, so it follows the language). */
  title: "" as Key | "",
  log: [] as string[],
  offer: null as ReviewOffer | null,
  error: "",
  /** The last action's outcome, shown in the results dialog. */
  outcome: null as ActionOutcome | null,
  busy: false,
});

export async function loadReport(): Promise<void> {
  try {
    report.analysis = await api.currentReport();
    report.ignored = await api.ignored();
  } catch (error) {
    report.error = String(error);
  } finally {
    report.loaded = true;
  }
}

export const isIgnored = (id: string) => report.ignored.includes(id);
export const itemById = (id: string): Item | undefined => report.analysis?.items.find((i) => i.id === id);

export async function toggleIgnored(id: string): Promise<void> {
  report.ignored = await api.setIgnored(id, !isIgnored(id));
}

let unlisten: (() => void) | null = null;

/** Step 1: inventory + local rules. Returns the AI review offer (or finishes when no review is wanted). */
export async function startScan(days: number, virustotal: boolean, useAi: boolean): Promise<void> {
  if (report.scanning) return;
  report.scanning = true;
  report.error = "";
  report.log = [];
  report.title = "scan.titleScanning";
  unlisten ??= await api.onScanProgress((p) => {
    report.log = [...report.log.slice(-400), p.text];
  });
  try {
    const offer = await api.scanCollect(days, virustotal);
    if (useAi && offer.destination && offer.pending > 0) {
      report.offer = offer;        // the consent dialog takes it from here
      return;
    }
    if (useAi && offer.problem) report.log = [...report.log, t("scan.aiUnavailable", { problem: offer.problem })];
    await finishScan(false, useAi);
  } catch (error) {
    report.error = String(error);
    report.scanning = false;
  }
}

/** Step 2, after the consent dialog: with or without the AI review. */
export async function finishScan(review: boolean, selected = true): Promise<void> {
  report.offer = null;
  report.title = review ? "scan.titleReviewing" : "scan.titleSaving";
  try {
    report.analysis = await api.scanFinish(review, selected);
    report.ignored = await api.ignored();
  } catch (error) {
    report.error = String(error);
  } finally {
    report.scanning = false;
  }
}

/** Runs an action through Rust (which confirms it natively) and refreshes what it may have changed. */
export async function act(request: ActionRequest): Promise<ActionOutcome | null> {
  if (report.busy) return null;
  report.busy = true;
  try {
    const outcome = await api.runAction(request);
    if (!outcome.cancelled) {
      report.outcome = outcome;
      if (request.kind === "finding" || request.kind === "role") report.analysis = await api.currentReport();
    }
    return outcome;
  } catch (error) {
    report.outcome = { cancelled: false, records: [], message: String(error), error: true };
    return null;
  } finally {
    report.busy = false;
  }
}
