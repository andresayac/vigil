// Names and colours shared by the security pages (same vocabulary as the report JSON).
import { t, type Key } from "./i18n/index.svelte";

export const VERDICT_ORDER = ["remove", "disable", "review", "no_signals", "safe", "trusted"] as const;
export type Verdict = (typeof VERDICT_ORDER)[number];

const VERDICT_KEY: Record<string, Key> = {
  remove: "verdict.remove", disable: "verdict.disable", review: "verdict.review", no_signals: "verdict.no_signals",
  safe: "verdict.safe", trusted: "verdict.trusted",
};
export const verdictLabel = (verdict: string): string => (VERDICT_KEY[verdict] ? t(VERDICT_KEY[verdict]) : verdict);

export const KINDS = ["executable", "command", "group", "program", "extension", "event", "config"] as const;
const KIND_KEY: Record<string, Key> = {
  executable: "kind.executable", command: "kind.command", group: "kind.group", program: "kind.program",
  extension: "kind.extension", event: "kind.event", config: "kind.config",
};
export const kindLabel = (kind: string): string => (KIND_KEY[kind] ? t(KIND_KEY[kind]) : kind);

const RISK_KEY: Record<string, Key> = { low: "risk.low", moderate: "risk.moderate", high: "risk.high", critical: "risk.critical" };
export const riskLabel = (level: string | null | undefined): string => (level && RISK_KEY[level] ? t(RISK_KEY[level]) : t("risk.local"));

/** CPU priority classes, lowest first. */
export const PRIORITIES = ["idle", "below_normal", "normal", "above_normal", "high"] as const;
const PRIORITY_KEY: Record<string, Key> = {
  idle: "priority.idle", below_normal: "priority.below_normal", normal: "priority.normal",
  above_normal: "priority.above_normal", high: "priority.high",
};
export const priorityLabel = (priority: string): string => (PRIORITY_KEY[priority] ? t(PRIORITY_KEY[priority]) : priority);

/** CSS colour of a verdict (only verdicts use these colours). */
export const verdictColor = (verdict: string): string =>
  ({ remove: "var(--remove)", disable: "var(--disable)", review: "var(--review)", no_signals: "var(--no-signals)",
     safe: "var(--safe)", trusted: "var(--trusted)" })[verdict] ?? "var(--ink3)";

export const riskColor = (level: string | null | undefined): string =>
  ({ low: "var(--safe)", moderate: "var(--disable)", high: "var(--remove)", critical: "var(--remove)" })[level ?? ""] ?? "var(--ink2)";

export const stateColor = (status: string): string =>
  ({ ok: "var(--ok)", warn: "var(--warn)", bad: "var(--bad)" })[status] ?? "var(--ink3)";
