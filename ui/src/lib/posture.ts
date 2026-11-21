// The security state readouts of the Overview: names and the colour rules of each setting.
import type { Readout } from "../components/Readouts.svelte";
import { t, type Key } from "./i18n/index.svelte";

const LABELS: Record<string, Key> = {
  system: "posture.system", computer: "posture.computer", is_administrator: "posture.is_administrator",
  realtime_protection: "posture.realtime_protection", tamper_protection: "posture.tamper_protection",
  signature_age_days: "posture.signature_age_days", last_quick_scan: "posture.last_quick_scan",
  last_full_scan: "posture.last_full_scan", firewall: "posture.firewall", uac: "posture.uac",
  remote_desktop: "posture.remote_desktop", last_update: "posture.last_update", registered_antivirus: "posture.registered_antivirus",
  defender_exclusions: "posture.defender_exclusions", hosts_file: "posture.hosts_file", local_accounts: "posture.local_accounts",
  administrators: "posture.administrators", smartscreen: "posture.smartscreen", proxy: "posture.proxy",
};

export function fmt(value: unknown): string {
  if (typeof value === "boolean") return value ? t("common.yes") : t("common.no");
  if (Array.isArray(value)) return value.map(fmt).join(", ") || t("common.none");
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k}: ${fmt(v)}`).join("; ") || t("common.none");
  }
  return value === null || value === undefined ? "" : String(value);
}

function status(key: string, value: unknown): Readout["status"] {
  const text = typeof value === "string" ? value.toLowerCase() : "";
  if (["realtime_protection", "tamper_protection", "is_administrator"].includes(key)) {
    return value === true ? "ok" : value === false ? "bad" : "";
  }
  if (key === "firewall" && value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).every(Boolean) ? "ok" : "bad";
  }
  if (key === "uac") return text === "enabled" ? "ok" : "bad";
  if (key === "remote_desktop") return text === "enabled" ? "warn" : "ok";
  if (key === "last_full_scan") return text === "never" || text === "" ? "warn" : "ok";
  if (key === "signature_age_days" && typeof value === "number") return value <= 7 ? "ok" : value <= 30 ? "warn" : "bad";
  return "";
}

export function readouts(posture: Record<string, unknown>): Readout[] {
  const rest = { ...posture };
  const defender = rest.defender as Record<string, unknown> | undefined;
  delete rest.defender;
  const rows: [string, unknown][] = [];
  for (const key of ["system", "computer"]) {
    if (rest[key]) {
      rows.push([key, rest[key]]);
      delete rest[key];
    }
  }
  if (defender && typeof defender === "object") {
    for (const key of ["realtime_protection", "tamper_protection", "signature_age_days", "last_quick_scan", "last_full_scan"]) {
      if (key in defender) rows.push([key, defender[key]]);
    }
  }
  rows.push(...Object.entries(rest));
  return rows.slice(0, 24).map(([key, value]) => ({
    status: status(key, value),
    name: LABELS[key] ? t(LABELS[key]) : key.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()),
    value: fmt(value),
    tip: fmt(value).slice(0, 600),
  }));
}
