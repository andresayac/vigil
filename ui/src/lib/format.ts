// Numbers, sizes, rates and times in the active language (decimal separators, unit names, word order).
import { locale, t } from "./i18n/index.svelte";

const formats = new Map<string, Intl.NumberFormat>();
function numberFormat(digits: number, style: "decimal" | "percent" = "decimal"): Intl.NumberFormat {
  const key = `${locale()}|${digits}|${style}`;
  let format = formats.get(key);
  if (!format) {
    format = new Intl.NumberFormat(locale(), { style, minimumFractionDigits: digits, maximumFractionDigits: digits });
    formats.set(key, format);
  }
  return format;
}

/** A number with the language's grouping and decimal separators. */
export const num = (value: number, digits = 0): string => numberFormat(digits).format(Number(value) || 0);

export function size(bytes: number, digits = 1): string {
  let value = Number(bytes) || 0;
  const units = [t("unit.KB"), t("unit.MB"), t("unit.GB"), t("unit.TB")];
  if (Math.abs(value) < 1024) return t("unit.bytes", { n: num(Math.round(value)) });
  for (let i = 0; i < units.length; i++) {
    value /= 1024;
    if (Math.abs(value) < 1024 || i === units.length - 1) return `${num(value, digits)} ${units[i]}`;
  }
  return "";
}

export function rate(bytesPerSecond: number, bits = false): string {
  let value = (Number(bytesPerSecond) || 0) * (bits ? 8 : 1);
  const units = bits
    ? [t("unit.bps"), t("unit.Kbps"), t("unit.Mbps"), t("unit.Gbps")]
    : [t("unit.Bps"), t("unit.KBps"), t("unit.MBps"), t("unit.GBps")];
  const step = bits ? 1000 : 1024;
  for (let i = 0; i < units.length; i++) {
    if (value < step || i === units.length - 1) {
      return `${value >= 100 || i === 0 ? num(Math.round(value)) : num(value, 1)} ${units[i]}`;
    }
    value /= step;
  }
  return "";
}

export const pct = (value: number, digits = 0): string => numberFormat(digits, "percent").format((Number(value) || 0) / 100);

/** How long ago a process started: "12 min", "3.5 h", "2.1 d". */
export function age(createdMs: number): string {
  if (!createdMs) return "";
  const seconds = Math.max(0, (Date.now() - createdMs) / 1000);
  if (seconds < 3600) return t("time.minutesShort", { n: num(Math.floor(seconds / 60)) });
  if (seconds < 86400) return t("time.hoursShort", { n: num(seconds / 3600, 1) });
  return t("time.daysShort", { n: num(seconds / 86400, 1) });
}

export function uptime(seconds: number): string {
  const s = Math.floor(seconds || 0);
  const days = Math.floor(s / 86400), hours = Math.floor((s % 86400) / 3600), minutes = Math.floor((s % 3600) / 60);
  const hm = `${hours}:${String(minutes).padStart(2, "0")}`;
  return days ? t("time.uptimeDays", { days: String(days), hm }) : hm;
}

const relative = new Map<string, Intl.RelativeTimeFormat>();
/** "12 sec. ago", "hace 2 min": seconds before now, for chart cursors and markers. */
export function ago(seconds: number): string {
  const tag = locale();
  let format = relative.get(tag);
  if (!format) {
    format = new Intl.RelativeTimeFormat(tag, { style: "short", numeric: "always" });
    relative.set(tag, format);
  }
  return seconds < 60 ? format.format(-Math.round(seconds), "second") : format.format(-Math.round(seconds / 6) / 10, "minute");
}

/** A local ISO time as written by the backend ("2026-01-01T10:05:00") shown in the active language. */
export function when(iso: string | null | undefined, withSeconds = false): string {
  const text = String(iso ?? "");
  if (!text) return "";
  const date = new Date(text.length === 10 ? `${text}T00:00:00` : text);
  if (Number.isNaN(date.getTime())) return text.replace("T", " ");
  return new Intl.DateTimeFormat(locale(), {
    dateStyle: "medium", timeStyle: text.length === 10 ? undefined : withSeconds ? "medium" : "short",
  }).format(date);
}

/** A date only ("2025-06-01" -> "1 jun 2025"); "—" when missing. */
export function day(iso: unknown): string {
  const text = String(iso ?? "").slice(0, 10);
  if (!text) return "—";
  const date = new Date(`${text}T00:00:00`);
  return Number.isNaN(date.getTime()) ? text : new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(date);
}

/** 1, 2, 5 × 10^n just above `value`: the top of a throughput chart. */
export function niceCeiling(value: number): number {
  if (value <= 0) return 1;
  const exponent = Math.floor(Math.log10(value));
  for (const step of [1, 2, 5, 10]) {
    const top = step * 10 ** exponent;
    if (top >= value) return top;
  }
  return 10 ** (exponent + 1);
}
