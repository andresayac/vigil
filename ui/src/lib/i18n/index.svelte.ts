// Translations of the interface. English (en.ts) is the source: every other catalog must have exactly the same
// keys, which TypeScript checks. Texts produced by the Rust side (findings, action labels, confirmations,
// insights) arrive already translated; only the interface's own words live here.
//
// Add a string: put the key and the English text in en.ts, then the same key in es.ts, fr.ts, pt.ts and zh.ts.
// Use it with t("area.key", { name: value }). A plural is an object ({ one, other, ... }) chosen by `count`.

import { en, type Key, type Msg } from "./en";
import { es } from "./es";
import { fr } from "./fr";
import { pt } from "./pt";
import { zh } from "./zh";

export type Language = "auto" | "en" | "es" | "fr" | "pt" | "zh";
export type Code = Exclude<Language, "auto">;
export type { Key };

/** Languages offered in Settings, each named in its own language. */
export const LANGUAGES: { code: Code; name: string }[] = [
  { code: "en", name: "English" },
  { code: "es", name: "Español" },
  { code: "fr", name: "Français" },
  { code: "pt", name: "Português (Brasil)" },
  { code: "zh", name: "简体中文" },
];

const CATALOGS: Record<Code, Record<Key, Msg>> = { en, es, fr, pt, zh };
const LOCALE: Record<Code, string> = { en: "en-US", es: "es-ES", fr: "fr-FR", pt: "pt-BR", zh: "zh-CN" };

/** "auto" follows the browser (WebView2 reports the Windows display language). */
export function resolveLanguage(choice: string | null | undefined): Code {
  if (choice && choice !== "auto" && choice in CATALOGS) return choice as Code;
  const preferred = typeof navigator !== "undefined" ? [...(navigator.languages ?? []), navigator.language] : [];
  for (const tag of preferred) {
    const base = String(tag ?? "").toLowerCase().split("-")[0];
    if (base in CATALOGS) return base as Code;
  }
  return "en";
}

const current = $state({ code: resolveLanguage("auto") });

export function setLanguage(choice: string | null | undefined): void {
  current.code = resolveLanguage(choice);
  if (typeof document !== "undefined") document.documentElement.lang = LOCALE[current.code];
}

/** The active language code (reactive). */
export const language = (): Code => current.code;
/** The BCP 47 locale for Intl formatting (reactive). */
export const locale = (): string => LOCALE[current.code];

const pluralRules = new Map<string, Intl.PluralRules>();
function pluralOf(count: number): Intl.LDMLPluralRule {
  const tag = locale();
  let rules = pluralRules.get(tag);
  if (!rules) {
    rules = new Intl.PluralRules(tag);
    pluralRules.set(tag, rules);
  }
  return rules.select(count);
}

const numberFormats = new Map<string, Intl.NumberFormat>();
function formatNumber(value: number): string {
  const tag = locale();
  let format = numberFormats.get(tag);
  if (!format) {
    format = new Intl.NumberFormat(tag, { maximumFractionDigits: 1 });
    numberFormats.set(tag, format);
  }
  return format.format(value);
}

/** Numbers in `params` are formatted for the language (1,316 / 1.316 / 1 316); pass identifiers such as a PID
 *  as strings so they stay as they are. */
export function t(key: Key, params: Record<string, string | number> = {}): string {
  const message: Msg = CATALOGS[current.code][key] ?? en[key];
  let text: string;
  if (typeof message === "string") {
    text = message;
  } else {
    const count = Number(params.count ?? 0);
    text = message[pluralOf(count)] ?? message.other;
  }
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const value = params[name];
    if (value === undefined) return whole;
    return typeof value === "number" ? formatNumber(value) : value;
  });
}
