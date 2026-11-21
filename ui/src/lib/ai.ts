// Helpers for the AI provider settings shared by the Settings, Scan and Consent dialogs.
import { t } from "./i18n/index.svelte";
import type { AiProvider } from "./types";

/** An address on this computer: what is sent to it does not leave the PC. */
export function isLocalAddress(endpoint: string): boolean {
  return /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\])(:\d+)?(\/|$)/i.test(endpoint.trim());
}

/** True when the review runs entirely on this computer (an API standard served on localhost). */
export function staysLocal(provider: AiProvider | undefined, endpoint: string): boolean {
  if (!provider || provider.kind !== "api") return false;
  return isLocalAddress(endpoint || provider.defaultEndpoint || "");
}

/** The name shown for a provider: "Automatic" and "Off" are interface words, the rest are product names. */
export function providerName(provider: AiProvider | undefined, id = ""): string {
  const kind = provider?.kind ?? (id === "auto" ? "auto" : id === "off" ? "off" : "");
  if (kind === "auto") return t("ai.automatic");
  if (kind === "off") return t("ai.off");
  return provider?.name ?? id;
}
