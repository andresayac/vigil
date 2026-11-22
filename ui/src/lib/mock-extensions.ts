// Fictitious browser extensions and policies for previewing the Browser extensions page in a browser.
// Nothing here describes a real computer.
import type { BrowserExtension, BrowserExtensions, BrowserPolicy } from "./types";

const DAY = 86_400_000;
const LOCAL = "C:\\Users\\jdoe\\AppData\\Local";
const ROAMING = "C:\\Users\\jdoe\\AppData\\Roaming";

function ext(name: string, extra: Partial<BrowserExtension>): BrowserExtension {
  const base: BrowserExtension = {
    key: "", browser: "Chrome", profile: "Person 1", profileDir: "Default", account: "", id: "aaaabbbbccccddddeeeeffffgggghhhh",
    name, version: "1.0", description: "", enabled: true, disableReasons: [], installedMs: Date.now() - 200 * DAY,
    source: "store", updateUrl: "https://clients2.google.com/service/update2/crx", manifestVersion: 3, permissions: [],
    hosts: [], flags: [], path: "", pathExists: true, icon: "", component: false,
  };
  const out = { ...base, ...extra };
  out.key = `${out.browser}|${out.account}|${out.profileDir}|${out.id}`;
  if (!out.path) {
    out.path = out.browser === "Firefox"
      ? `${ROAMING}\\Mozilla\\Firefox\\Profiles\\abcd1234.default-release\\extensions\\${out.id}.xpi`
      : `${LOCAL}\\${out.browser === "Edge" ? "Microsoft\\Edge" : "Google\\Chrome"}\\User Data\\${out.profileDir}\\Extensions\\${out.id}\\${out.version}_0`;
  }
  if (!out.icon && out.browser !== "Firefox") out.icon = `${out.path}\\icon48.png`;
  return out;
}

export function extensionsList(): BrowserExtensions {
  const extensions: BrowserExtension[] = [
    ext("Contoso Notes", {
      version: "4.12.0", description: "Takes notes on any page.", installedMs: Date.now() - 320 * DAY,
      permissions: ["storage", "tabs", "contextMenus"], hosts: ["<all_urls>"], flags: ["all_sites", "tabs"],
    }),
    ext("Fabrikam Coupons", {
      id: "ppppoooonnnnmmmmllllkkkkjjjjiiii", version: "2.0.1", description: "Finds coupons while you shop.",
      enabled: false, disableReasons: ["flagged"], installedMs: Date.now() - 12 * DAY, source: "external",
      updateUrl: "https://updates.fabrikam.example/crx", manifestVersion: 2,
      permissions: ["cookies", "nativeMessaging", "webRequest", "webRequestBlocking"], hosts: ["*://*/*"],
      flags: ["store_flagged", "external", "outside_store", "all_sites", "cookies", "web_request", "native", "mv2"],
    }),
    ext("Northwind Agent", {
      browser: "Edge", profile: "Profile 1", id: "nnnnmmmmllllkkkkjjjjiiiihhhhgggg", version: "7.3.2",
      description: "Connects the browser to Northwind's desktop agent.", source: "policy",
      updateUrl: "https://updates.northwind.example/edge", permissions: ["nativeMessaging", "tabs", "history"],
      hosts: ["https://*.northwind.example/*"], flags: ["policy", "outside_store", "history", "tabs", "native"],
    }),
    ext("Woodgrove Reader", {
      browser: "Edge", profile: "Profile 1", id: "ccccddddeeeeffffgggghhhhiiiijjjj", version: "1.8",
      description: "Reads pages aloud.", updateUrl: "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
      permissions: ["storage", "tts"],
    }),
    ext("Dev Helper", {
      profile: "Work", profileDir: "Profile 1", id: "abcdefghijklmnopabcdefghijklmnop", version: "0.1",
      description: "Local build.", source: "unpacked", updateUrl: "", installedMs: Date.now() - 2 * DAY,
      path: "C:\\Users\\jdoe\\source\\dev-helper", permissions: ["debugger", "storage"], flags: ["unpacked", "debugger"],
    }),
    ext("Tailspin Tabs", {
      profile: "Work", profileDir: "Profile 1", id: "hhhhggggffffeeeeddddccccbbbbaaaa", version: "3.4", manifestVersion: 2,
      description: "Groups your tabs.", enabled: false, disableReasons: ["unsupported_manifest"],
      permissions: ["tabs", "storage"], flags: ["tabs", "mv2"],
    }),
    ext("Woodgrove Translate", {
      browser: "Firefox", profile: "default-release", profileDir: "abcd1234.default-release", id: "translate@woodgrove.example",
      version: "5.1", description: "Translates pages.", updateUrl: "https://addons.mozilla.org/firefox/downloads/file/1/translate.xpi",
      permissions: ["storage", "contextMenus"], hosts: ["<all_urls>"], flags: ["all_sites"],
    }),
    ext("Proseware Proxy", {
      browser: "Firefox", profile: "default-release", profileDir: "abcd1234.default-release", id: "proxy@proseware.example",
      version: "1.0", description: "", enabled: false, disableReasons: ["not_verified"], source: "external", updateUrl: "",
      installedMs: Date.now() - 5 * DAY, permissions: ["proxy", "management"],
      flags: ["external", "proxy", "management", "not_signed"],
    }),
    ext("Microsoft Edge PDF Viewer", {
      browser: "Edge", profile: "Profile 1", id: "mmmmnnnnoooopppphhhhggggffffeeee", version: "1", source: "component",
      component: true, updateUrl: "",
    }),
  ];
  const policies: BrowserPolicy[] = [
    policy("Chrome", "machine", "ExtensionInstallForcelist", "1", "ExtensionInstallForcelist",
      "ppppoooonnnnmmmmllllkkkkjjjjiiii;https://updates.fabrikam.example/crx", "force_install", true, true,
      ["ppppoooonnnnmmmmllllkkkkjjjjiiii"]),
    policy("Chrome", "machine", "", "HomepageLocation", "HomepageLocation", "https://start.fabrikam.example", "homepage", true, true),
    policy("Chrome", "machine", "", "DefaultSearchProviderSearchURL", "DefaultSearchProviderSearchURL",
      "https://search.fabrikam.example/?q={searchTerms}", "search", true, true),
    policy("Edge", "user", "", "SmartScreenEnabled", "SmartScreenEnabled", "0", "safe_browsing", true, true),
    policy("Edge", "machine", "ExtensionInstallForcelist", "1", "ExtensionInstallForcelist",
      "nnnnmmmmllllkkkkjjjjiiiihhhhgggg;https://updates.northwind.example/edge", "force_install", true, true,
      ["nnnnmmmmllllkkkkjjjjiiiihhhhgggg"]),
    policy("Edge", "machine", "", "PasswordManagerEnabled", "PasswordManagerEnabled", "0", "other", false, false),
    {
      id: "C:\\Program Files\\Mozilla Firefox\\distribution\\policies.json|Proxy",
      key: "C:\\Program Files\\Mozilla Firefox\\distribution\\policies.json", value: "Proxy", browser: "Firefox",
      scope: "file", name: "Proxy", data: '{"Mode":"manual","HTTPProxy":"203.0.113.5:8080"}', kind: "proxy",
      flagged: true, extensionIds: [], store: false, removable: false,
    },
  ];
  return {
    extensions,
    policies,
    browsers: [
      { name: "Chrome", profiles: 2, extensions: 4 },
      { name: "Edge", profiles: 1, extensions: 2 },
      { name: "Firefox", profiles: 1, extensions: 2 },
    ],
    otherAccounts: false,
  };
}

function policy(
  browser: string, scope: "machine" | "user", rel: string, value: string, name: string, data: string,
  kind: BrowserPolicy["kind"], flagged: boolean, removable: boolean, extensionIds: string[] = [],
): BrowserPolicy {
  const vendor = browser === "Edge" ? "Microsoft\\Edge" : browser === "Brave" ? "BraveSoftware\\Brave" : "Google\\Chrome";
  const key = `${scope === "machine" ? "HKLM" : "HKCU"}\\SOFTWARE\\Policies\\${vendor}${rel ? `\\${rel}` : ""}`;
  return { id: `${key}|${value}`, key, value, browser, scope, name, data, kind, flagged, extensionIds, store: false, removable };
}

/** Lettered tiles standing in for extension icons. */
export function extensionIcons(keys: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  const list = extensionsList().extensions;
  for (const key of keys) {
    const found = list.find((e) => e.key === key);
    if (!found?.icon) continue;
    let hash = 11;
    for (const c of found.name) hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect x="2" y="2" width="28" height="28" rx="6" fill="hsl(${hash % 360} 50% 45%)"/>` +
      `<text x="16" y="22.5" font-family="Segoe UI, sans-serif" font-size="17" font-weight="700" text-anchor="middle" fill="#fff">${found.name.charAt(0)}</text></svg>`;
    out[key] = `data:image/svg+xml,${encodeURIComponent(svg)}`;
  }
  return out;
}
