// Fictitious security posture for previewing the Security posture page in a browser. Nothing here
// describes a real computer: a mix of settings that are as recommended and some that are not.
import type { Posture, PostureCheck } from "./types";

function check(id: PostureCheck["id"], group: PostureCheck["group"], weight: number, state: PostureCheck["state"],
               more: Partial<PostureCheck> = {}): PostureCheck {
  return { id, group, weight, state, detail: "", facts: {}, needsAdmin: false, fixes: [], open: "", ...more };
}

export function postureState(): Posture {
  const checks: PostureCheck[] = [
    check("secure_boot", "device", 2, "on", { open: "windowsdefender://devicesecurity" }),
    check("tpm", "device", 2, "on", { facts: { version: "2.0" }, open: "windowsdefender://devicesecurity" }),
    check("memory_integrity", "device", 3, "off", { open: "windowsdefender://coreisolation" }),
    check("credential_guard", "device", 1, "na", { detail: "edition" }),
    check("lsa", "device", 2, "off", { fixes: ["lsa-on"], open: "windowsdefender://coreisolation" }),
    check("driver_blocklist", "device", 2, "on", { detail: "default", open: "windowsdefender://coreisolation" }),
    check("bitlocker", "data", 3, "partial", { detail: "data_drives", facts: { drives: "D:" }, open: "tool:bitlocker" }),
    check("uac", "signin", 3, "partial", { detail: "no_dimming", fixes: ["uac-default"] }),
    check("rdp", "signin", 2, "off", { detail: "open_no_nla", fixes: ["rdp-nla", "rdp-off"], open: "ms-settings:remotedesktop" }),
    check("remote_registry", "signin", 1, "on", { detail: "disabled" }),
    check("smb1", "network", 2, "off", { detail: "enabled", fixes: ["smb1-off"] }),
    check("firewall", "network", 3, "off", { detail: "profiles_off", facts: { profiles: "public" }, open: "page:firewall" }),
    check("smartscreen", "apps", 2, "on", { open: "windowsdefender://appbrowser" }),
    check("powershell2", "apps", 1, "off", { detail: "enabled", fixes: ["ps2-off"] }),
    check("autorun", "apps", 1, "partial", { detail: "default", fixes: ["autorun-off"] }),
    check("defender", "protection", 3, "on", { open: "page:protection" }),
    check("defender_updates", "protection", 2, "on", { facts: { days: "0" }, open: "page:protection" }),
    check("windows_update", "protection", 2, "partial", { facts: { days: "41" }, open: "ms-settings:windowsupdate" }),
  ];
  return {
    checks,
    // As Rust computes it: 37 of 72 weighted points (partly on counts half).
    score: { on: 7, partial: 4, off: 6, counted: 17, percent: 51 },
    volumes: [
      { letter: "C:", kind: "os", protection: "on", encryption: "encrypted" },
      { letter: "D:", kind: "fixed", protection: "off", encryption: "decrypted" },
    ],
    elevated: true, edition: "Professional", build: 26100,
  };
}
