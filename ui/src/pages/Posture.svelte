<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { num } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { Posture, PostureCheck, PostureOp, PostureVolume } from "../lib/types";

  let { elevated, onpage }: { elevated: boolean; onpage: (page: string) => void } = $props();

  let posture = $state<Posture | null>(null);
  let loading = $state(false);
  let error = $state("");

  async function load(): Promise<void> {
    loading = true;
    try {
      posture = await api.postureState();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });

  const GROUPS: { key: PostureCheck["group"]; title: Key }[] = [
    { key: "device", title: "posture.group.device" },
    { key: "data", title: "posture.group.data" },
    { key: "signin", title: "posture.group.signin" },
    { key: "network", title: "posture.group.network" },
    { key: "apps", title: "posture.group.apps" },
    { key: "protection", title: "posture.group.protection" },
  ];
  const NAME: Record<PostureCheck["id"], Key> = {
    secure_boot: "posture.name.secure_boot", tpm: "posture.name.tpm", memory_integrity: "posture.name.memory_integrity",
    credential_guard: "posture.name.credential_guard", lsa: "posture.name.lsa", driver_blocklist: "posture.name.driver_blocklist",
    bitlocker: "posture.name.bitlocker", uac: "posture.name.uac", rdp: "posture.name.rdp", remote_registry: "posture.name.remote_registry",
    smb1: "posture.name.smb1", firewall: "posture.name.firewall", smartscreen: "posture.name.smartscreen",
    powershell2: "posture.name.powershell2", autorun: "posture.name.autorun", defender: "posture.name.defender",
    defender_updates: "posture.name.defender_updates", windows_update: "posture.name.windows_update",
  };
  const ABOUT: Record<PostureCheck["id"], Key> = {
    secure_boot: "posture.about.secure_boot", tpm: "posture.about.tpm", memory_integrity: "posture.about.memory_integrity",
    credential_guard: "posture.about.credential_guard", lsa: "posture.about.lsa", driver_blocklist: "posture.about.driver_blocklist",
    bitlocker: "posture.about.bitlocker", uac: "posture.about.uac", rdp: "posture.about.rdp", remote_registry: "posture.about.remote_registry",
    smb1: "posture.about.smb1", firewall: "posture.about.firewall", smartscreen: "posture.about.smartscreen",
    powershell2: "posture.about.powershell2", autorun: "posture.about.autorun", defender: "posture.about.defender",
    defender_updates: "posture.about.defender_updates", windows_update: "posture.about.windows_update",
  };
  const FIX: Record<PostureOp, Key> = {
    "uac-default": "posture.fix.uacDefault", "rdp-nla": "posture.fix.rdpNla", "rdp-off": "posture.fix.turnOff",
    "smb1-off": "posture.fix.turnOff", "ps2-off": "posture.fix.turnOff", "autorun-off": "posture.fix.autorunOff",
    "driver-blocklist-on": "posture.fix.turnOn", "lsa-on": "posture.fix.turnOn", "remote-registry-off": "posture.fix.turnOff",
  };

  /** What the setting is now, in words (the state colours it). */
  const VALUE: Record<string, Key> = {
    "secure_boot.legacy_bios": "posture.value.legacyBios",
    "memory_integrity.pending_restart": "posture.value.afterRestart",
    "credential_guard.pending_restart": "posture.value.afterRestart",
    "credential_guard.edition": "posture.value.notInEdition",
    "driver_blocklist.default": "posture.value.onDefault",
    "bitlocker.data_drives": "posture.value.systemDriveOnly",
    "bitlocker.encrypting": "posture.value.encrypting",
    "bitlocker.suspended": "posture.value.suspended",
    "bitlocker.not_available": "posture.value.notAvailable",
    "bitlocker.needs_admin": "posture.value.needsAdmin",
    "uac.": "posture.value.uacDefault",
    "uac.always": "posture.value.uacAlways",
    "uac.no_dimming": "posture.value.uacNoDimming",
    "uac.never_notify": "posture.value.uacNever",
    "rdp.closed": "common.off",
    "rdp.open_nla": "posture.value.rdpNla",
    "rdp.open_no_nla": "posture.value.rdpNoNla",
    "rdp.edition": "posture.value.notInEdition",
    "remote_registry.disabled": "posture.value.serviceDisabled",
    "remote_registry.manual": "posture.value.serviceManual",
    "remote_registry.running": "posture.value.serviceRunning",
    "remote_registry.automatic": "posture.value.serviceAutomatic",
    "remote_registry.missing": "posture.value.notInstalled",
    "smb1.disabled": "common.off",
    "smb1.driver_off": "common.off",
    "smb1.removed": "posture.value.removed",
    "smb1.enabled": "common.on",
    "smb1.client": "posture.value.smb1Client",
    "firewall.": "posture.value.allProfiles",
    "powershell2.enabled": "posture.value.installed",
    "powershell2.disabled": "common.off",
    "powershell2.removed": "posture.value.removed",
    "autorun.": "posture.value.autorunOff",
    "autorun.default": "posture.value.windowsDefault",
    "autorun.some_drives": "posture.value.autorunSome",
    "autorun.all_drives": "posture.value.autorunOn",
    "defender.": "posture.value.defenderOn",
    "defender.realtime_off": "posture.value.realtimeOff",
    "defender.unavailable": "posture.value.notAvailable",
    "defender_updates.other": "posture.value.otherAntivirus",
    "defender_updates.unavailable": "posture.value.notApplicable",
    "windows_update.no_record": "posture.value.noRecord",
  };
  const PROFILE: Record<string, Key> = {
    domain: "posture.profile.domain", private: "posture.profile.private", public: "posture.profile.public",
  };

  function value(c: PostureCheck): string {
    const facts = c.facts;
    if (c.state === "unknown" && c.detail !== "needs_admin" && c.detail !== "no_record") return t("posture.value.unknown");
    if (c.id === "tpm") return c.state === "off" ? t("posture.value.notFound") : t("posture.value.tpm", { version: facts.version ?? "" });
    if (c.id === "firewall" && c.state === "off") {
      const names = (facts.profiles ?? "").split(",").filter(Boolean).map((p) => (PROFILE[p] ? t(PROFILE[p]) : p));
      return t("posture.value.offFor", { profiles: names.join(", ") });
    }
    if (c.id === "smartscreen") {
      const base = t(c.state === "off" ? "common.off" : "common.on");
      return c.detail === "policy" ? t("posture.value.withPolicy", { value: base }) : base;
    }
    if (c.id === "defender" && c.detail === "other") return facts.names ?? "";
    if (c.id === "defender_updates" && facts.days !== undefined) {
      const days = Number(facts.days);
      return days === 0 ? t("posture.value.updatedToday") : t("posture.value.daysOld", { count: days });
    }
    if (c.id === "windows_update" && facts.days !== undefined) {
      const days = Number(facts.days);
      return days === 0 ? t("posture.value.today") : t("posture.value.daysAgo", { count: days });
    }
    const key = VALUE[`${c.id}.${c.detail}`];
    if (key) return t(key);
    if (c.state === "na") return t("posture.value.notApplicable");
    if (c.id === "uac" && c.state === "off") return t("common.off");
    return t(c.state === "off" ? "common.off" : c.state === "partial" ? "posture.value.partly" : "common.on");
  }

  /** A sentence about what was found, when there is more to say than the value. */
  const NOTE: Record<string, Key> = {
    "secure_boot.legacy_bios": "posture.note.legacyBios",
    "secure_boot.uefi_off": "posture.note.secureBootOff",
    "tpm.old_version": "posture.note.tpmOld",
    "tpm.absent": "posture.note.tpmAbsent",
    "memory_integrity.pending_restart": "posture.note.afterRestart",
    "memory_integrity.": "posture.note.memoryIntegrityOff",
    "credential_guard.pending_restart": "posture.note.afterRestart",
    "lsa.old_windows": "posture.note.lsaOldWindows",
    "bitlocker.needs_admin": "posture.note.bitlockerAdmin",
    "bitlocker.data_drives": "posture.note.dataDrives",
    "bitlocker.suspended": "posture.note.suspended",
    "bitlocker.not_available": "posture.note.bitlockerMissing",
    "uac.never_notify": "posture.note.uacSilent",
    "uac.disabled": "posture.note.uacSilent",
    "uac.no_dimming": "posture.note.uacNoDimming",
    "rdp.open_no_nla": "posture.note.rdpNoNla",
    "smb1.client": "posture.note.smb1Client",
    "autorun.default": "posture.note.autorunDefault",
    "defender.other": "posture.note.otherAntivirus",
    "windows_update.no_record": "posture.note.noUpdateRecord",
  };
  function note(c: PostureCheck): string {
    if (c.state === "on" && c.id !== "defender") return "";
    const key = NOTE[`${c.id}.${c.detail}`];
    if (key) return t(key, { drives: c.facts.drives ?? "" });
    if (c.id === "windows_update" && (c.state === "off" || c.state === "partial")) return t("posture.note.updateOld");
    return "";
  }

  type Look = { icon: string; color: string | null };
  function look(c: PostureCheck): Look {
    switch (c.state) {
      case "on": return { icon: "", color: "var(--ok)" };
      case "partial": return { icon: "", color: "var(--warn)" };
      case "off": return c.weight >= 2 ? { icon: "", color: "var(--bad)" } : { icon: "", color: "var(--warn)" };
      case "unknown": return { icon: "", color: null };
      default: return { icon: "", color: null };
    }
  }

  const PAGE_TITLE: Record<string, Key> = { firewall: "page.firewall", protection: "page.protection" };
  function openLabel(target: string): string {
    const page = target.startsWith("page:") ? PAGE_TITLE[target.slice(5)] : undefined;
    return page ? t("posture.openPage", { page: t(page) }) : t("posture.openSettings");
  }
  function open(target: string): void {
    if (target.startsWith("page:")) onpage(target.slice(5));
    else if (target.startsWith("tool:")) void act({ kind: "shell", op: "tool", name: target.slice(5) });
    else void act({ kind: "shell", op: "url", url: target });
  }
  async function fix(op: PostureOp): Promise<void> {
    const outcome = await act({ kind: "posture", op });
    if (outcome && !outcome.cancelled) await load();
  }

  const DRIVE_STATE: Record<PostureVolume["encryption"], Key> = {
    encrypted: "posture.drive.encrypted", decrypted: "posture.drive.decrypted", encrypting: "posture.drive.encrypting",
    decrypting: "posture.drive.decrypting", paused: "posture.drive.paused", unknown: "posture.value.unknown",
  };
  function drive(v: PostureVolume): string {
    const state = v.protection === "on" ? t("posture.drive.protected") : t(DRIVE_STATE[v.encryption]);
    // "D:" plus the template's own colon would read "D::".
    const name = v.letter.replace(/:$/, "") || t("posture.drive.noLetter");
    const kind = v.kind === "os" ? t("posture.drive.system") : v.kind === "removable" ? t("posture.drive.removable") : "";
    return kind ? t("posture.drive.lineKind", { name, kind, state }) : t("posture.drive.line", { name, state });
  }

  const checks = $derived(posture?.checks ?? []);
  const score = $derived(posture?.score ?? null);
  const share = (part: number) => (score && score.counted ? `${(part / score.counted) * 100}%` : "0");
  const needsAdmin = $derived(!elevated && checks.some((c) => c.needsAdmin || c.fixes.length > 0));
</script>

<div class="page scroll">
  <div class="page-head">
    <h1>{t("page.posture")}</h1>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" onclick={() => open("windowsdefender://devicesecurity")}>
        <i class="icon">{""}</i>{t("posture.openSecurity")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="muted lead">{t("posture.lead")}</p>

  <section class="panel summary" aria-busy={loading}>
    {#if score}
      <div class="percent num" aria-hidden="true">{num(score.percent)}<span class="unit">%</span></div>
      <div class="summary-text">
        <h2>{t("posture.scoreTitle", { on: num(score.on), count: score.counted })}</h2>
        <div class="bar" role="img" aria-label={t("posture.scoreParts", { partial: num(score.partial), off: num(score.off) })}>
          <span style:width={share(score.on)} style:background="var(--ok)"></span>
          <span style:width={share(score.partial)} style:background="var(--warn)"></span>
          <span style:width={share(score.off)} style:background="var(--bad)"></span>
        </div>
        <p class="muted">{t("posture.scoreParts", { partial: num(score.partial), off: num(score.off) })}</p>
        <p class="faint">{t("posture.scoreFormula")}</p>
      </div>
    {:else}
      <p class="muted">{loading ? t("common.reading") : ""}</p>
    {/if}
    {#if error}<p class="error selectable">{error}</p>{/if}
  </section>
  {#if needsAdmin}<p class="faint admin-note">{t("posture.adminNote")}</p>{/if}

  {#each GROUPS as group (group.key)}
    {@const list = checks.filter((c) => c.group === group.key)}
    {#if list.length}
      <section class="panel card">
        <h2>{t(group.title)}</h2>
        <div class="rows">
          {#each list as c (c.id)}
            {@const mark = look(c)}
            {@const extra = note(c)}
            <div class="row">
              <i class="icon mark" style:color={mark.color} aria-hidden="true">{mark.icon}</i>
              <div class="text">
                <span class="name">{t(NAME[c.id])}</span>
                <span class="faint">{t(ABOUT[c.id])}</span>
                {#if extra}<span class="note">{extra}</span>{/if}
                {#if c.id === "bitlocker" && posture?.volumes.length}
                  <ul class="drives">
                    {#each posture.volumes as v, index (index)}<li class="faint">{drive(v)}</li>{/each}
                  </ul>
                {/if}
              </div>
              <span class="value" style:color={c.state === "unknown" || c.state === "na" ? null : mark.color}>{value(c)}</span>
              <div class="actions">
                {#each c.fixes as op, index (op)}
                  <button class:primary={index === 0} disabled={!elevated || report.busy}
                          title={elevated ? "" : t("posture.needsAdmin")} onclick={() => fix(op)}>{t(FIX[op])}</button>
                {/each}
                {#if c.open}<button onclick={() => open(c.open)}>{openLabel(c.open)}</button>{/if}
              </div>
            </div>
          {/each}
        </div>
      </section>
    {/if}
  {/each}
</div>

<style>
  .scroll { overflow-y: auto; }
  .lead { margin: 0; }
  .grow { flex: 1; }
  .error { color: var(--bad); margin: 0; }

  .summary { display: flex; align-items: center; gap: 24px; flex: none; }
  .percent { font-size: 44px; font-weight: 600; line-height: 1; flex: none; min-width: 96px; }
  .percent .unit { font-size: 22px; font-weight: 400; color: var(--ink2); margin-left: 2px; }
  .summary-text { display: flex; flex-direction: column; gap: 6px; min-width: 0; flex: 1; }
  .summary-text h2, .summary-text p { margin: 0; }
  .bar { display: flex; height: 6px; border-radius: 3px; overflow: hidden; background: var(--sunken); max-width: 520px; }
  .bar span { display: block; height: 100%; }
  .admin-note { margin: 0; }

  .card { display: flex; flex-direction: column; gap: 6px; flex: none; }
  .card h2 { margin: 0 0 4px; }
  .rows { display: flex; flex-direction: column; }
  .row {
    display: grid; grid-template-columns: 20px minmax(0, 1fr) 200px 230px;
    align-items: center; gap: 12px; padding: 10px 0;
  }
  .row + .row { border-top: 1px solid var(--rule); }
  .mark { font-size: 16px; text-align: center; align-self: start; padding-top: 2px; }
  .text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .name { font-size: 14px; }
  .note { font-size: 13px; color: var(--ink2); }
  .drives { margin: 2px 0 0; padding-left: 18px; font-size: 12px; }
  .value { font-size: 13px; overflow-wrap: anywhere; }
  .actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
  @media (max-width: 900px) {
    .row { grid-template-columns: 20px minmax(0, 1fr); }
    .value, .actions { grid-column: 2; justify-content: flex-start; }
  }
</style>
