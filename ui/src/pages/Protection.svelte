<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { num, when } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { ActionRequest, DefenderExclusion, DefenderScan, DefenderScanEvent, DefenderSwitch, DefenderThreat, Protection } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  let defender = $state<Protection | null>(null);
  let loading = $state(false);
  let error = $state("");
  let progress = $state<DefenderScanEvent | null>(null);
  let selected = $state<string | null>(null);
  let now = $state(Date.now());

  async function load(): Promise<void> {
    loading = true;
    try {
      defender = await api.protectionState();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
    const stop = api.subscribe(api.onDefenderScan((event) => {
      progress = event;
      if (!event.running && event.found !== null) void load();
    }));
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => {
      stop?.();
      clearInterval(timer);
    };
  });

  // ---------------------------------------------------------------- switches
  type Fix = { kind: "turn-on" } | { kind: "security"; url: string } | null;
  const SWITCHES: { key: DefenderSwitch["key"]; name: Key; about: Key; essential: boolean; fix: Fix }[] = [
    { key: "realtime", name: "protection.swRealtime", about: "protection.swRealtimeAbout", essential: true, fix: { kind: "turn-on" } },
    { key: "behavior", name: "protection.swBehavior", about: "protection.swBehaviorAbout", essential: true,
      fix: { kind: "security", url: "windowsdefender://threatsettings" } },
    { key: "tamper", name: "protection.swTamper", about: "protection.swTamperAbout", essential: true,
      fix: { kind: "security", url: "windowsdefender://threatsettings" } },
    { key: "cloud", name: "protection.swCloud", about: "protection.swCloudAbout", essential: true, fix: { kind: "turn-on" } },
    { key: "samples", name: "protection.swSamples", about: "protection.swSamplesAbout", essential: false, fix: { kind: "turn-on" } },
    { key: "pua", name: "protection.swPua", about: "protection.swPuaAbout", essential: false, fix: { kind: "turn-on" } },
    { key: "network", name: "protection.swNetwork", about: "protection.swNetworkAbout", essential: false, fix: null },
    { key: "cfa", name: "protection.swCfa", about: "protection.swCfaAbout", essential: false,
      fix: { kind: "security", url: "windowsdefender://threatsettings" } },
  ];
  const switchState = (key: DefenderSwitch["key"]) => defender?.switches.find((s) => s.key === key)?.state ?? "unknown";
  function stateText(value: DefenderSwitch["state"]): string {
    if (value === "on") return t("common.on");
    if (value === "off") return t("common.off");
    if (value === "audit") return t("protection.audit");
    return t("common.unknown");
  }
  function stateColor(value: DefenderSwitch["state"], essential: boolean): string | null {
    if (value === "on") return "var(--ok)";
    if (value === "unknown") return null;
    return essential ? "var(--warn)" : null;
  }
  const passive = $derived(defender?.mode === "passive");

  // ---------------------------------------------------------------- overall status
  const threats = $derived(defender?.threats ?? []);
  const active = $derived(threats.filter((x) => x.active));
  const exclusions = $derived(defender?.exclusions ?? []);
  const flagged = $derived(exclusions.filter((x) => x.flags.length));
  const otherOn = $derived((defender?.otherAntivirus ?? []).filter((a) => a.enabled));
  type Level = "ok" | "warn" | "bad";
  const status = $derived.by((): { level: Level; title: string; detail: string } => {
    const s = defender;
    if (!s) return { level: "warn", title: t("common.reading"), detail: "" };
    const names = otherOn.map((a) => a.name).join(", ");
    if (!s.available) {
      if (otherOn.length) return { level: "ok", title: t("protection.statusOther"), detail: t("protection.statusOtherDetail", { names }) };
      return { level: "bad", title: t("protection.statusUnavailable"), detail: t("protection.statusUnavailableDetail") };
    }
    if (active.length) return { level: "bad", title: t("protection.statusThreats", { count: active.length }), detail: t("protection.statusThreatsDetail") };
    if (s.mode === "passive" || (!s.antivirusEnabled && otherOn.length)) {
      return { level: otherOn.length ? "ok" : "warn", title: t("protection.statusOther"), detail: t("protection.statusOtherDetail", { names: names || "—" }) };
    }
    if (!s.serviceEnabled || !s.antivirusEnabled) return { level: "bad", title: t("protection.statusOff"), detail: t("protection.statusOffDetail") };
    if (switchState("realtime") === "off") return { level: "bad", title: t("protection.statusRealtimeOff"), detail: t("protection.statusRealtimeOffDetail") };
    if (s.signatureOutOfDate || (s.signatureAgeDays ?? 0) > 7) return { level: "warn", title: t("protection.statusOutdated"), detail: t("protection.statusOutdatedDetail") };
    if (s.fullScanRequired) return { level: "warn", title: t("protection.statusFullScan"), detail: t("protection.fullScanRequired") };
    if (["tamper", "cloud", "behavior"].some((k) => switchState(k as DefenderSwitch["key"]) === "off") || flagged.length) {
      return { level: "warn", title: t("protection.statusLook"), detail: t("protection.statusLookDetail") };
    }
    return { level: "ok", title: t("protection.statusOk"), detail: t("protection.statusOkDetail") };
  });
  const LEVEL_COLOR: Record<Level, string> = { ok: "var(--ok)", warn: "var(--warn)", bad: "var(--bad)" };

  // ---------------------------------------------------------------- scans
  /** The newest of what the page read and what the events said. */
  const scan = $derived.by((): (DefenderScan & { elapsedSecs: number; found: number | null }) | null => {
    const read = defender?.scan ?? null;
    if (progress && (!read || progress.id >= read.id)) return progress;
    if (!read) return null;
    const end = read.running ? now : read.finishedMs;
    return { ...read, elapsedSecs: Math.max(0, Math.round((end - read.startedMs) / 1000)), found: null };
  });
  const vigilRunning = $derived(!!scan?.running);
  const external = $derived(!vigilRunning ? defender?.runningScan ?? null : null);
  const canScan = $derived(!!defender?.available && !!defender?.serviceEnabled && !vigilRunning && !report.busy);

  function duration(seconds: number): string {
    const s = Math.max(0, Math.floor(seconds));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    if (h) return t("protection.durHours", { h: num(h), m: String(m).padStart(2, "0") });
    if (m) return t("protection.durMinutes", { m: num(m), s: String(sec).padStart(2, "0") });
    return t("protection.durSeconds", { s: num(sec) });
  }
  const at = (ms: number) => (ms > 0 ? when(new Date(ms).toISOString()) : t("protection.never"));
  const elapsed = $derived(scan?.running ? duration(scan.elapsedSecs || (now - scan.startedMs) / 1000) : "");
  const result = $derived.by((): { level: Level; text: string } | null => {
    if (!scan || scan.running) return null;
    const time = duration(scan.elapsedSecs);
    if (scan.cancelled) return { level: "warn", text: t("protection.resultCancelled", { time }) };
    if (scan.found) return { level: "bad", text: t("protection.resultFound", { count: scan.found, time }) };
    if (scan.code === 0) return { level: "ok", text: t("protection.resultClean", { time }) };
    if (scan.code === 2) return { level: "warn", text: t("protection.resultAttention", { time }) };
    return { level: "warn", text: t("protection.resultFailed", { code: String(scan.code ?? "?") }) };
  });

  async function run(request: ActionRequest): Promise<void> {
    const outcome = await act(request);
    if (outcome && !outcome.cancelled) await load();
  }
  const security = (url: string) => act({ kind: "shell", op: "url", url });

  // ---------------------------------------------------------------- threats
  const SEVERITY: Record<DefenderThreat["severity"], Key> = {
    low: "protection.sevLow", moderate: "protection.sevModerate", high: "protection.sevHigh", severe: "protection.sevSevere",
    unknown: "common.unknown",
  };
  const CATEGORY: Record<DefenderThreat["category"], Key> = {
    virus: "protection.catVirus", trojan: "protection.catTrojan", backdoor: "protection.catBackdoor",
    ransomware: "protection.catRansomware", worm: "protection.catWorm", spyware: "protection.catSpyware",
    exploit: "protection.catExploit", tool: "protection.catTool", pua: "protection.catPua", other: "protection.catOther",
  };
  const STATUS: Record<DefenderThreat["status"], Key> = {
    detected: "protection.stDetected", cleaned: "protection.stCleaned", quarantined: "protection.stQuarantined",
    removed: "protection.stRemoved", allowed: "protection.stAllowed", blocked: "protection.stBlocked",
    failed: "protection.stFailed", abandoned: "protection.stAbandoned", unknown: "protection.stResolved",
  };
  const statusText = (x: DefenderThreat) => t(x.active ? "protection.stActive" : STATUS[x.status]);
  const severityColor = (x: DefenderThreat) => (x.active ? "var(--bad)" : null);
  const current = $derived(threats.find((x) => x.id === selected) ?? null);

  // ---------------------------------------------------------------- exclusions
  const KIND: Record<DefenderExclusion["kind"], Key> = {
    path: "protection.kindPath", process: "protection.kindProcess", extension: "protection.kindExtension",
  };
  const FLAG: Record<DefenderExclusion["flags"][number], Key> = {
    drive: "protection.flagDrive", writable: "protection.flagWritable", executable: "protection.flagExecutable",
    anyFolder: "protection.flagAnyFolder",
  };
</script>

<div class="page scroll">
  <div class="page-head">
    <h1>{t("page.protection")}</h1>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" disabled={!defender?.available || !elevated || report.busy} onclick={() => run({ kind: "defender", op: "update" })}>
        <i class="icon">{""}</i>{t("protection.update")}</button>
      <button class="command" onclick={() => security("windowsdefender://threat")}>
        <i class="icon">{""}</i>{t("protection.openSecurity")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="muted lead">{t("protection.lead")}</p>

  <section class="panel status">
    <i class="icon big" style:color={defender ? LEVEL_COLOR[status.level] : null}>{status.level === "ok" ? "" : ""}</i>
    <div class="status-text">
      <h2>{status.title}</h2>
      {#if status.detail}<p class="muted">{status.detail}</p>{/if}
      {#if defender?.available}
        <p class="faint selectable">{t("protection.versions", {
          sig: defender.signatureVersion || "—", when: at(defender.signatureUpdatedMs), engine: defender.engineVersion || "—",
          platform: defender.platformVersion || "—" })}</p>
      {:else if defender?.problem}
        <p class="faint selectable">{defender.problem}</p>
      {/if}
      {#if error}<p class="error selectable">{error}</p>{/if}
    </div>
  </section>

  <div class="columns">
    <div class="stack">
    <section class="panel card">
      <h2>{t("protection.scans")}</h2>
      {#if scan?.running}
        <div class="running">
          <div class="running-head">
            <span>{t(scan.kind === "quick" ? "protection.quickRunning" : "protection.fullRunning")}</span>
            <span class="faint">{t("protection.elapsed", { time: elapsed })}</span>
            <span class="grow"></span>
            <button disabled={report.busy} onclick={() => run({ kind: "defender", op: "cancel-scan" })}>
              <i class="icon">{""}</i> {t("protection.stop")}</button>
          </div>
          <div class="bar"><div></div></div>
        </div>
      {:else if external}
        <div class="running">
          <div class="running-head">
            <span>{t(external.kind === "quick" ? "protection.quickRunning" : "protection.fullRunning")}</span>
            <span class="grow"></span>
            <button disabled={report.busy} onclick={() => run({ kind: "defender", op: "cancel-scan" })}>
              <i class="icon">{""}</i> {t("protection.stop")}</button>
          </div>
          <p class="faint">{t("protection.externalRunning", { time: at(external.startMs) })}</p>
        </div>
      {:else if result}
        <p style:color={LEVEL_COLOR[result.level]}>{result.text}</p>
      {/if}
      <div class="facts">
        <span class="faint">{t("protection.lastQuick")}</span><span>{at(defender?.quickScan.endMs ?? 0)}</span>
        <span class="faint">{t("protection.lastFull")}</span><span>{at(defender?.fullScan.endMs ?? 0)}</span>
      </div>
      {#if defender?.fullScanRequired}<p style:color="var(--warn)">{t("protection.fullScanRequired")}</p>{/if}
      <div class="buttons">
        <button class="primary" disabled={!canScan} onclick={() => run({ kind: "defender", op: "quick-scan" })}>
          <i class="icon">{""}</i> {t("protection.quickScan")}</button>
        <button disabled={!canScan} onclick={() => run({ kind: "defender", op: "full-scan" })}>{t("protection.fullScan")}</button>
        <button disabled={!canScan || !elevated} onclick={() => run({ kind: "defender", op: "offline-scan" })}>{t("protection.offlineScan")}</button>
      </div>
      <p class="faint">{t("protection.offlineNote")}</p>
      {#if defender?.otherAntivirus.length}
        <h3>{t("protection.otherAv")}</h3>
        {#each defender.otherAntivirus as av (av.name)}
          <div class="av">
            <span>{av.name}</span>
            <span style:color={av.enabled ? "var(--ok)" : null}>{t(av.enabled ? "common.on" : "common.off")}</span>
            {#if !av.upToDate}<span style:color="var(--warn)">{t("protection.avOutdated")}</span>{/if}
          </div>
        {/each}
      {/if}
    </section>

    <section class="panel card">
      <h2>{t("protection.exclusions")}</h2>
      <p class="faint">{t("protection.exclusionsNote")}</p>
      {#if defender?.exclusionsHidden}
        <p>{t("protection.exclusionsHidden")}</p>
      {:else if defender && !exclusions.length}
        <p class="muted">{t("protection.noExclusions")}</p>
      {:else}
        <div class="exclusions">
          {#each exclusions as x (`${x.kind}|${x.value}`)}
            <div class="exclusion">
              <span class="faint">{t(KIND[x.kind])}</span>
              <div class="exclusion-text">
                <span class="mono selectable">{x.value}</span>
                {#each x.flags as f (f)}
                  <span class="flag" style:color="var(--warn)"><i class="icon">{""}</i>{t(FLAG[f])}</span>
                {/each}
              </div>
              <button disabled={!elevated || report.busy}
                      onclick={() => run({ kind: "defender", op: "remove-exclusion", list: x.kind, value: x.value })}>{t("protection.remove")}</button>
            </div>
          {/each}
        </div>
      {/if}
    </section>
    </div>

    <section class="panel card">
      <h2>{t("protection.settings")}</h2>
      <div class="switches">
        {#each SWITCHES as s (s.key)}
          {@const value = switchState(s.key)}
          <div class="switch">
            <div class="switch-text">
              <span class="switch-name">{t(s.name)}</span>
              <span class="faint">{s.key === "realtime" && passive ? t("protection.passiveRealtime") : t(s.about)}</span>
            </div>
            <span class="switch-state" style:color={stateColor(value, s.essential)}>{stateText(value)}</span>
            {#if value === "off" || value === "audit"}
              {#if s.fix?.kind === "turn-on" && !(s.key === "realtime" && passive)}
                <button disabled={!elevated || report.busy || !defender?.available}
                        onclick={() => run({ kind: "defender", op: "turn-on", setting: s.key })}>{t("protection.turnOn")}</button>
              {:else if s.fix?.kind === "security"}
                {@const url = s.fix.url}
                <button onclick={() => security(url)}>{t("protection.openSecurity")}</button>
              {:else}
                <span></span>
              {/if}
            {:else}
              <span></span>
            {/if}
          </div>
        {/each}
      </div>
      {#if !elevated}<p class="faint">{t("protection.adminNote")}</p>{/if}
    </section>
  </div>

  <section class="panel card">
    <div class="section-head">
      <h2>{t("protection.threats")}</h2>
      <span class="grow"></span>
      <div class="commandbar">
        <button class="command" disabled={!active.length || !elevated || report.busy} onclick={() => run({ kind: "defender", op: "remove-threats" })}>
          <i class="icon">{""}</i>{t("protection.removeThreats")}</button>
        <button class="command" onclick={() => security("windowsdefender://history")}>
          <i class="icon">{""}</i>{t("protection.history")}</button>
      </div>
    </div>
    {#if !threats.length}
      <p class="faint">{loading && !defender ? t("common.reading") : t("protection.noThreats")}</p>
    {:else}
      <div class="table">
        <div class="row head">
          <span class="th">{t("protection.colThreat")}</span><span class="th">{t("protection.colCategory")}</span>
          <span class="th">{t("protection.colSeverity")}</span><span class="th">{t("protection.colStatus")}</span>
          <span class="th">{t("protection.colDetected")}</span>
        </div>
        {#each threats as x (x.id)}
          <button class="row" class:sel={selected === x.id} onclick={() => (selected = selected === x.id ? null : x.id)}>
            <span class="cell name" title={x.name}>
              {#if x.active}<i class="icon mark" style:color="var(--bad)">{""}</i>{:else}<span class="mark"></span>{/if}
              <span class="text">{x.name}</span>
            </span>
            <span class="cell">{t(CATEGORY[x.category])}</span>
            <span class="cell" style:color={severityColor(x)}>{t(SEVERITY[x.severity])}</span>
            <span class="cell" style:color={x.active ? "var(--bad)" : null}>{statusText(x)}</span>
            <span class="cell">{at(x.detectedMs)}</span>
          </button>
        {/each}
      </div>
      {#if current}
        <div class="detail" aria-live="polite">
          {#if current.active}<p style:color="var(--bad)">{t("protection.activeNote")}</p>{/if}
          {#if current.executed}<p style:color="var(--warn)">{t("protection.executed")}</p>{/if}
          <div class="facts">
            <span class="faint">{t("protection.resources")}</span>
            <span class="mono selectable">{#each current.resources as r (r)}<span class="resource">{r}</span>{:else}—{/each}</span>
            {#if current.process}
              <span class="faint">{t("protection.process")}</span><span class="mono selectable">{current.process}</span>
            {/if}
            <span class="faint">{t("protection.colDetected")}</span>
            <span>{at(current.detectedMs)} · {t("protection.detections", { count: current.detections })}</span>
          </div>
        </div>
      {/if}
    {/if}
  </section>
</div>

<style>
  .scroll { overflow-y: auto; }
  .lead { margin: 0; }
  .grow { flex: 1; }
  .status { display: flex; align-items: center; gap: 18px; flex: none; }
  .status .big { font-size: 44px; flex: none; }
  .status-text { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .status-text p { margin: 0; }
  .error { color: var(--bad); }

  .stack { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
  .columns { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr); gap: 14px; align-items: start; }
  @media (max-width: 1100px) { .columns { grid-template-columns: minmax(0, 1fr); } }
  .card { display: flex; flex-direction: column; gap: 10px; flex: none; }
  .card p { margin: 0; }
  .section-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

  .running { display: flex; flex-direction: column; gap: 8px; }
  .running-head { display: flex; align-items: center; gap: 10px; }
  .bar { height: 4px; background: var(--sunken); border-radius: 2px; overflow: hidden; position: relative; }
  .bar div { position: absolute; inset: 0 60% 0 0; background: var(--chart); animation: slide 1.4s ease-in-out infinite; }
  @keyframes slide { from { transform: translateX(-100%); } to { transform: translateX(250%); } }
  @media (prefers-reduced-motion: reduce) { .bar div { animation: none; inset: 0; opacity: 0.5; } }

  .facts { display: grid; grid-template-columns: 170px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .facts .mono { overflow-wrap: anywhere; display: flex; flex-direction: column; }
  .buttons { display: flex; flex-wrap: wrap; gap: 6px; }
  .av { display: flex; gap: 12px; font-size: 13px; }

  .switches { display: flex; flex-direction: column; }
  .switch { display: grid; grid-template-columns: minmax(0, 1fr) 90px 150px; align-items: center; gap: 12px; padding: 8px 0; }
  .switch + .switch { border-top: 1px solid var(--rule); }
  .switch-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .switch-name { font-size: 14px; }
  .switch-state { font-size: 13px; }
  .switch button { justify-self: end; }

  .table { border-top: 1px solid var(--rule); max-height: 320px; overflow: auto; }
  .row { display: grid; grid-template-columns: minmax(240px, 2.4fr) minmax(120px, 1fr) 90px minmax(120px, 1fr) 160px; min-width: 760px; font-size: 13px; }
  .head { position: sticky; top: 0; z-index: 1; background: var(--surface); border-bottom: 1px solid var(--rule); }
  .th { padding: 6px 8px; color: var(--ink2); font-size: 12px; white-space: nowrap; }
  button.row { position: relative; width: 100%; height: 28px; min-height: 0; padding: 0; border: 0; border-radius: 0; background: transparent; text-align: left; color: var(--ink); }
  button.row::after { content: ""; position: absolute; inset: 0; pointer-events: none; }
  button.row:hover:not(:disabled) { background: transparent; }
  button.row:hover::after { background: var(--hover); }
  button.row.sel::after { background: var(--table-select); }
  .cell { padding: 0 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; line-height: 28px; }
  .cell.name { display: flex; align-items: center; gap: 8px; }
  .mark { flex: none; width: 14px; font-size: 13px; text-align: center; }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .detail { display: flex; flex-direction: column; gap: 6px; padding-top: 4px; }

  .exclusions { display: flex; flex-direction: column; }
  .exclusion { display: grid; grid-template-columns: 110px minmax(0, 1fr) auto; align-items: center; gap: 12px; padding: 8px 0; }
  .exclusion + .exclusion { border-top: 1px solid var(--rule); }
  .exclusion-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .exclusion-text .mono { overflow-wrap: anywhere; }
  .flag { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
  .flag .icon { font-size: 12px; }
</style>
