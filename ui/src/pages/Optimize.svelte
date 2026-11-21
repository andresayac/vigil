<script lang="ts">
  import { onMount } from "svelte";
  import Readouts from "../components/Readouts.svelte";
  import StackedBar from "../components/StackedBar.svelte";
  import * as api from "../lib/api";
  import { pct, size } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { verdictColor, verdictLabel } from "../lib/labels";
  import { acquire, live, release } from "../lib/live.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { Hardware, Item, TuningState } from "../lib/types";

  let { elevated, onscan }: { elevated: boolean; onscan: () => void } = $props();

  const NOTES: Record<string, Key> = {
    "381b4222-f694-41f0-9685-ff5bb260df2e": "optimize.planBalanced",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "optimize.planHigh",
    "a1841308-3541-4fab-bc81-f71556f20b4a": "optimize.planSaver",
  };
  const PREF: [number, Key][] = [[0, "optimize.gpuAuto"], [1, "optimize.gpuSaving"], [2, "optimize.gpuHigh"]];
  const prefLabel = (value: number) => {
    const key = PREF.find(([v]) => v === value)?.[1];
    return key ? t(key) : String(value);
  };

  let tuning = $state<TuningState | null>(null);
  let hw = $state<Hardware | null>(null);
  let plan = $state("");
  let startupSel = $state<string | null>(null);
  let serviceSel = $state<string | null>(null);
  let gpuExe = $state<string | null>(null);

  async function reload(): Promise<void> {
    tuning = await api.tuningState();
    plan = tuning.powerPlans.find((p) => p.active)?.guid ?? "";
  }

  onMount(() => {
    void acquire();
    void reload();
    void api.hardware().then((h) => (hw = h));
    return () => void release();
  });

  const windir = "c:\\windows";
  interface RoleRow { key: string; item: Item; role: number; op: "startup.disable" | "task.disable" | "service.manual"; where: string; name: string }

  const startupRows: RoleRow[] = $derived.by(() => {
    const out: RoleRow[] = [];
    for (const item of report.analysis?.items ?? []) {
      if ((item.path ?? "").toLowerCase().startsWith(windir) || item.title.toLowerCase().includes("securityhealth")) continue;
      item.roles.forEach((role, index) => {
        if (role.kind === "startup" && role.active) out.push({ key: `${item.id}:${index}`, item, role: index, op: "startup.disable", where: role.label, name: item.title });
        else if (role.kind === "task" && role.active && role.persistent) out.push({ key: `${item.id}:${index}`, item, role: index, op: "task.disable", where: role.label, name: item.title });
      });
    }
    return out;
  });

  const serviceRows: RoleRow[] = $derived.by(() => {
    const out: RoleRow[] = [];
    for (const item of report.analysis?.items ?? []) {
      if ((item.path ?? "").toLowerCase().startsWith(windir)) continue;
      item.roles.forEach((role, index) => {
        const name = String(role.detail?.name ?? "");
        if (role.kind === "service" && role.active && role.persistent && name) {
          out.push({ key: `${item.id}:${index}`, item, role: index, op: "service.manual", where: role.label, name });
        }
      });
    }
    return out;
  });

  async function runRole(rows: RoleRow[], key: string | null): Promise<void> {
    const row = rows.find((r) => r.key === key);
    if (row) await act({ kind: "role", op: row.op, itemId: row.item.id, role: row.role });
  }

  async function tune(op: string, params: Record<string, unknown> = {}): Promise<void> {
    const outcome = await act({ kind: "tuning", op, params });
    if (outcome && !outcome.cancelled) await reload();
  }

  const active = $derived(tuning?.powerPlans.find((p) => p.active));
  const hasUltimate = $derived(tuning?.powerPlans.some((p) => p.name.toLowerCase().includes("ultimate")) ?? true);
  const m = $derived(live.snapshot?.memory ?? null);
  const commit = $derived(m && m.commitLimit ? (m.commit / m.commitLimit) * 100 : 0);
  const drives = $derived.by(() => {
    const out: { letter: string; media: string }[] = [];
    for (const disk of hw?.disks ?? []) {
      for (const letter of disk.letters ?? []) {
        if (["SSD", "HDD"].includes(String(disk.media).toUpperCase())) out.push({ letter: String(letter).replace(":", ""), media: String(disk.media) });
      }
    }
    return out.sort((a, b) => a.letter.localeCompare(b.letter));
  });

  const TOOLS: [Key, string][] = [["optimize.toolPerformance", "SystemPropertiesPerformance.exe"], ["optimize.toolResmon", "resmon.exe"],
                                   ["optimize.toolDefrag", "dfrgui.exe"], ["optimize.toolMsinfo", "msinfo32.exe"]];

  async function chooseGpuApp(): Promise<void> {
    gpuExe = await api.chooseExe();
  }
</script>

<div class="page scroll">
  <div class="page-head"><h1>{t("page.optimize")}</h1></div>
  <p class="muted lead">{t("optimize.lead")}</p>

  <div class="cards">
    <section class="panel card">
      <h2>{t("optimize.startup")}</h2>
      {#if !report.analysis}
        <p class="muted">{t("optimize.runScanToList")}</p>
        <div><button onclick={onscan}>{t("optimize.runScan")}</button></div>
      {:else}
        <p class="muted">{t("optimize.startupCount", { count: startupRows.length })}</p>
        <div class="table">
          {#each startupRows as row (row.key)}
            <button class="trow" class:sel={startupSel === row.key} onclick={() => (startupSel = row.key)} title={row.item.path ?? row.name}>
              <span class="ellipsis">{row.name}</span><span class="ellipsis faint" title={row.where}>{row.where}</span>
              <span style:color={["remove", "disable", "review"].includes(row.item.verdict) ? verdictColor(row.item.verdict) : "var(--ink3)"}>{verdictLabel(row.item.verdict)}</span>
            </button>
          {/each}
        </div>
        <div><button disabled={!startupSel || !elevated || report.busy} onclick={() => runRole(startupRows, startupSel)}>{t("optimize.turnOff")}</button></div>
      {/if}
    </section>

    <section class="panel card">
      <h2>{t("optimize.services")}</h2>
      {#if !report.analysis}
        <p class="muted">{t("optimize.runScanServices")}</p>
      {:else}
        <p class="muted">{t("optimize.servicesCount", { count: serviceRows.length })}</p>
        <div class="table">
          {#each serviceRows as row (row.key)}
            <button class="trow" class:sel={serviceSel === row.key} onclick={() => (serviceSel = row.key)} title={row.where}>
              <span class="ellipsis">{row.name}</span><span class="ellipsis faint">{row.item.title}</span><span class="faint">{verdictLabel(row.item.verdict)}</span>
            </button>
          {/each}
        </div>
        <div><button disabled={!serviceSel || !elevated || report.busy} onclick={() => runRole(serviceRows, serviceSel)}>{t("optimize.manual")}</button></div>
      {/if}
    </section>

    <section class="panel card">
      <h2>{t("optimize.power")}</h2>
      {#each tuning?.powerPlans ?? [] as p (p.guid)}
        <label class="radio"><input type="radio" name="plan" value={p.guid} bind:group={plan} /> {p.name}</label>
        {#if NOTES[p.guid.toLowerCase()] || p.name.toLowerCase().includes("ultimate")}
          <p class="faint indent">{NOTES[p.guid.toLowerCase()] ? t(NOTES[p.guid.toLowerCase()]) : t("optimize.planUltimate")}</p>
        {/if}
      {:else}
        <p class="muted">{t("optimize.noPlans")}</p>
        <div><button onclick={() => act({ kind: "shell", op: "url", url: "ms-settings:powersleep" })}>{t("optimize.openPower")}</button></div>
      {/each}
      <div class="buttons">
        <button disabled={!plan || plan === active?.guid || report.busy}
                onclick={() => tune("power.plan", { guid: plan, name: tuning?.powerPlans.find((p) => p.guid === plan)?.name, previous_name: active?.name })}>{t("optimize.usePlan")}</button>
        {#if !hasUltimate && !hw?.battery}<button disabled={!elevated || report.busy} onclick={() => tune("power.ultimate")}>{t("optimize.addUltimate")}</button>{/if}
      </div>
    </section>

    <section class="panel card">
      <h2>{t("res.memory")}</h2>
      {#if m}
        <div style:--chart="var(--chart-memory)"><StackedBar total={m.total} segments={[
          { name: t("perf.inUse"), value: Math.max(0, m.used - m.modified), color: "var(--chart)" },
          { name: t("perf.modified"), value: m.modified, color: "color-mix(in srgb, var(--chart) 60%, var(--sunken))" },
          { name: t("perf.standby"), value: m.standby, color: "color-mix(in srgb, var(--chart) 25%, var(--sunken))" },
          { name: t("perf.free"), value: m.free, color: "var(--sunken)" }]} /></div>
        <p class="muted">{t("optimize.memoryState", { available: size(m.available), total: size(m.total), commit: size(m.commit),
                                                       limit: size(m.commitLimit), pct: pct(commit) })}
          {commit >= 90 ? t("optimize.memoryTight") : commit < 70 ? t("optimize.memoryPlenty") : t("optimize.memoryModerate")}</p>
      {:else}
        <p class="muted">{t("optimize.readingMemory")}</p>
      {/if}
      <p class="faint">{t("optimize.standbyNote")}</p>
      <div class="buttons">
        <button disabled={!elevated || report.busy} onclick={() => tune("memory.purge_standby")}>{t("optimize.purge")}</button>
        <button disabled={!elevated || report.busy} onclick={() => tune("memory.trim_all")}>{t("optimize.trimAll")}</button>
      </div>
    </section>

    <section class="panel card">
      <h2>{t("optimize.gaming")}</h2>
      <Readouts nameWidth={220} rows={[
        { status: tuning?.gameMode ? "ok" : "", name: t("optimize.gameMode"), value: tuning?.gameMode ? t("common.on") : t("common.off"), tip: t("optimize.gameModeTip") },
        { status: tuning?.hags ? "ok" : "", name: t("optimize.hags"), value: tuning?.hags ? t("common.on") : tuning?.hags === false ? t("common.off") : t("optimize.notSet") }]} />
      <div class="buttons">
        <button disabled={report.busy} onclick={() => tune("gaming.game_mode", { on: !tuning?.gameMode })}>{tuning?.gameMode ? t("optimize.gameModeOff") : t("optimize.gameModeOn")}</button>
        <button disabled={!elevated || report.busy} onclick={() => tune("gaming.hags", { on: !tuning?.hags })}>{tuning?.hags ? t("optimize.hagsOff") : t("optimize.hagsOn")}</button>
      </div>
      <h3>{t("optimize.gpuPerApp")}</h3>
      <p class="faint">{t("optimize.gpuPerAppNote")}</p>
      {#if tuning?.gpuPreferences.length}
        <Readouts nameWidth={220} rows={tuning.gpuPreferences.slice(0, 12).map((g) => ({ name: g.exe.split("\\").pop() ?? g.exe, value: prefLabel(g.preference), tip: g.exe }))} />
      {/if}
      <div class="buttons">
        <button onclick={chooseGpuApp}>{t("optimize.chooseApp")}</button>
        {#if gpuExe}
          {#each PREF as [value, label] (value)}
            <button disabled={report.busy} onclick={async () => { await tune("gpu.preference", { exe: gpuExe, preference: value }); gpuExe = null; }}>{t(label)}</button>
          {/each}
        {/if}
      </div>
      {#if gpuExe}<p class="faint">{t("optimize.forApp", { app: gpuExe.split("\\").pop() ?? gpuExe })}</p>{/if}
    </section>

    <section class="panel card">
      <h2>{t("optimize.hibernation")}</h2>
      {#if tuning?.hibernation.enabled}
        <p class="muted">{t("optimize.hibernationOn", { size: size(tuning.hibernation.fileSize) })}</p>
        <div><button disabled={!elevated || report.busy} onclick={() => tune("power.hibernate", { on: false })}>{t("optimize.hibernationOff", { size: size(tuning.hibernation.fileSize) })}</button></div>
      {:else if tuning}
        <p class="muted">{t("optimize.hibernationIsOff")}</p>
        <div><button disabled={!elevated || report.busy} onclick={() => tune("power.hibernate", { on: true })}>{t("optimize.hibernationTurnOn")}</button></div>
      {/if}
    </section>

    <section class="panel card">
      <h2>{t("optimize.drives")}</h2>
      <p class="faint">{t("optimize.drivesNote")}</p>
      {#each drives as drive (drive.letter)}
        <div class="drive"><span class="muted">{drive.letter}: {drive.media}</span><span class="grow"></span>
          <button disabled={!elevated || report.busy} onclick={() => tune("disk.optimize", { drive: drive.letter, media: drive.media })}>{drive.letter}: {drive.media.toUpperCase() === "SSD" ? t("optimize.trim") : t("optimize.defrag")}</button></div>
      {:else}
        <p class="muted">{hw ? t("optimize.noDrives") : t("optimize.readingDrives")}</p>
      {/each}
    </section>

    <section class="panel card">
      <h2>{t("optimize.tools")}</h2>
      <p class="faint">{t("optimize.toolsNote")}</p>
      {#each TOOLS as [label, name] (name)}
        <div><button onclick={() => act({ kind: "shell", op: "tool", name })}>{t(label)}</button></div>
      {/each}
    </section>
  </div>
</div>

<style>
  .scroll { overflow-y: auto; }
  .lead { margin: 0; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(460px, 1fr)); gap: 14px; align-items: start; }
  .card { display: flex; flex-direction: column; gap: 8px; }
  .card p { margin: 0; }
  .table { max-height: 260px; min-height: 120px; overflow-y: auto; border: 1px solid var(--rule); border-radius: 7px; }
  .trow { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1.5fr) 70px; gap: 8px; align-items: center; width: 100%; height: 26px;
          padding: 0 10px; border: 0; border-radius: 0; background: transparent; text-align: left; font-size: 13px; }
  .trow:nth-child(even) { background: var(--surface2); }
  .trow.sel { background: var(--select); }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .radio { display: flex; align-items: center; gap: 8px; }
  .radio input { accent-color: var(--chart); }
  .indent { padding-left: 24px; }
  .buttons { display: flex; flex-wrap: wrap; gap: 6px; }
  .drive { display: flex; align-items: center; gap: 8px; }
  .grow { flex: 1; }
</style>
