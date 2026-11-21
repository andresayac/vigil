<script lang="ts">
  import { onMount } from "svelte";
  import AffinityDialog from "../components/AffinityDialog.svelte";
  import ProcessTable, { type Totals, type View } from "../components/ProcessTable.svelte";
  import RunTaskDialog from "../components/RunTaskDialog.svelte";
  import { age, num, pct, size } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { PRIORITIES, priorityLabel } from "../lib/labels";
  import { acquire, live, release } from "../lib/live.svelte";
  import { processDetails } from "../lib/api";
  import type { Picked } from "../lib/process-groups";
  import { act, report } from "../lib/report.svelte";
  import type { ProcessDetails } from "../lib/types";

  let { focusPid = null, elevated, autoRefresh = true, onshowfinding }: {
    focusPid?: number | null; elevated: boolean; autoRefresh?: boolean; onshowfinding?: (id: string) => void;
  } = $props();
  let menu = $state<"" | "priority" | "file" | "more">("");
  let runOpen = $state(false);
  let affinityFor = $state<{ pid: number; createdMs: number; name: string } | null>(null);

  let filter = $state("");
  let selected = $state<string | null>(null);
  let picked = $state<Picked | null>(null);
  let held = $state(false);

  // Grouped (Task Manager's Processes tab), tree (who started whom) or a flat list; remembered per computer.
  const VIEWS: View[] = ["grouped", "tree", "list"];
  const VIEW_LABEL: Record<View, Key> = { grouped: "proc.viewGrouped", tree: "proc.viewTree", list: "proc.viewList" };
  let view = $state<View>(readView());
  function readView(): View {
    try {
      const saved = localStorage.getItem("vigil.processes.view");
      return VIEWS.includes(saved as View) ? (saved as View) : "grouped";
    } catch {
      return "grouped";
    }
  }
  function setView(next: View): void {
    view = next;
    try {
      localStorage.setItem("vigil.processes.view", next);
    } catch {
      // Not remembered: the view still changes.
    }
  }

  onMount(() => {
    void acquire();
    return () => void release();
  });

  // A process chosen on another page: select it as soon as the list contains it.
  let pending = $state<number | null>(null);
  $effect(() => {
    pending = focusPid;
  });
  $effect(() => {
    if (pending === null) return;
    const row = live.processes.find((r) => r.pid === pending);
    if (row) {
      filter = "";
      selected = `${row.pid}:${row.createdMs}`;
      pending = null;
    }
  });

  const row = $derived(picked?.row ?? null);
  const group = $derived((picked?.count ?? 0) > 1);
  const suspended = $derived(live.processes.filter((r) => r.status === "suspended").length);
  const snap = $derived(live.snapshot);
  const vramTotal = $derived(snap?.gpus.reduce((sum, g) => sum + g.dedicatedTotal, 0) ?? 0);
  const totals: Totals | null = $derived(snap ? {
    cpu: snap.cpu,
    memory: snap.memory.total ? (snap.memory.used / snap.memory.total) * 100 : 0,
    disk: Math.max(0, ...snap.disks.map((d) => d.active)),
    gpu: Math.max(0, ...snap.gpus.map((g) => g.utilization)),
    vram: vramTotal ? (snap.gpus.reduce((sum, g) => sum + g.dedicatedUsed, 0) / vramTotal) * 100 : 0,
  } : null);

  // Findings of the last scan whose file is running now.
  const findingsByExe = $derived(new Map((report.analysis?.items ?? [])
    .filter((i) => i.path && ["remove", "disable", "review"].includes(i.verdict))
    .map((i) => [String(i.path).toLowerCase(), i] as const)));
  const marks = $derived(new Map([...findingsByExe].map(([exe, i]) => [exe, i.verdict])));
  const finding = $derived(row ? findingsByExe.get(row.exe.toLowerCase()) ?? null : null);

  // Inspector: modules and hosted services of the selected process, read when its tab is open.
  let tab = $state<"details" | "modules" | "services">("details");
  let details = $state<ProcessDetails | null>(null);
  let detailsFor = $state("");
  let detailsLoading = $state(false);
  const rowKey = $derived(row ? `${row.pid}:${row.createdMs}` : "");
  $effect(() => {
    const key = rowKey;
    const pid = row?.pid;
    if (tab === "details" || !key || pid === undefined || key === detailsFor) return;
    detailsLoading = true;
    const timer = setTimeout(async () => {
      try {
        const result = await processDetails(pid);
        if (rowKey === key) {
          details = result;
          detailsFor = key;
        }
      } catch (error) {
        details = { modules: [], modulesError: String(error), services: [] };
        detailsFor = key;
      } finally {
        detailsLoading = false;
      }
    }, 150);
    return () => clearTimeout(timer);
  });
  const shownDetails = $derived(detailsFor === rowKey ? details : null);
  const modules = $derived(
    [...(shownDetails?.modules ?? [])].sort((a, b) => Number(b.userWritable) - Number(a.userWritable)),
  );
  const writable = $derived(modules.filter((m) => m.userWritable).length);

  function run(op: string, priority?: string): void {
    menu = "";
    if (row) void act({ kind: "process", op, pid: row.pid, createdMs: row.createdMs, priority });
  }
  /** End task: a group row ends every process of the group (Rust checks each one again and leaves out protected ones). */
  function endTask(): void {
    menu = "";
    if (!row || !picked) return;
    if (!group) return run("terminate");
    void act({
      kind: "process", op: "terminate", pid: row.pid, createdMs: row.createdMs,
      pids: picked.members.map((m) => ({ pid: m.pid, createdMs: m.createdMs })),
    });
  }
  function openAffinity(): void {
    menu = "";
    if (row) affinityFor = { pid: row.pid, createdMs: row.createdMs, name: `${row.name} (PID ${row.pid})` };
  }
  const toggleMenu = (name: typeof menu) => (menu = menu === name ? "" : name);
  const canEnd = $derived(!!row && row.pid > 4 && !report.busy);
</script>

<div class="page">
  <div class="searchbar">
    <label class="search">
      <i class="icon">{""}</i>
      <input type="search" placeholder={t("proc.search")} aria-label={t("proc.search")} bind:value={filter} />
    </label>
  </div>

  <div class="title-row">
    <h2>{t("page.processes")}</h2>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" disabled={report.busy} onclick={() => { menu = ""; runOpen = true; }}>
        <i class="icon">{""}</i>{t("proc.runTask")}</button>
      <button class="command" disabled={!canEnd} title={group ? t("proc.endGroupTip", { count: picked?.count ?? 0 }) : ""}
              onclick={endTask}><i class="icon">{""}</i>{t("proc.endTask")}</button>
      <button class="command" disabled={!row || report.busy} onclick={() => run("efficiency")}>
        <i class="icon">{""}</i>{t("proc.efficiency")}</button>
      <div class="anchor">
        <button class="command" disabled={!row || report.busy} aria-expanded={menu === "priority"} onclick={() => toggleMenu("priority")}>
          <i class="icon">{""}</i>{t("proc.priority")}<i class="chev">{""}</i></button>
        {#if menu === "priority"}
          <div class="pop" role="menu">
            {#each PRIORITIES as value (value)}
              <button role="menuitem" onclick={() => run("priority", value)}>{t("proc.cpuPriority", { level: priorityLabel(value) })}</button>
            {/each}
            <hr />
            <button role="menuitem" onclick={() => run("background")} title={t("proc.backgroundTip")}>{t("proc.background")}</button>
            <hr />
            <button role="menuitem" onclick={openAffinity}>{t("proc.affinity")}</button>
          </div>
        {/if}
      </div>
      <div class="anchor">
        <button class="command" disabled={!row?.exe} aria-expanded={menu === "file"} onclick={() => toggleMenu("file")}>
          <i class="icon">{""}</i>{t("proc.file")}<i class="chev">{""}</i></button>
        {#if menu === "file"}
          <div class="pop" role="menu">
            <button role="menuitem" onclick={() => run("location")}><i class="icon">{""}</i>{t("proc.location")}</button>
            <button role="menuitem" onclick={() => run("properties")}><i class="icon"></i>{t("proc.properties")}</button>
            <button role="menuitem" onclick={() => run("verify")}><i class="icon">{""}</i>{t("proc.verify")}</button>
            <hr />
            <button role="menuitem" disabled={!elevated || report.busy} onclick={() => run("block")}><i class="icon"></i>{t("proc.block")}</button>
            <button role="menuitem" class="danger" disabled={!elevated || report.busy} onclick={() => run("quarantine")}>
              <i class="icon">{""}</i>{t("proc.quarantine")}</button>
          </div>
        {/if}
      </div>
      <div class="anchor">
        <button class="command more" aria-label={t("proc.more")} title={t("proc.more")} aria-expanded={menu === "more"}
                onclick={() => toggleMenu("more")}><i class="icon">{""}</i></button>
        {#if menu === "more"}
          <div class="pop end" role="menu">
            <button role="menuitem" disabled={!canEnd} onclick={() => run("terminate_tree")}><i class="icon">{""}</i>{t("proc.endTree")}</button>
            {#if row?.status === "suspended"}
              <button role="menuitem" disabled={report.busy} onclick={() => run("resume")}><i class="icon">{""}</i>{t("proc.resume")}</button>
            {:else}
              <button role="menuitem" disabled={!canEnd} onclick={() => run("suspend")}><i class="icon">{""}</i>{t("proc.suspend")}</button>
            {/if}
            <button role="menuitem" disabled={!row || report.busy} onclick={() => run("trim")}><i class="icon">{""}</i>{t("proc.trim")}</button>
            <hr />
            <button role="menuitem" disabled={!finding} onclick={() => { menu = ""; if (finding) onshowfinding?.(finding.id); }}>
              <i class="icon">{""}</i>{t("proc.showFinding")}</button>
          </div>
        {/if}
      </div>
      <span class="sep"></span>
      <div class="segmented" role="radiogroup" aria-label={t("proc.view")}>
        {#each VIEWS as v (v)}
          <button role="radio" aria-checked={view === v} class:on={view === v} onclick={() => setView(v)}>{t(VIEW_LABEL[v])}</button>
        {/each}
      </div>
    </div>
  </div>
  {#if menu}<button class="scrim" aria-label={t("common.closeMenu")} onclick={() => (menu = "")}></button>{/if}

  <ProcessTable rows={live.processes} gpu={snap?.gpuByPid ?? []} {filter} {view} {marks} {totals} {vramTotal}
                memoryTotal={snap?.memory.total ?? 0} bind:selected bind:picked hold={menu !== "" || report.busy} bind:held />

  {#if row && picked}
    <section class="panel info">
      <div class="info-head">
        <h3>{picked.label}</h3>
        <span class="faint">
          {group ? `${t("proc.count", { count: picked.count })} · ` : ""}{t("proc.ids", { pid: String(row.pid), ppid: String(row.ppid) })} · {row.status === "suspended" ? t("proc.stateSuspended") : t("proc.stateRunning")}
        </span>
        {#if finding}
          <button class="finding subtle" style:--mark={`var(--${finding.verdict.replace("_", "-")})`} onclick={() => onshowfinding?.(finding.id)}>
            <span class="dot"></span>{t("proc.showFinding")}
          </button>
        {/if}
        <span class="grow"></span>
        <div class="tabs" role="tablist">
          <button role="tab" aria-selected={tab === "details"} class:on={tab === "details"} onclick={() => (tab = "details")}>{t("proc.tabDetails")}</button>
          <button role="tab" aria-selected={tab === "modules"} class:on={tab === "modules"} onclick={() => (tab = "modules")}>
            {t("proc.tabModules")}{#if shownDetails && writable}<span class="warn-count">{writable}</span>{/if}</button>
          <button role="tab" aria-selected={tab === "services"} class:on={tab === "services"} onclick={() => (tab = "services")}>{t("proc.tabServices")}</button>
        </div>
      </div>
      {#if tab === "modules"}
        {#if !shownDetails}
          <p class="faint">{detailsLoading ? t("proc.readingModules") : ""}</p>
        {:else if shownDetails.modulesError}
          <p class="faint">{shownDetails.modulesError} {t("proc.modulesDenied")}</p>
        {:else}
          <p class="faint">{t("proc.modulesLoaded", { count: modules.length })}{writable ? ` · ${t("proc.modulesWritable", { count: writable })}` : ""}</p>
          <div class="list">
            {#each modules as m (m.path)}
              <div class="mrow" class:flag={m.userWritable} title={m.userWritable ? t("proc.moduleWritableTip") : ""}>
                <span class="ellipsis">{m.name}</span><span class="mono ellipsis selectable">{m.path}</span><span class="r num">{size(m.size, 0)}</span>
              </div>
            {/each}
          </div>
        {/if}
      {:else if tab === "services"}
        {#if !shownDetails}
          <p class="faint">{detailsLoading ? t("proc.readingServices") : ""}</p>
        {:else if !shownDetails.services.length}
          <p class="faint">{t("proc.noServices")}</p>
        {:else}
          <div class="list">
            {#each shownDetails.services as svc (svc.name)}
              <div class="srow"><span class="mono selectable">{svc.name}</span><span class="ellipsis">{svc.displayName}</span></div>
            {/each}
          </div>
        {/if}
      {:else}
      <div class="grid">
        <span class="faint">{t("proc.path")}</span><span class="mono selectable">{row.exe || "—"}</span>
        <span class="faint">{t("proc.commandLine")}</span><span class="mono selectable cmd">{row.cmdline || "—"}</span>
        <span class="faint">{t("proc.user")}</span><span class="selectable">{row.user || "—"}</span>
        <span class="faint">{t("proc.started")}</span><span>{t("proc.startedAgo", { age: age(row.createdMs) })}</span>
        <span class="faint">{t("proc.memory")}</span><span>{t("proc.memoryValue", { private: size(row.privateBytes), working: size(row.workingSet) })}</span>
        <span class="faint">{t("proc.threadsHandles")}</span><span>{num(row.threads)} · {num(row.handles)}</span>
      </div>
      {/if}
    </section>
  {/if}

  <RunTaskDialog open={runOpen} {elevated} onclose={() => (runOpen = false)} />
  <AffinityDialog open={affinityFor !== null} target={affinityFor} onclose={() => (affinityFor = null)} />

  <div class="faint footer">
    {[
      t("proc.count", { count: live.processes.length }),
      suspended ? t("proc.suspendedCount", { count: suspended }) : "",
      held ? t("proc.held") : "",
      snap ? t("proc.usage", { cpu: pct(snap.cpu), memory: pct((snap.memory.used / snap.memory.total) * 100), total: size(snap.memory.total, 0) }) : "",
    ].filter(Boolean).join(" · ")}
  </div>
</div>

<style>
  .page { gap: 8px; padding: 10px 20px 12px; }
  .searchbar { display: flex; justify-content: center; padding-bottom: 2px; }
  .search {
    position: relative; display: flex; align-items: center; width: min(640px, 100%);
  }
  .search .icon { position: absolute; left: 12px; font-size: 14px; color: var(--ink2); pointer-events: none; }
  .search input { width: 100%; min-width: 0; padding-left: 36px; }
  .title-row { display: flex; align-items: center; gap: 8px; min-height: 40px; position: relative; z-index: 11; flex-wrap: wrap; }
  .title-row h2 { padding-left: 4px; }
  .grow { flex: 1; }
  .anchor { position: relative; }
  .more { padding-left: 8px; padding-right: 8px; }
  .segmented {
    display: inline-flex; gap: 2px; padding: 2px; border-radius: var(--radius); background: var(--control);
    border: 1px solid var(--control-stroke);
  }
  .segmented button {
    min-height: 26px; padding: 2px 10px 3px; border: 1px solid transparent; background: transparent; color: var(--ink2);
    border-radius: 3px; font-size: 13px;
  }
  .segmented button:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  .segmented button.on {
    background: var(--surface); color: var(--ink); border-color: var(--control-stroke); font-weight: 600;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
  }
  .scrim { position: fixed; inset: 0; z-index: 10; border: 0; background: transparent; padding: 0; cursor: default; }
  .pop {
    position: absolute; top: 38px; left: 0; z-index: 12; display: flex; flex-direction: column; min-width: 220px; padding: 4px;
    background: var(--flyout); border: 1px solid var(--rule-strong); border-radius: 8px; box-shadow: var(--shadow-flyout);
  }
  .pop.end { left: auto; right: 0; }
  .pop button {
    display: flex; align-items: center; gap: 12px; border: 0; background: transparent; text-align: left; padding: 5px 10px;
    min-height: 32px; white-space: nowrap;
  }
  .pop button .icon { width: 16px; font-size: 16px; text-align: center; flex: none; }
  .pop button:hover:not(:disabled) { background: var(--hover); }
  .pop button:disabled { background: transparent; }
  .pop .danger { color: var(--bad); }
  .pop .danger:disabled { color: var(--ink-disabled); }
  .pop hr { border: 0; border-top: 1px solid var(--rule); margin: 4px -4px; }
  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; flex: none; }
  .info-head { display: flex; align-items: center; gap: 12px; }
  .info-head .grow { flex: 1; }
  .finding { display: inline-flex; align-items: center; gap: 7px; min-height: 28px; padding: 2px 10px; }
  .finding .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--mark); }
  .tabs { display: inline-flex; gap: 2px; }
  .tabs button { border: 0; background: transparent; padding: 4px 10px; border-radius: 4px; color: var(--ink2); position: relative; }
  .tabs button:hover { background: var(--hover); }
  .tabs button.on { color: var(--ink); font-weight: 600; }
  .tabs button.on::after { content: ""; position: absolute; left: 30%; right: 30%; bottom: -2px; height: 3px; border-radius: 2px; background: var(--accent); }
  .warn-count { margin-left: 6px; padding: 0 6px; border-radius: 8px; font-size: 11px; background: var(--warn); color: var(--on-accent, #fff); }
  .list { max-height: 168px; overflow: auto; border: 1px solid var(--rule); border-radius: 4px; }
  .mrow, .srow { display: grid; gap: 0 12px; align-items: center; padding: 0 10px; height: 24px; font-size: 13px; }
  .mrow { grid-template-columns: 200px minmax(0, 1fr) 80px; }
  .srow { grid-template-columns: 220px minmax(0, 1fr); }
  .mrow:nth-child(even), .srow:nth-child(even) { background: var(--surface2); }
  .mrow.flag { color: var(--warn); font-weight: 600; }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .r { text-align: right; }
  .grid { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .cmd { white-space: pre-wrap; word-break: break-all; max-height: 3.2em; overflow: auto; }
  .footer { padding-left: 4px; }
</style>
