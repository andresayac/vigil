<script lang="ts">
  import { onMount } from "svelte";
  import ProcessTable from "../components/ProcessTable.svelte";
  import { age, num, pct, size } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { PRIORITIES, priorityLabel } from "../lib/labels";
  import { acquire, live, release } from "../lib/live.svelte";
  import { processDetails } from "../lib/api";
  import { act, report } from "../lib/report.svelte";
  import type { ProcessDetails } from "../lib/types";

  let { focusPid = null, elevated, autoRefresh = true, onshowfinding }: {
    focusPid?: number | null; elevated: boolean; autoRefresh?: boolean; onshowfinding?: (id: string) => void;
  } = $props();
  let menu = $state<"" | "priority" | "file">("");

  let filter = $state("");
  let tree = $state(true);
  let selected = $state<string | null>(null);
  let held = $state(false);

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

  const row = $derived(live.processes.find((r) => `${r.pid}:${r.createdMs}` === selected) ?? null);
  const suspended = $derived(live.processes.filter((r) => r.status === "suspended").length);
  const snap = $derived(live.snapshot);

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
  $effect(() => {
    const key = selected;
    const pid = row?.pid;
    if (tab === "details" || !key || pid === undefined || key === detailsFor) return;
    detailsLoading = true;
    const timer = setTimeout(async () => {
      try {
        const result = await processDetails(pid);
        if (selected === key) {
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
  const shownDetails = $derived(detailsFor === selected ? details : null);
  const modules = $derived(
    [...(shownDetails?.modules ?? [])].sort((a, b) => Number(b.userWritable) - Number(a.userWritable)),
  );
  const writable = $derived(modules.filter((m) => m.userWritable).length);

  function run(op: string, priority?: string): void {
    menu = "";
    if (row) void act({ kind: "process", op, pid: row.pid, createdMs: row.createdMs, priority });
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>{t("page.processes")}</h1>
    <span class="grow"></span>
    <input type="search" placeholder={t("proc.filter")} bind:value={filter} />
    <label class="check"><input type="checkbox" bind:checked={tree} /> {t("proc.tree")}</label>
  </div>

  <div class="toolbar">
    <button class="danger-outline" disabled={!row || row.pid <= 4 || report.busy} onclick={() => run("terminate")}>{t("proc.end")}</button>
    <button class="danger-outline" disabled={!row || row.pid <= 4 || report.busy} onclick={() => run("terminate_tree")}>{t("proc.endTree")}</button>
    {#if row?.status === "suspended"}
      <button disabled={report.busy} onclick={() => run("resume")}>{t("proc.resume")}</button>
    {:else}
      <button disabled={!row || row.pid <= 4 || report.busy} onclick={() => run("suspend")}>{t("proc.suspend")}</button>
    {/if}
    <span class="sep"></span>
    <div class="anchor">
      <button disabled={!row || report.busy} aria-expanded={menu === "priority"}
              onclick={() => (menu = menu === "priority" ? "" : "priority")}>{t("proc.priority")} <span class="chev">{"\uE70D"}</span></button>
      {#if menu === "priority"}
        <div class="pop">
          {#each PRIORITIES as value (value)}<button onclick={() => run("priority", value)}>{t("proc.cpuPriority", { level: priorityLabel(value) })}</button>{/each}
          <hr />
          <button onclick={() => run("background")} title={t("proc.backgroundTip")}>{t("proc.background")}</button>
        </div>
      {/if}
    </div>
    <button disabled={!row || report.busy} onclick={() => run("efficiency")}>{t("proc.efficiency")}</button>
    <button disabled={!row || report.busy} onclick={() => run("trim")}>{t("proc.trim")}</button>
    <span class="sep"></span>
    <div class="anchor">
      <button disabled={!row?.exe} aria-expanded={menu === "file"} onclick={() => (menu = menu === "file" ? "" : "file")}>{t("proc.file")} <span class="chev">{"\uE70D"}</span></button>
      {#if menu === "file"}
        <div class="pop">
          <button onclick={() => run("location")}>{t("proc.location")}</button>
          <button onclick={() => run("properties")}>{t("proc.properties")}</button>
          <button onclick={() => run("verify")}>{t("proc.verify")}</button>
          <hr />
          <button disabled={!elevated || report.busy} onclick={() => run("block")}>{t("proc.block")}</button>
          <button class="danger" disabled={!elevated || report.busy} onclick={() => run("quarantine")}>{t("proc.quarantine")}</button>
        </div>
      {/if}
    </div>
    {#if finding}
      <span class="grow"></span>
      <button class="finding" style:--mark={`var(--${finding.verdict.replace("_", "-")})`} onclick={() => onshowfinding?.(finding.id)}>
        <span class="dot"></span>{t("proc.showFinding")}
      </button>
    {/if}
  </div>
  {#if menu}<button class="scrim" aria-label={t("common.closeMenu")} onclick={() => (menu = "")}></button>{/if}

  <ProcessTable rows={live.processes} gpu={snap?.gpuByPid ?? []} {filter} {tree} {marks} bind:selected
                hold={menu !== "" || report.busy} bind:held />

  {#if row}
    <section class="panel info">
      <div class="info-head">
        <h3>{row.name}</h3>
        <span class="faint">{t("proc.ids", { pid: String(row.pid), ppid: String(row.ppid) })} · {row.status === "suspended" ? t("proc.stateSuspended") : t("proc.stateRunning")}</span>
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

  <div class="faint">
    {[
      t("proc.count", { count: live.processes.length }),
      suspended ? t("proc.suspendedCount", { count: suspended }) : "",
      held ? t("proc.held") : "",
      snap ? t("proc.usage", { cpu: pct(snap.cpu), memory: pct((snap.memory.used / snap.memory.total) * 100), total: size(snap.memory.total, 0) }) : "",
    ].filter(Boolean).join(" · ")}
  </div>
</div>

<style>
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; position: relative; z-index: 11; }
  .sep { width: 1px; align-self: stretch; margin: 4px 4px; background: var(--rule); }
  .chev { font-family: var(--font-icons); font-size: 9px; margin-left: 4px; }
  .grow { flex: 1; }
  .finding { display: inline-flex; align-items: center; gap: 7px; }
  .finding .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--mark); }
  .pop hr { border: 0; border-top: 1px solid var(--rule); margin: 4px 0; }
  .pop .danger { color: var(--bad); }
  .scrim { position: fixed; inset: 0; z-index: 10; border: 0; background: transparent; padding: 0; cursor: default; }
  .anchor { position: relative; }
  .pop { position: absolute; top: 34px; left: 0; z-index: 10; display: flex; flex-direction: column; min-width: 200px; padding: 4px;
         background: var(--surface); border: 1px solid var(--rule-strong); border-radius: 7px; box-shadow: 0 10px 28px rgb(0 0 0 / 0.3); }
  .pop button { border: 0; background: transparent; text-align: left; padding: 5px 10px; }
  .pop button:hover:not(:disabled) { background: var(--select); }
  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; }
  .info-head { display: flex; align-items: center; gap: 12px; }
  .info-head .grow { flex: 1; }
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
</style>
