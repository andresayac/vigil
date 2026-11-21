<script lang="ts">
  import { onMount } from "svelte";
  import Pill from "../components/Pill.svelte";
  import * as api from "../lib/api";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { Service, ServiceOp } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  type SortKey = "displayName" | "name" | "state" | "startType" | "pid" | "account" | "path";
  const STATE: Record<string, { key: Key; rank: number; color: string }> = {
    running: { key: "services.running", rank: 0, color: "var(--ok)" },
    start_pending: { key: "services.starting", rank: 1, color: "var(--warn)" },
    stop_pending: { key: "services.stopping", rank: 1, color: "var(--warn)" },
    continue_pending: { key: "services.changing", rank: 1, color: "var(--warn)" },
    pause_pending: { key: "services.changing", rank: 1, color: "var(--warn)" },
    paused: { key: "services.paused", rank: 2, color: "var(--warn)" },
    stopped: { key: "services.stopped", rank: 3, color: "var(--ink3)" },
  };
  // The four startup types the page can set, in the order services.msc lists them.
  const START_TYPES: { value: string; key: Key }[] = [
    { value: "auto", key: "services.auto" },
    { value: "delayed-auto", key: "services.delayedAuto" },
    { value: "demand", key: "services.demand" },
    { value: "disabled", key: "services.disabled" },
  ];
  const COLUMNS: { key: SortKey; label: Key; right?: boolean }[] = [
    { key: "displayName", label: "services.displayName" },
    { key: "name", label: "services.name" },
    { key: "state", label: "services.status" },
    { key: "startType", label: "services.startupType" },
    { key: "pid", label: "services.pid", right: true },
    { key: "account", label: "services.account" },
    { key: "path", label: "services.path" },
  ];

  let rows = $state<Service[]>([]);
  let error = $state("");
  let loading = $state(false);
  let filter = $state("");
  let runningOnly = $state(false);
  let selected = $state<string | null>(null);
  let sortKey = $state<SortKey>("displayName");
  let ascending = $state(true);
  let menuOpen = $state(false);

  async function load(): Promise<void> {
    loading = true;
    try {
      rows = await api.services();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => void load());

  const stateOf = (s: Service) => STATE[s.state] ?? { key: "services.changing" as Key, rank: 1, color: "var(--warn)" };
  const stateLabel = (s: Service) => (STATE[s.state] ? t(STATE[s.state].key) : s.state);
  function startLabel(value: string): string {
    const known = START_TYPES.find((type) => type.value === value);
    if (known) return t(known.key);
    return value === "boot" || value === "system" ? t("services.boot") : value;
  }
  const startRank = (value: string) => {
    const index = START_TYPES.findIndex((type) => type.value === value);
    return index < 0 ? START_TYPES.length : index;
  };

  function sortBy(key: SortKey): void {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      ascending = true;
    }
  }

  function compare(a: Service, b: Service): number {
    switch (sortKey) {
      case "pid":
        return a.pid - b.pid;
      case "state":
        return stateOf(a).rank - stateOf(b).rank;
      case "startType":
        return startRank(a.startType) - startRank(b.startType);
      default:
        return a[sortKey].localeCompare(b[sortKey], undefined, { sensitivity: "base" });
    }
  }

  const shown = $derived.by(() => {
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    const list = rows.filter((s) => {
      if (runningOnly && s.state !== "running") return false;
      const haystack = `${s.displayName} ${s.name} ${s.description} ${s.pid || ""} ${s.path} ${s.account} ${s.group}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    // Ties keep the display-name order, so the list never jumps between refreshes.
    return list.sort((a, b) => (ascending ? 1 : -1) * compare(a, b) || a.displayName.localeCompare(b.displayName));
  });
  const current = $derived(rows.find((s) => s.name === selected) ?? null);
  const running = $derived(rows.filter((s) => s.state === "running").length);

  // The engine re-checks everything (live state, guards, signatures); these only keep pointless buttons off.
  const locked = $derived(!current || current.protected || !elevated || report.busy);
  const canStart = $derived(!locked && current?.state === "stopped" && current.startType !== "disabled");
  const canStop = $derived(!locked && current?.state === "running");
  const canRestart = $derived(canStop && current?.startType !== "disabled");
  const canSetType = $derived(!locked && !!current && startRank(current.startType) < START_TYPES.length);
  const note = $derived.by(() => {
    if (!current) return "";
    if (current.protected) return t("services.protectedNote");
    if (!elevated) return t("services.adminNote");
    if (current.startType === "disabled" && current.state === "stopped") return t("services.disabledNote");
    return "";
  });
  const host = $derived(
    !current ? "" : current.serviceType === "share"
      ? current.group ? t("services.sharedHostGroup", { group: current.group }) : t("services.sharedHost")
      : t("services.ownProcess"),
  );

  async function run(op: ServiceOp, startType?: string): Promise<void> {
    menuOpen = false;
    if (!current) return;
    const outcome = await act({ kind: "service", op, name: current.name, ...(startType ? { startType } : {}) });
    if (outcome && !outcome.cancelled) await load();
  }
</script>

<svelte:window onclick={() => (menuOpen = false)} onkeydown={(e) => e.key === "Escape" && (menuOpen = false)} />

<div class="page">
  <div class="page-head">
    <h1>{t("page.services")}</h1>
    <span class="grow"></span>
    <input class="search" type="search" placeholder={t("services.filter")} aria-label={t("services.filter")} bind:value={filter} />
    <label class="check"><input type="checkbox" bind:checked={runningOnly} /> {t("services.runningOnly")}</label>
    <button onclick={load} disabled={loading}>{loading ? t("common.reading") : t("common.refresh")}</button>
  </div>

  <div class="toolbar">
    <button disabled={!canStart} onclick={() => run("start")}
            title={current?.startType === "disabled" ? t("services.disabledNote") : ""}>
      <i class="icon">{""}</i>{t("services.start")}
    </button>
    <button class="danger-outline" disabled={!canStop} onclick={() => run("stop")}><i class="icon">{""}</i>{t("services.stop")}</button>
    <button disabled={!canRestart} onclick={() => run("restart")}><i class="icon">{""}</i>{t("services.restart")}</button>
    <div class="anchor">
      <button disabled={!canSetType} aria-haspopup="menu" aria-expanded={menuOpen}
              onclick={(e) => { e.stopPropagation(); menuOpen = !menuOpen; }}>
        {t("services.startupType")}<i class="icon chevron">{""}</i>
      </button>
      {#if menuOpen && current}
        <div class="menu" role="menu">
          {#each START_TYPES as type (type.value)}
            <button role="menuitemradio" aria-checked={current.startType === type.value} disabled={current.startType === type.value}
                    onclick={(e) => { e.stopPropagation(); void run("start_type", type.value); }}>
              <i class="icon mark">{current.startType === type.value ? "" : ""}</i>{t(type.key)}
            </button>
          {/each}
        </div>
      {/if}
    </div>
    <span class="sep"></span>
    <button disabled={!current?.executable} onclick={() => current && act({ kind: "shell", op: "location", path: current.executable })}>
      {t("proc.location")}
    </button>
    <button onclick={() => act({ kind: "shell", op: "console", name: "services.msc" })}>{t("services.openConsole")}</button>
  </div>

  <div class="table">
    <div class="row head">
      {#each COLUMNS as column (column.key)}
        <button class="sort" class:r={column.right} onclick={() => sortBy(column.key)}
                aria-label={t(column.label)} aria-pressed={sortKey === column.key}>
          {t(column.label)}
          {#if sortKey === column.key}<i class="icon arrow">{ascending ? "" : ""}</i>{/if}
        </button>
      {/each}
    </div>
    {#each shown as s (s.name)}
      <button class="row" class:sel={selected === s.name} onclick={() => (selected = s.name)}>
        <span class="ellipsis name" title={s.displayName}>
          {#if s.protected}<i class="icon lock" title={t("services.protectedTip")}>{""}</i>{/if}{s.displayName}
        </span>
        <span class="ellipsis" title={s.name}>{s.name}</span>
        <span><Pill text={stateLabel(s)} color={stateOf(s).color} /></span>
        <span class="ellipsis">{startLabel(s.startType)}</span>
        <span class="r num">{s.pid || ""}</span>
        <span class="ellipsis" title={s.account}>{s.account}</span>
        <span class="ellipsis mono" title={s.path}>{s.path}</span>
      </button>
    {:else}
      <p class="faint empty">{loading ? t("common.reading") : t("services.empty")}</p>
    {/each}
  </div>

  <section class="panel details" aria-live="polite">
    {#if current}
      <div class="title">
        <h3 class="selectable">{current.displayName}</h3>
        <Pill text={stateLabel(current)} color={stateOf(current).color} />
        {#if current.protected}<span class="faint locked"><i class="icon">{""}</i>{t("services.protected")}</span>{/if}
      </div>
      <p class="muted selectable desc">{current.description || t("services.noDescription")}</p>
      <dl>
        <dt>{t("services.name")}</dt><dd class="selectable mono">{current.name}</dd>
        <dt>{t("services.startupType")}</dt><dd>{startLabel(current.startType)}</dd>
        <dt>{t("services.runsIn")}</dt><dd>{host}{current.pid ? ` · PID ${current.pid}` : ""}</dd>
        <dt>{t("services.account")}</dt><dd class="selectable">{current.account}</dd>
        <dt>{t("services.path")}</dt><dd class="selectable mono">{current.path}</dd>
        {#if current.dll}<dt>{t("services.dll")}</dt><dd class="selectable mono">{current.dll}</dd>{/if}
      </dl>
      {#if note}<p class="faint note">{note}</p>{/if}
    {:else}
      <p class="faint">{t("services.pick")}</p>
    {/if}
  </section>

  <div class="faint">{error || t("services.summary", { shown: shown.length, total: rows.length, running })}</div>
</div>

<style>
  .search { width: 320px; }
  .toolbar { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  .toolbar button { display: inline-flex; align-items: center; gap: 8px; }
  .toolbar .icon { font-size: 14px; }
  .toolbar .chevron { font-size: 10px; margin-left: 2px; }
  .sep { width: 1px; height: 20px; background: var(--rule); margin: 0 4px; }
  .anchor { position: relative; }
  /* MenuFlyout under its button. */
  .menu {
    position: absolute; top: calc(100% + 4px); left: 0; z-index: 60; min-width: 240px; padding: 4px;
    background: var(--flyout); border: 1px solid var(--rule); border-radius: 8px; box-shadow: var(--shadow-flyout);
    display: flex; flex-direction: column;
  }
  .menu button {
    border: 0; background: transparent; text-align: left; padding: 0 12px 0 8px; min-height: 32px; border-radius: var(--radius);
    color: var(--ink); gap: 8px;
  }
  .menu button:hover:not(:disabled) { background: var(--hover); }
  .menu button:disabled { color: var(--ink); background: transparent; }
  .menu .mark { width: 16px; font-size: 12px; }

  .table { flex: 1; min-height: 120px; overflow: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; }
  .row {
    display: grid; grid-template-columns: minmax(230px, 2fr) minmax(140px, 1fr) 130px 190px 64px 200px minmax(260px, 2fr);
    gap: 0 10px; align-items: center; padding: 0 10px; height: 30px; font-size: 13px; min-width: 1300px;
  }
  button.row { width: 100%; border: 0; border-radius: 0; background: transparent; text-align: left; min-height: 0; }
  button.row:nth-child(odd) { background: var(--surface2); }
  button.row:hover { background: var(--hover); }
  button.row.sel { background: var(--select); }
  .head { position: sticky; top: 0; background: var(--surface); height: 34px; border-bottom: 1px solid var(--rule); z-index: 1; }
  .sort {
    display: flex; align-items: center; gap: 4px; border: 0; background: transparent; padding: 0; min-height: 0; height: 100%;
    font-size: 12px; font-weight: 600; color: var(--ink2); text-align: left; overflow: hidden; white-space: nowrap;
  }
  .sort:hover:not(:disabled) { background: transparent; color: var(--ink); }
  .sort.r { justify-content: flex-end; }
  .arrow { font-size: 9px; }
  .r { text-align: right; }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .name { display: flex; align-items: center; gap: 6px; }
  .lock { font-size: 12px; color: var(--ink3); flex: none; }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .details { flex: none; max-height: 280px; overflow: auto; padding: 14px 16px; display: flex; flex-direction: column; gap: 8px; }
  .title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .locked { display: inline-flex; align-items: center; gap: 4px; }
  .desc { margin: 0; font-size: 13px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 3px 18px; margin: 0; font-size: 13px; }
  dt { color: var(--ink2); }
  dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
  .note { margin: 0; }
</style>
