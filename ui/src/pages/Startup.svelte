<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { when } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { iconOf } from "../lib/icons.svelte";
  import { verdictColor, verdictLabel } from "../lib/labels";
  import { act, report } from "../lib/report.svelte";
  import type { StartupEntry, StartupSignature } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  type SortKey = "name" | "publisher" | "status" | "signature" | "location";
  const COLUMNS: { key: SortKey; label: Key }[] = [
    { key: "name", label: "startup.colName" },
    { key: "publisher", label: "startup.colPublisher" },
    { key: "status", label: "startup.colStatus" },
    { key: "signature", label: "startup.colSignature" },
    { key: "location", label: "startup.colLocation" },
  ];
  // Colour only where the signature says something is wrong; a valid one stays plain ink.
  const SIGNATURE: Record<StartupSignature["status"], { key: Key; color: string; rank: number }> = {
    broken: { key: "startup.sigBroken", color: "var(--bad)", rank: 0 },
    untrusted: { key: "startup.sigUntrusted", color: "var(--bad)", rank: 1 },
    unsigned: { key: "startup.sigUnsigned", color: "var(--warn)", rank: 2 },
    missing: { key: "startup.fileMissing", color: "var(--warn)", rank: 3 },
    unknown: { key: "startup.sigUnknown", color: "var(--ink3)", rank: 5 },
    valid: { key: "startup.sigValid", color: "var(--ink)", rank: 6 },
  };

  let rows = $state<StartupEntry[]>([]);
  let signatures = $state<Record<string, StartupSignature>>({});
  let checking = $state(false);
  let loading = $state(false);
  let error = $state("");
  let filter = $state("");
  let selected = $state<string | null>(null);
  let sortKey = $state<SortKey>("name");
  let ascending = $state(true);

  async function load(): Promise<void> {
    loading = true;
    try {
      rows = await api.startupList();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
    void check();
  }

  // Each signature check runs PowerShell, so they are read after the list and never hold it up.
  async function check(): Promise<void> {
    const paths = [...new Set(rows.filter((r) => r.exists && !r.host && r.executable).map((r) => r.executable))]
      .filter((path) => !signatures[path]);
    if (!paths.length) return;
    checking = true;
    try {
      signatures = { ...signatures, ...(await api.startupSignatures(paths)) };
    } catch {
      // The column then says "Unknown".
    } finally {
      checking = false;
    }
  }
  onMount(() => void load());

  const baseName = (path: string) => path.split(/[\\/]/).pop() ?? path;
  const displayName = (e: StartupEntry) => e.description || e.name;
  const publisherText = (e: StartupEntry) => (e.host ? t("startup.viaHost", { host: baseName(e.executable) }) : e.publisher);
  const statusRank = (e: StartupEntry) => (!e.canToggle ? 2 : e.enabled ? 0 : 1);
  const statusText = (e: StartupEntry) =>
    !e.canToggle ? t("startup.runsOnce") : e.enabled ? t("startup.enabled") : t("startup.disabled");

  function signatureOf(e: StartupEntry): { text: string; color: string; rank: number; tip: string } {
    if (!e.executable) return { text: t("startup.sigUnknown"), color: "var(--ink3)", rank: 5, tip: "" };
    if (!e.exists) return { text: t("startup.fileMissing"), color: "var(--warn)", rank: 3, tip: e.executable };
    if (e.host) return { text: t("startup.sigHost"), color: "var(--ink3)", rank: 4, tip: t("startup.hostNote") };
    const found = signatures[e.executable];
    if (!found) return { text: checking ? t("startup.sigChecking") : t("startup.sigUnknown"), color: "var(--ink3)", rank: 5, tip: "" };
    const look = SIGNATURE[found.status] ?? SIGNATURE.unknown;
    return { text: t(look.key), color: look.color, rank: look.rank, tip: found.signer ? t("startup.signedBy", { signer: found.signer }) : "" };
  }

  function locationText(e: StartupEntry): string {
    const user = e.scope === "user";
    if (e.kind === "folder") return t(user ? "startup.locFolderUser" : "startup.locFolderMachine");
    if (e.kind === "run_once") return t(user ? "startup.locOnceUser" : "startup.locOnceMachine");
    if (user) return t("startup.locRunUser");
    return t(/wow6432node/i.test(e.location) ? "startup.locRun32" : "startup.locRunMachine");
  }

  function sortBy(key: SortKey): void {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      ascending = true;
    }
  }

  const text = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" });
  function compare(a: StartupEntry, b: StartupEntry): number {
    switch (sortKey) {
      case "publisher":
        return text(publisherText(a), publisherText(b));
      case "status":
        return statusRank(a) - statusRank(b);
      case "signature":
        return signatureOf(a).rank - signatureOf(b).rank;
      case "location":
        return text(locationText(a), locationText(b));
      default:
        return text(displayName(a), displayName(b));
    }
  }

  const shown = $derived.by(() => {
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    const list = rows.filter((e) => {
      const haystack = `${e.name} ${e.description} ${e.publisher} ${e.command} ${e.location}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    // Ties keep the name order, so rows never jump between refreshes.
    return list.sort((a, b) => (ascending ? 1 : -1) * compare(a, b) || text(displayName(a), displayName(b)));
  });
  const current = $derived(rows.find((e) => e.id === selected) ?? null);
  const enabledCount = $derived(rows.filter((e) => e.canToggle && e.enabled).length);

  // Rust re-checks everything against the live list; these only keep pointless buttons off.
  const switchable = $derived(!!current && current.canToggle && (current.scope === "user" || elevated) && !report.busy);
  const canEnable = $derived(switchable && !current?.enabled);
  const canDisable = $derived(switchable && !!current?.enabled);
  // A host program's folder (System32) says nothing; its shortcut, when there is one, does.
  const target = $derived(!current ? "" : current.host || !current.exists ? current.file : current.executable);
  const currentSignature = $derived(current ? signatureOf(current) : null);
  const note = $derived.by(() => {
    if (!current) return "";
    if (!current.canToggle) return t("startup.onceNote");
    if (current.scope === "machine" && !elevated) return t("startup.adminNote");
    if (!current.exists) return t("startup.missingNote");
    if (current.host) return t("startup.hostNote");
    return "";
  });
  const finding = $derived.by(() => {
    if (!current || current.host || !current.executable) return null;
    const exe = current.executable.toLowerCase();
    return (report.analysis?.items ?? []).find((i) => (i.path ?? "").toLowerCase() === exe && i.roles.some((r) => r.kind === "startup")) ?? null;
  });

  async function toggle(op: "enable" | "disable"): Promise<void> {
    if (!current) return;
    const id = current.id;
    const outcome = await act({ kind: "startup", op, id });
    if (outcome && !outcome.cancelled) {
      await load();
      selected = id;
    }
  }
</script>

<div class="page">
  <div class="searchbar">
    <label class="search">
      <i class="icon">{""}</i>
      <input type="search" placeholder={t("startup.search")} aria-label={t("startup.search")} bind:value={filter} />
    </label>
  </div>

  <div class="title-row">
    <h2>{t("page.startup")}</h2>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" disabled={!canEnable} onclick={() => toggle("enable")}><i class="icon">{""}</i>{t("startup.enable")}</button>
      <button class="command" disabled={!canDisable} onclick={() => toggle("disable")}><i class="icon">{""}</i>{t("startup.disable")}</button>
      <span class="sep"></span>
      <button class="command" disabled={!target} onclick={() => act({ kind: "shell", op: "location", path: target })}>
        <i class="icon">{""}</i>{t("proc.location")}</button>
      <button class="command" disabled={!target} onclick={() => act({ kind: "shell", op: "properties", path: target })}>
        <i class="icon">{""}</i>{t("proc.properties")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{t("startup.note")}</p>

  <div class="table">
    <div class="row head">
      {#each COLUMNS as column (column.key)}
        <button class="th" class:sorted={sortKey === column.key} aria-pressed={sortKey === column.key} onclick={() => sortBy(column.key)}>
          {#if sortKey === column.key}<i class="icon caret">{ascending ? "" : ""}</i>{/if}
          <span class="label">{t(column.label)}</span>
        </button>
      {/each}
    </div>
    {#each shown as e (e.id)}
      {@const icon = e.host ? "" : iconOf(e.executable)}
      {@const sig = signatureOf(e)}
      <button class="row" class:sel={selected === e.id} class:off={e.canToggle && !e.enabled} onclick={() => (selected = e.id)}>
        <span class="cell name" title={e.name}>
          {#if icon}<img class="app-icon" src={icon} alt="" />{:else}<i class="icon app-icon generic">{""}</i>{/if}
          <span class="text">{displayName(e)}</span>
          {#if e.own}<span class="own" title={t("startup.ownTip")}>{t("startup.own")}</span>{/if}
        </span>
        <span class="cell" title={publisherText(e)}>{publisherText(e)}</span>
        <span class="cell">{statusText(e)}</span>
        <span class="cell" style:color={sig.color} title={sig.tip}>{sig.text}</span>
        <span class="cell" title={e.location}>{locationText(e)}</span>
      </button>
    {:else}
      <p class="faint empty">{loading ? t("common.reading") : t("startup.empty")}</p>
    {/each}
  </div>

  {#if current}
    <section class="panel info" aria-live="polite">
      <div class="info-head">
        <h3 class="selectable">{displayName(current)}</h3>
        <span class="faint">{statusText(current)} · {locationText(current)}</span>
        {#if finding}
          <span class="finding" style:--mark={verdictColor(finding.verdict)}><span class="dot"></span>{t("startup.lastScan", { verdict: verdictLabel(finding.verdict) })}</span>
        {/if}
      </div>
      <div class="grid">
        <span class="faint">{t("startup.command")}</span><span class="mono selectable cmd">{current.command || "—"}</span>
        <span class="faint">{t("startup.program")}</span><span class="mono selectable">{current.executable || "—"}</span>
        <span class="faint">{t("startup.where")}</span>
        <span class="mono selectable">{current.kind === "folder" ? current.file : `${current.location}\\${current.value}`}</span>
        <span class="faint">{t("startup.scope")}</span><span>{current.scope === "user" ? t("startup.scopeUser") : t("startup.scopeMachine")}</span>
        {#if !current.host}
          <span class="faint">{t("startup.colPublisher")}</span><span class="selectable">{current.publisher || "—"}</span>
        {/if}
        {#if currentSignature}
          <span class="faint">{t("startup.colSignature")}</span>
          <span style:color={currentSignature.color}>{currentSignature.text}{!current.host && signatures[current.executable]?.signer ? ` · ${signatures[current.executable].signer}` : ""}</span>
        {/if}
        {#if current.disabledAtMs}
          <span class="faint">{t("startup.disabledAt")}</span><span>{when(new Date(current.disabledAtMs).toISOString())}</span>
        {/if}
      </div>
      {#if note}<p class="faint">{note}</p>{/if}
    </section>
  {/if}

  <div class="faint footer">
    {error || t("startup.summary", { shown: shown.length, total: rows.length, enabled: enabledCount })}{checking ? ` · ${t("startup.checking")}` : ""}
  </div>
</div>

<style>
  .page { gap: 8px; padding: 10px 20px 12px; }
  .searchbar { display: flex; justify-content: center; padding-bottom: 2px; }
  .search { position: relative; display: flex; align-items: center; width: min(640px, 100%); }
  .search .icon { position: absolute; left: 12px; font-size: 14px; color: var(--ink2); pointer-events: none; }
  .search input { width: 100%; min-width: 0; padding-left: 36px; }
  .title-row { display: flex; align-items: center; gap: 8px; min-height: 40px; flex-wrap: wrap; }
  .title-row h2 { padding-left: 4px; }
  .grow { flex: 1; }
  .lead { margin: 0; padding-left: 4px; }

  /* Task Manager's table: a plain header with column rules, flat rows, hover and selection as overlays. */
  .table {
    --cols: minmax(220px, 2fr) minmax(150px, 1.3fr) 110px 150px minmax(190px, 1.4fr);
    flex: 1; min-height: 120px; overflow: auto; border-top: 1px solid var(--rule);
  }
  .row { display: grid; grid-template-columns: var(--cols); min-width: 860px; align-items: stretch; font-size: 13px; }
  .head { position: sticky; top: 0; z-index: 1; background: var(--layer); border-bottom: 1px solid var(--rule); }
  .th {
    position: relative; display: flex; align-items: flex-end; min-height: 0; height: 40px; padding: 4px 8px 6px; border: 0;
    border-radius: 0; background: transparent; color: var(--ink2); font-size: 12px; line-height: 16px; font-weight: 400;
    text-align: left; white-space: nowrap; overflow: hidden;
  }
  .th + .th { border-left: 1px solid var(--rule); }
  .th:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  .th:active:not(:disabled) { background: var(--pressed); }
  .th.sorted .label { color: var(--ink); }
  .th .label { overflow: hidden; text-overflow: ellipsis; }
  .caret { position: absolute; top: 2px; left: 50%; transform: translateX(-50%); font-size: 8px; color: var(--ink2); }
  button.row {
    position: relative; width: 100%; height: 28px; min-height: 0; padding: 0; border: 0; border-radius: 0; background: transparent;
    text-align: left; color: var(--ink);
  }
  button.row::after { content: ""; position: absolute; inset: 0; pointer-events: none; }
  button.row:hover:not(:disabled) { background: transparent; }
  button.row:hover::after { background: var(--hover); }
  button.row.sel::after { background: var(--table-select); }
  button.row.off .cell { color: var(--ink2); }
  .cell { padding: 0 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; line-height: 28px; }
  .cell.name { display: flex; align-items: center; gap: 8px; padding-left: 12px; }
  .own {
    flex: none; font-size: 11px; line-height: 16px; padding: 0 6px; border-radius: 8px; border: 1px solid var(--rule); color: var(--ink2);
  }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .app-icon { flex: none; width: 16px; height: 16px; }
  .app-icon.generic { font-size: 16px; color: var(--ink2); }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; flex: none; max-height: 260px; overflow: auto; }
  .info p { margin: 0; }
  .info-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .finding { display: inline-flex; align-items: center; gap: 7px; font-size: 12px; color: var(--ink2); }
  .finding .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--mark); }
  .grid { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .mono { overflow-wrap: anywhere; }
  .cmd { white-space: pre-wrap; word-break: break-all; max-height: 4.8em; overflow: auto; }
  .footer { padding-left: 4px; }
</style>
