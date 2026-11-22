<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { size } from "../lib/format";
  import { locale, t, type Key } from "../lib/i18n/index.svelte";
  import { iconOf } from "../lib/icons.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { InstalledProgram, StartupSignature } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  /** "Recently installed": within this many days (the same as `vigil programs --recent`). */
  const RECENT_DAYS = 7;

  type SortKey = "name" | "publisher" | "version" | "installed" | "size" | "scope";
  const COLUMNS: { key: SortKey; label: Key }[] = [
    { key: "name", label: "programs.colName" },
    { key: "publisher", label: "programs.colPublisher" },
    { key: "version", label: "programs.colVersion" },
    { key: "installed", label: "programs.colInstalled" },
    { key: "size", label: "programs.colSize" },
    { key: "scope", label: "programs.colScope" },
  ];
  type Filter = "all" | "recent" | "remote" | "leftover" | "unsigned";
  const FILTERS: { key: Filter; label: Key; test: (p: InstalledProgram) => boolean }[] = [
    { key: "all", label: "programs.chipAll", test: () => true },
    { key: "recent", label: "programs.chipRecent", test: (p) => recent(p) },
    { key: "remote", label: "programs.chipRemote", test: (p) => p.remote },
    { key: "leftover", label: "programs.chipLeftover", test: (p) => p.leftover },
    { key: "unsigned", label: "programs.chipUnsigned", test: (p) => unsignedFiles(p).length > 0 },
  ];
  // Colour only where the signature says something is wrong; a valid one stays plain ink.
  const SIGNATURE: Record<StartupSignature["status"], { key: Key; color: string }> = {
    broken: { key: "startup.sigBroken", color: "var(--bad)" },
    untrusted: { key: "startup.sigUntrusted", color: "var(--bad)" },
    unsigned: { key: "startup.sigUnsigned", color: "var(--warn)" },
    missing: { key: "startup.fileMissing", color: "var(--warn)" },
    unknown: { key: "startup.sigUnknown", color: "var(--ink3)" },
    valid: { key: "startup.sigValid", color: "var(--ink)" },
  };
  const BAD_SIGNATURE = ["unsigned", "broken", "untrusted"];
  /** Paths per signature request: Rust checks them in a few PowerShell batches. */
  const SIGNATURE_BATCH = 48;

  let rows = $state<InstalledProgram[]>([]);
  let signatures = $state<Record<string, StartupSignature>>({});
  let checking = $state(false);
  let loading = $state(false);
  let error = $state("");
  let search = $state("");
  let filter = $state<Filter>("all");
  let selected = $state<string | null>(null);
  let sortKey = $state<SortKey>("name");
  let ascending = $state(true);

  async function load(): Promise<void> {
    loading = true;
    try {
      rows = await api.programsList();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
    void check();
  }

  // Each batch runs PowerShell, so signatures are read after the list and never hold it up.
  async function check(): Promise<void> {
    if (checking) return;
    const paths = [...new Set(rows.flatMap(filesOf))].filter((path) => !signatures[path]);
    if (!paths.length) return;
    checking = true;
    try {
      for (let i = 0; i < paths.length; i += SIGNATURE_BATCH) {
        signatures = { ...signatures, ...(await api.programSignatures(paths.slice(i, i + SIGNATURE_BATCH))) };
      }
    } catch {
      // Unchecked files then say "Unknown".
    } finally {
      checking = false;
    }
  }
  onMount(() => void load());

  /** The files whose signature says something: the program itself and its uninstaller (not msiexec). */
  function filesOf(p: InstalledProgram): string[] {
    const files = p.executable ? [p.executable] : [];
    if (p.uninstallerExists && !p.uninstallerHost && p.uninstaller && !files.some((f) => f.toLowerCase() === p.uninstaller.toLowerCase())) {
      files.push(p.uninstaller);
    }
    return files;
  }
  const unsignedFiles = (p: InstalledProgram) => filesOf(p).filter((f) => BAD_SIGNATURE.includes(signatures[f]?.status ?? ""));
  const baseName = (path: string) => path.split(/[\\/]/).pop() ?? path;

  // ------------------------------------------------------------------ dates
  /** A YYYY-MM-DD day as a local Date. */
  function dayOf(text: string): Date | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
    return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
  }
  function daysAgo(p: InstalledProgram): number | null {
    const day = dayOf(p.installed);
    if (!day) return null;
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    return Math.round((today.getTime() - day.getTime()) / 86_400_000);
  }
  function recent(p: InstalledProgram): boolean {
    const days = daysAgo(p);
    return days !== null && days >= 0 && days <= RECENT_DAYS;
  }
  function dateText(p: InstalledProgram): string {
    const day = dayOf(p.installed);
    return day ? new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(day) : "";
  }

  function scopeText(p: InstalledProgram): string {
    if (p.sid) return p.account || p.sid;
    if (p.scope === "user") return t("programs.scopeUser");
    return t(p.scope === "machine32" ? "programs.scopeMachine32" : "programs.scopeMachine");
  }

  /** What deserves a look, most important first (warnings, then the plain "installed recently"). */
  function marks(p: InstalledProgram): { text: string; warn: boolean }[] {
    const list: { text: string; warn: boolean }[] = [];
    if (p.remote) list.push({ text: t("programs.flagRemote"), warn: true });
    if (p.leftover) list.push({ text: t("programs.flagLeftover"), warn: true });
    for (const file of unsignedFiles(p)) list.push({ text: t("programs.flagUnsigned", { file: baseName(file) }), warn: true });
    if (recent(p)) list.push({ text: t("programs.flagRecent", { count: RECENT_DAYS }), warn: false });
    return list;
  }

  function signatureOf(path: string): { text: string; color: string; signer: string } {
    const found = signatures[path];
    if (!found) return { text: checking ? t("startup.sigChecking") : t("startup.sigUnknown"), color: "var(--ink3)", signer: "" };
    const look = SIGNATURE[found.status] ?? SIGNATURE.unknown;
    return { text: t(look.key), color: look.color, signer: found.signer };
  }

  // ------------------------------------------------------------------ table
  function sortBy(key: SortKey): void {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      // Newest and biggest first, like Settings.
      ascending = key !== "installed" && key !== "size";
    }
  }

  const text = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
  function compare(a: InstalledProgram, b: InstalledProgram): number {
    switch (sortKey) {
      case "publisher":
        return text(a.publisher, b.publisher);
      case "version":
        return text(a.version, b.version);
      case "installed":
        return a.installed.localeCompare(b.installed);
      case "size":
        return a.size - b.size;
      case "scope":
        return text(scopeText(a), scopeText(b));
      default:
        return text(a.name, b.name);
    }
  }
  // Programs without a date or a size sort last whichever way the column is sorted.
  const blank = (p: InstalledProgram) => (sortKey === "installed" ? !p.installed : sortKey === "size" ? !p.size : false);

  const counts = $derived(Object.fromEntries(FILTERS.map((f) => [f.key, rows.filter(f.test).length])) as Record<Filter, number>);
  const shown = $derived.by(() => {
    const test = FILTERS.find((f) => f.key === filter)?.test ?? (() => true);
    const words = search.toLowerCase().split(/\s+/).filter(Boolean);
    const list = rows.filter((p) => {
      if (!test(p)) return false;
      if (!words.length) return true;
      const haystack = `${p.name} ${p.publisher} ${p.version} ${p.location} ${p.uninstaller} ${p.keyName}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    // Ties keep the name order, so rows never jump between refreshes.
    return list.sort((a, b) => Number(blank(a)) - Number(blank(b)) || (ascending ? 1 : -1) * compare(a, b) || text(a.name, b.name) || text(a.id, b.id));
  });
  const shownSize = $derived(shown.reduce((sum, p) => sum + p.size, 0));
  const current = $derived(rows.find((p) => p.id === selected) ?? null);

  // Rust reads the entry again and re-checks everything; these only keep pointless buttons off.
  const mine = $derived(!!current && !current.sid && (current.scope === "user" || elevated) && !report.busy);
  const canUninstall = $derived(
    mine && !!current?.uninstall && !current.noRemove &&
      (current.msi ? !(current.productCode && !current.msiKnown) : current.uninstallerExists),
  );
  const canRemove = $derived(mine && !!current?.leftover && !current.microsoft && !(current.msi && current.msiKnown));
  const canOpen = $derived(!!current?.location && !!current?.locationExists);
  const notes = $derived.by(() => {
    if (!current) return [] as string[];
    const list: string[] = [];
    if (current.sid) list.push(t("programs.otherNote", { account: current.account || current.sid }));
    else if (current.scope !== "user" && !elevated) list.push(t("programs.adminNote"));
    if (current.leftover) list.push(current.microsoft ? t("programs.microsoftNote") : t("programs.leftoverNote"));
    if (current.noRemove) list.push(t("programs.noRemoveNote"));
    if (!current.uninstall) list.push(t("programs.noUninstallerNote"));
    return list;
  });

  async function run(op: "uninstall" | "remove_entry"): Promise<void> {
    if (!current) return;
    const id = current.id;
    const outcome = await act({ kind: "program", op, id });
    if (outcome && !outcome.cancelled) {
      await load();
      selected = rows.some((p) => p.id === id) ? id : null;
    }
  }
</script>

<div class="page">
  <div class="searchbar">
    <label class="search">
      <i class="icon">{""}</i>
      <input type="search" placeholder={t("programs.search")} aria-label={t("programs.search")} bind:value={search} />
    </label>
  </div>

  <div class="title-row">
    <h2>{t("page.programs")}</h2>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" disabled={!canUninstall} onclick={() => run("uninstall")}><i class="icon">{""}</i>{t("programs.uninstall")}</button>
      <button class="command" disabled={!canRemove} onclick={() => run("remove_entry")}><i class="icon">{""}</i>{t("programs.removeEntry")}</button>
      <span class="sep"></span>
      <button class="command" disabled={!canOpen} onclick={() => current && act({ kind: "program", op: "folder", id: current.id })}>
        <i class="icon">{""}</i>{t("programs.openFolder")}</button>
      <button class="command" onclick={() => act({ kind: "shell", op: "url", url: "ms-settings:appsfeatures" })}>
        <i class="icon">{""}</i>{t("programs.openSettings")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{t("programs.note")}</p>

  <div class="filters" role="toolbar" aria-label={t("programs.filters")}>
    {#each FILTERS as f (f.key)}
      {#if f.key === "all" || counts[f.key] > 0}
        <button class="chip" class:on={filter === f.key} aria-pressed={filter === f.key} onclick={() => (filter = f.key)}>
          {t(f.label)} <span class="num">{counts[f.key]}</span>
        </button>
      {/if}
    {/each}
  </div>

  <div class="table">
    <div class="row head">
      {#each COLUMNS as column (column.key)}
        <button class="th" class:sorted={sortKey === column.key} aria-pressed={sortKey === column.key} onclick={() => sortBy(column.key)}>
          {#if sortKey === column.key}<i class="icon caret">{ascending ? "" : ""}</i>{/if}
          <span class="label">{t(column.label)}</span>
        </button>
      {/each}
    </div>
    {#each shown as p (p.id)}
      {@const icon = p.icon ? iconOf(p.icon) : ""}
      {@const found = marks(p)}
      {@const warned = found.filter((m) => m.warn)}
      <button class="row" class:sel={selected === p.id} class:off={p.leftover} onclick={() => (selected = p.id)}>
        <span class="cell name" title={p.name}>
          {#if icon}<img class="app-icon" src={icon} alt="" />{:else}<i class="icon app-icon generic">{""}</i>{/if}
          <span class="text">{p.name}</span>
          {#if warned.length}
            <i class="icon mark" style:color="var(--warn)" title={warned.map((m) => m.text).join("\n")}>{""}</i>
          {:else if found.length}
            <i class="icon mark" style:color="var(--ink3)" title={found.map((m) => m.text).join("\n")}>{""}</i>
          {/if}
        </span>
        <span class="cell" title={p.publisher}>{p.publisher}</span>
        <span class="cell" title={p.version}>{p.version}</span>
        <span class="cell" title={p.installedEstimated ? t("programs.estimatedTip") : ""}>{dateText(p)}</span>
        <span class="cell num-cell">{p.size ? size(p.size) : ""}</span>
        <span class="cell" title={scopeText(p)}>{scopeText(p)}</span>
      </button>
    {:else}
      <p class="faint empty">{loading ? t("common.reading") : t("programs.empty")}</p>
    {/each}
  </div>

  {#if current}
    {@const found = marks(current)}
    <section class="panel info" aria-live="polite">
      <div class="info-head">
        <h3 class="selectable">{current.name}</h3>
        <span class="faint">{[current.publisher, current.version].filter(Boolean).join(" · ")}</span>
      </div>
      {#each found as m (m.text)}
        <span class="reason" style:color={m.warn ? "var(--warn)" : "var(--ink2)"}>
          <i class="icon">{m.warn ? "" : ""}</i>{m.text}
        </span>
      {/each}
      <div class="grid">
        <span class="faint">{t("programs.colInstalled")}</span>
        <span>{dateText(current) ? (current.installedEstimated ? t("programs.estimated", { date: dateText(current) }) : dateText(current)) : "—"}</span>
        <span class="faint">{t("programs.colSize")}</span><span>{current.size ? size(current.size) : t("programs.notDeclared")}</span>
        <span class="faint">{t("programs.location")}</span>
        <span class="mono selectable">
          {#if !current.location}{t("programs.notDeclared")}
          {:else if !current.locationExists}{t("programs.locationMissing", { path: current.location })}
          {:else if current.locationEmpty}{t("programs.locationEmpty", { path: current.location })}
          {:else}{current.location}{/if}
        </span>
        <span class="faint">{t("programs.uninstallCommand")}</span><span class="mono selectable cmd">{current.uninstall || "—"}</span>
        {#if current.quietUninstall}
          <span class="faint">{t("programs.quietCommand")}</span><span class="mono selectable cmd">{current.quietUninstall}</span>
        {/if}
        {#if current.executable}
          {@const sig = signatureOf(current.executable)}
          <span class="faint">{t("programs.executable")}</span><span class="mono selectable">{current.executable}</span>
          <span class="faint">{t("programs.signature")}</span>
          <span style:color={sig.color}>{sig.text}{sig.signer ? ` · ${sig.signer}` : ""}</span>
        {/if}
        {#if current.uninstaller && !current.uninstallerHost}
          <span class="faint">{t("programs.uninstaller")}</span>
          <span class="mono selectable">{current.uninstallerExists ? current.uninstaller : t("programs.locationMissing", { path: current.uninstaller })}</span>
          {#if current.uninstallerExists && current.uninstaller.toLowerCase() !== current.executable.toLowerCase()}
            {@const sig = signatureOf(current.uninstaller)}
            <span class="faint">{t("programs.signature")}</span>
            <span style:color={sig.color}>{sig.text}{sig.signer ? ` · ${sig.signer}` : ""}</span>
          {/if}
        {/if}
        {#if current.msi}
          <span class="faint">{t("programs.msiLabel")}</span>
          <span class="mono selectable" class:warn={!!current.productCode && !current.msiKnown}>
            {current.productCode ? t(current.msiKnown ? "programs.msiKnown" : "programs.msiUnknown", { code: current.productCode }) : "—"}
          </span>
        {/if}
        <span class="faint">{t("programs.colScope")}</span><span>{scopeText(current)}</span>
        <span class="faint">{t("programs.registry")}</span><span class="mono selectable">{current.id}</span>
      </div>
      {#each notes as note (note)}<p class="faint">{note}</p>{/each}
    </section>
  {/if}

  <div class="faint footer">
    {error || t("programs.summary", { shown: shown.length, total: rows.length, size: size(shownSize) })}{checking ? ` · ${t("startup.checking")}` : ""}
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

  .filters { display: flex; flex-wrap: wrap; gap: 6px; flex: none; }
  .num { color: var(--ink3); margin-left: 2px; }

  /* Task Manager's table: a plain header with column rules, flat rows, hover and selection as overlays. */
  .table {
    --cols: minmax(260px, 2.4fr) minmax(160px, 1.4fr) minmax(100px, 0.8fr) 120px 90px minmax(130px, 1fr);
    flex: 1; min-height: 120px; overflow: auto; border-top: 1px solid var(--rule);
  }
  .row { display: grid; grid-template-columns: var(--cols); min-width: 900px; align-items: stretch; font-size: 13px; }
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
    text-align: left; color: var(--ink); content-visibility: auto; contain-intrinsic-size: auto 28px;
  }
  button.row::after { content: ""; position: absolute; inset: 0; pointer-events: none; }
  button.row:hover:not(:disabled) { background: transparent; }
  button.row:hover::after { background: var(--hover); }
  button.row.sel::after { background: var(--table-select); }
  button.row.off .cell { color: var(--ink2); }
  .cell { padding: 0 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; line-height: 28px; }
  .cell.name { display: flex; align-items: center; gap: 8px; padding-left: 12px; }
  .num-cell { text-align: right; font-variant-numeric: tabular-nums; }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .app-icon { flex: none; width: 16px; height: 16px; }
  .app-icon.generic { font-size: 16px; color: var(--ink2); }
  .mark { flex: none; font-size: 13px; }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; flex: none; max-height: 300px; overflow: auto; }
  .info p { margin: 0; }
  .info-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .reason { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
  .reason .icon { font-size: 13px; }
  .grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .mono { overflow-wrap: anywhere; }
  .cmd { white-space: pre-wrap; word-break: break-all; max-height: 4.8em; overflow: auto; }
  .warn { color: var(--warn); }
  .footer { padding-left: 4px; }
</style>
