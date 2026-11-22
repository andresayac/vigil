<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { FirewallFlag, FirewallProfile, FirewallRule, FirewallSummary } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  type SortKey = "name" | "program" | "direction" | "action" | "ports" | "remote" | "profiles" | "enabled";
  const COLUMNS: { key: SortKey; label: Key }[] = [
    { key: "name", label: "firewall.colName" },
    { key: "program", label: "firewall.colProgram" },
    { key: "direction", label: "firewall.colDirection" },
    { key: "action", label: "firewall.colAction" },
    { key: "ports", label: "firewall.colPorts" },
    { key: "remote", label: "firewall.colRemote" },
    { key: "profiles", label: "firewall.colProfiles" },
    { key: "enabled", label: "firewall.colEnabled" },
  ];
  type Filter = "all" | "flagged" | "open" | "remote" | "missing" | "vigil" | "in" | "out" | "disabled";
  const FILTERS: { key: Filter; label: Key; test: (r: FirewallRule) => boolean }[] = [
    { key: "all", label: "firewall.chipAll", test: () => true },
    { key: "flagged", label: "firewall.chipFlagged", test: (r) => r.flags.some((f) => f.warn) },
    { key: "open", label: "firewall.chipOpen", test: (r) => has(r, "open_public") },
    { key: "remote", label: "firewall.chipRemote", test: (r) => has(r, "remote_access") },
    { key: "missing", label: "firewall.chipMissing", test: (r) => has(r, "missing_program") },
    { key: "vigil", label: "firewall.chipVigil", test: (r) => r.vigil },
    { key: "in", label: "firewall.inbound", test: (r) => r.direction === "in" },
    { key: "out", label: "firewall.outbound", test: (r) => r.direction === "out" },
    { key: "disabled", label: "firewall.chipDisabled", test: (r) => !r.enabled },
  ];
  const PROFILE: Record<string, Key> = {
    domain: "firewall.profileDomain", private: "firewall.profilePrivate", public: "firewall.profilePublic",
  };
  const PROFILE_SHORT: Record<string, Key> = {
    domain: "firewall.pDomain", private: "firewall.pPrivate", public: "firewall.pPublic",
  };
  // Port -> the remote-access service it belongs to (product names stay as they are).
  const REMOTE: Record<number, string> = { 22: "SSH", 23: "Telnet", 5900: "VNC", 5985: "WinRM", 5986: "WinRM" };

  // `row` tells rules apart in the table, even the ones that share a key.
  type Row = FirewallRule & { row: string };
  let rules = $state<Row[]>([]);
  let profiles = $state<FirewallProfile[]>([]);
  let summary = $state<FirewallSummary | null>(null);
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
      const view = await api.firewallList();
      rules = view.rules.map((r, i) => ({ ...r, row: r.duplicate ? `${r.key}#${i}` : r.key }));
      profiles = view.profiles;
      summary = view.summary;
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => void load());

  function has(rule: FirewallRule, code: FirewallFlag["code"]): boolean {
    return rule.flags.some((f) => f.code === code);
  }
  const anyValue = (value: string) => !value.trim() || value.trim() === "*" || value.trim().toLowerCase() === "any";

  function flagText(flag: FirewallFlag): string {
    switch (flag.code) {
      case "open_public":
        return t("firewall.flagOpen");
      case "remote_access":
        return t("firewall.flagRemote", { port: String(flag.port), service: flag.port === 3389 ? t("firewall.svcRdp") : REMOTE[flag.port] ?? "" });
      case "writable_program":
        return t("firewall.flagWritable");
      default:
        return t("firewall.flagMissing");
    }
  }

  const programText = (r: FirewallRule) =>
    r.program ? r.program : r.service ? t("firewall.service", { name: r.service }) : t("firewall.allPrograms");
  const directionText = (r: FirewallRule) => t(r.direction === "out" ? "firewall.outbound" : "firewall.inbound");
  const actionText = (r: FirewallRule) => t(r.action === "allow" ? "firewall.allow" : "firewall.block");
  function portsText(r: FirewallRule): string {
    const ports = r.direction === "out" ? r.remotePorts : r.localPorts;
    if (anyValue(ports)) return r.protocol === 256 ? t("firewall.any") : r.protocolName;
    return `${r.protocolName} ${ports.split(",").map((p) => p.trim()).join(", ")}`;
  }
  const addressText = (value: string) => (anyValue(value) ? t("firewall.any") : value.split(",").join(", "));
  const profilesText = (r: FirewallRule) =>
    r.profiles.length >= 3 ? t("firewall.allProfiles") : r.profiles.map((p) => t(PROFILE_SHORT[p] ?? "firewall.any")).join(", ");
  const enabledText = (r: FirewallRule) => t(r.enabled ? "common.yes" : "common.no");

  function sortBy(key: SortKey): void {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      ascending = true;
    }
  }

  const text = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" });
  function compare(a: FirewallRule, b: FirewallRule): number {
    switch (sortKey) {
      case "program":
        return text(programText(a), programText(b));
      case "direction":
        return text(a.direction, b.direction);
      case "action":
        return text(a.action, b.action);
      case "ports":
        return text(portsText(a), portsText(b));
      case "remote":
        return text(addressText(a.remoteAddresses), addressText(b.remoteAddresses));
      case "profiles":
        return text(profilesText(a), profilesText(b));
      case "enabled":
        return Number(b.enabled) - Number(a.enabled);
      default:
        // Rules that need a look come first, then by name.
        return Number(b.flags.some((f) => f.warn)) - Number(a.flags.some((f) => f.warn)) || text(a.name, b.name);
    }
  }

  const counts = $derived(Object.fromEntries(FILTERS.map((f) => [f.key, rules.filter(f.test).length])) as Record<Filter, number>);
  const shown = $derived.by(() => {
    const test = FILTERS.find((f) => f.key === filter)?.test ?? (() => true);
    const words = search.toLowerCase().split(/\s+/).filter(Boolean);
    const list = rules.filter((r) => {
      if (!test(r)) return false;
      if (!words.length) return true;
      const haystack =
        `${r.name} ${r.group} ${r.program} ${r.service} ${r.localPorts} ${r.remotePorts} ${r.remoteAddresses} ${r.description}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    return list.sort((a, b) => (ascending ? 1 : -1) * compare(a, b) || text(a.name, b.name) || text(a.row, b.row));
  });
  const current = $derived(rules.find((r) => r.row === selected) ?? null);

  // Rust re-checks everything against a fresh read; these only keep pointless buttons off.
  const actionable = $derived(!!current && elevated && !current.duplicate && !report.busy);
  const canEnable = $derived(actionable && !current?.enabled);
  const canDisable = $derived(actionable && !!current?.enabled);
  const canDelete = $derived(actionable && !current?.builtin);
  const location = $derived(current && /^[a-z]:\\/i.test(current.program) && current.programExists ? current.program : "");
  const notes = $derived.by(() => {
    if (!current) return [] as string[];
    const list: string[] = [];
    if (current.duplicate) list.push(t("firewall.duplicateNote"));
    if (current.builtin) list.push(t("firewall.builtinNote"));
    if (current.appPackage) list.push(t("firewall.packageNote"));
    if (current.vigil) list.push(t("firewall.vigilNote"));
    if (!elevated) list.push(t("firewall.adminNote"));
    return list;
  });

  async function run(op: "enable" | "disable" | "delete"): Promise<void> {
    if (!current) return;
    const key = current.key;
    const outcome = await act({ kind: "firewall-rule", op, key });
    if (outcome && !outcome.cancelled) {
      await load();
      selected = rules.some((r) => r.row === key) ? key : null;
    }
  }
</script>

<div class="page">
  <div class="searchbar">
    <label class="search">
      <i class="icon">{""}</i>
      <input type="search" placeholder={t("firewall.search")} aria-label={t("firewall.search")} bind:value={search} />
    </label>
  </div>

  <div class="title-row">
    <h2>{t("page.firewall")}</h2>
    <span class="grow"></span>
    <div class="commandbar">
      <button class="command" disabled={!canEnable} onclick={() => run("enable")}><i class="icon">{""}</i>{t("firewall.enable")}</button>
      <button class="command" disabled={!canDisable} onclick={() => run("disable")}><i class="icon">{""}</i>{t("firewall.disable")}</button>
      <button class="command" disabled={!canDelete} onclick={() => run("delete")}><i class="icon">{""}</i>{t("firewall.delete")}</button>
      <span class="sep"></span>
      <button class="command" disabled={!location} onclick={() => act({ kind: "shell", op: "location", path: location })}>
        <i class="icon">{""}</i>{t("proc.location")}</button>
      <button class="command" onclick={() => act({ kind: "shell", op: "console", name: "wf.msc" })}>
        <i class="icon">{""}</i>{t("firewall.openConsole")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{t("firewall.note")}</p>

  {#if profiles.length}
    <div class="profiles">
      {#each profiles as p (p.name)}
        <div class="panel profile">
          <div class="profile-head">
            <span class="profile-name">{t(PROFILE[p.name] ?? "firewall.profilePublic")}</span>
            {#if p.active}<span class="faint connected">{t("firewall.connected")}</span>{/if}
          </div>
          <span class="state" style:color={p.enabled ? "var(--ok)" : "var(--bad)"}>
            <i class="icon">{p.enabled ? "" : ""}</i>{t(p.enabled ? "firewall.profileOn" : "firewall.profileOff")}
          </span>
          <span class="faint">
            {#if p.blockAllInbound}{t("firewall.blockAll")}{:else}<span style:color={p.enabled && p.defaultInbound === "allow" ? "var(--warn)" : null}>{t("firewall.incoming", { action: t(p.defaultInbound === "allow" ? "firewall.allow" : "firewall.block") })}</span>{/if}
            · {t("firewall.outgoing", { action: t(p.defaultOutbound === "allow" ? "firewall.allow" : "firewall.block") })}
          </span>
        </div>
      {/each}
    </div>
  {/if}

  <div class="filters" role="toolbar" aria-label={t("firewall.filters")}>
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
    {#each shown as r (r.row)}
      {@const warned = r.flags.filter((f) => f.warn)}
      <button class="row" class:sel={selected === r.row} class:off={!r.enabled} onclick={() => (selected = r.row)}>
        <span class="cell name" title={r.name}>
          {#if warned.length}
            <i class="icon mark" style:color="var(--warn)" title={warned.map(flagText).join("\n")}>{""}</i>
          {:else if r.flags.length}
            <i class="icon mark" style:color="var(--ink3)" title={r.flags.map(flagText).join("\n")}>{""}</i>
          {:else}
            <span class="mark"></span>
          {/if}
          <span class="text">{r.name}</span>
        </span>
        <span class="cell" title={programText(r)}>{programText(r)}</span>
        <span class="cell">{directionText(r)}</span>
        <span class="cell">{actionText(r)}</span>
        <span class="cell" title={portsText(r)}>{portsText(r)}</span>
        <span class="cell" title={addressText(r.remoteAddresses)}>{addressText(r.remoteAddresses)}</span>
        <span class="cell">{profilesText(r)}</span>
        <span class="cell">{enabledText(r)}</span>
      </button>
    {:else}
      <p class="faint empty">{loading ? t("common.reading") : t("firewall.empty")}</p>
    {/each}
  </div>

  {#if current}
    <section class="panel info" aria-live="polite">
      <div class="info-head">
        <h3 class="selectable">{current.name}</h3>
        <span class="faint">{directionText(current)} · {actionText(current)} · {t(current.enabled ? "common.enabled" : "common.disabled")}</span>
      </div>
      {#each current.flags as f (f.code)}
        <span class="reason" style:color={f.warn ? "var(--warn)" : "var(--ink2)"}>
          <i class="icon">{f.warn ? "" : ""}</i>{flagText(f)}
        </span>
      {/each}
      {#if current.description}<p class="selectable description">{current.description}</p>{/if}
      <div class="grid">
        <span class="faint">{t("firewall.program")}</span>
        <span class="mono selectable wide">{current.program || t("firewall.allPrograms")}{current.program && !current.programExists ? ` · ${t("firewall.notFound")}` : ""}</span>
        <span class="faint">{t("firewall.group")}</span><span class="selectable">{current.group || "—"}</span>
        {#if current.service}
          <span class="faint">{t("firewall.serviceLabel")}</span><span class="mono selectable">{current.service}</span>
        {/if}
        <span class="faint">{t("firewall.protocol")}</span><span>{current.protocol === 256 ? t("firewall.any") : current.protocolName}</span>
        <span class="faint">{t("firewall.localPorts")}</span><span class="mono selectable">{addressText(current.localPorts)}</span>
        <span class="faint">{t("firewall.remotePorts")}</span><span class="mono selectable">{addressText(current.remotePorts)}</span>
        <span class="faint">{t("firewall.localAddresses")}</span><span class="mono selectable">{addressText(current.localAddresses)}</span>
        <span class="faint">{t("firewall.remoteAddresses")}</span><span class="mono selectable">{addressText(current.remoteAddresses)}</span>
        <span class="faint">{t("firewall.colProfiles")}</span><span>{profilesText(current)}</span>
        <span class="faint">{t("firewall.interfaces")}</span><span>{anyValue(current.interfaceTypes) || current.interfaceTypes === "All" ? t("firewall.any") : current.interfaceTypes}</span>
        {#if current.edgeTraversal}
          <span class="faint">{t("firewall.edge")}</span><span>{t("firewall.edgeOn")}</span>
        {/if}
      </div>
      {#each notes as note (note)}<p class="faint">{note}</p>{/each}
    </section>
  {/if}

  <div class="faint footer">
    {error || t("firewall.summary", { shown: shown.length, total: rules.length, flagged: summary?.flagged ?? 0, missing: summary?.missing ?? 0 })}
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

  .profiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; flex: none; }
  .profile { display: flex; flex-direction: column; gap: 4px; padding: 10px 14px; font-size: 13px; }
  .profile-head { display: flex; align-items: baseline; gap: 8px; }
  .profile-name { font-weight: 600; }
  .connected { font-size: 12px; }
  .state { display: inline-flex; align-items: center; gap: 6px; }
  .state .icon { font-size: 12px; }

  .filters { display: flex; flex-wrap: wrap; gap: 6px; flex: none; }
  .num { color: var(--ink3); margin-left: 2px; }

  /* Task Manager's table: a plain header with column rules, flat rows, hover and selection as overlays. */
  .table {
    --cols: minmax(240px, 2.2fr) minmax(200px, 2fr) 90px 70px minmax(110px, 1fr) minmax(120px, 1fr) 110px 70px;
    flex: 1; min-height: 120px; overflow: auto; border-top: 1px solid var(--rule);
  }
  .row { display: grid; grid-template-columns: var(--cols); min-width: 1010px; align-items: stretch; font-size: 13px; }
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
  .mark { flex: none; width: 14px; font-size: 13px; text-align: center; }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; flex: none; max-height: 240px; overflow: auto; }
  .info p { margin: 0; }
  .info-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .reason { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
  .reason .icon { font-size: 13px; }
  .description { font-size: 13px; color: var(--ink2); }
  .grid { display: grid; grid-template-columns: 130px minmax(0, 1fr) 130px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .wide { grid-column: 2 / -1; }
  @media (max-width: 1100px) {
    .grid { grid-template-columns: 130px minmax(0, 1fr); }
  }
  .grid .mono { overflow-wrap: anywhere; }
  .footer { padding-left: 4px; }
</style>
