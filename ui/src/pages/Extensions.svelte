<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { locale, t, type Key } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type {
    BrowserExtension, BrowserExtensions, BrowserPolicy, BrowserPolicyKind, ExtensionDisableReason, ExtensionFlag, ExtensionSource,
  } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  type View = "extensions" | "policies";
  type SortKey = "name" | "browser" | "profile" | "version" | "state" | "source";
  const COLUMNS: { key: SortKey; label: Key }[] = [
    { key: "name", label: "ext.colName" },
    { key: "browser", label: "ext.colBrowser" },
    { key: "profile", label: "ext.colProfile" },
    { key: "version", label: "ext.colVersion" },
    { key: "state", label: "ext.colState" },
    { key: "source", label: "ext.colSource" },
  ];
  type Filter = "all" | "allSites" | "outside" | "policy" | "disabled" | "mv2";
  const FILTERS: { key: Filter; label: Key; test: (e: BrowserExtension) => boolean }[] = [
    { key: "all", label: "ext.chipAll", test: () => true },
    { key: "allSites", label: "ext.chipAllSites", test: (e) => e.flags.includes("all_sites") },
    { key: "outside", label: "ext.chipOutside", test: (e) => ["outside_store", "unpacked", "not_signed"].some((f) => e.flags.includes(f as ExtensionFlag)) },
    { key: "policy", label: "ext.chipPolicy", test: (e) => e.flags.includes("policy") },
    { key: "disabled", label: "ext.chipDisabled", test: (e) => !e.enabled },
    { key: "mv2", label: "ext.chipMv2", test: (e) => e.flags.includes("mv2") },
  ];
  // Warnings first; the others say what an extension may do, which many good ones need.
  const WARN_FLAGS: ExtensionFlag[] = [
    "store_flagged", "policy", "outside_store", "unpacked", "not_signed", "delisted", "native", "debugger", "proxy", "management",
  ];
  const FLAG: Record<ExtensionFlag, { long: Key; short: Key }> = {
    all_sites: { long: "ext.flag.allSites", short: "ext.short.allSites" },
    history: { long: "ext.flag.history", short: "ext.short.history" },
    tabs: { long: "ext.flag.tabs", short: "ext.short.tabs" },
    cookies: { long: "ext.flag.cookies", short: "ext.short.cookies" },
    web_request: { long: "ext.flag.webRequest", short: "ext.short.webRequest" },
    native: { long: "ext.flag.native", short: "ext.short.native" },
    debugger: { long: "ext.flag.debugger", short: "ext.short.debugger" },
    proxy: { long: "ext.flag.proxy", short: "ext.short.proxy" },
    management: { long: "ext.flag.management", short: "ext.short.management" },
    policy: { long: "ext.flag.policy", short: "ext.short.policy" },
    outside_store: { long: "ext.flag.outsideStore", short: "ext.short.outsideStore" },
    external: { long: "ext.flag.external", short: "ext.short.external" },
    unpacked: { long: "ext.flag.unpacked", short: "ext.short.unpacked" },
    mv2: { long: "ext.flag.mv2", short: "ext.short.mv2" },
    not_signed: { long: "ext.flag.notSigned", short: "ext.short.notSigned" },
    store_flagged: { long: "ext.flag.storeFlagged", short: "ext.short.storeFlagged" },
    delisted: { long: "ext.flag.delisted", short: "ext.short.delisted" },
  };
  const SOURCE: Record<ExtensionSource, Key> = {
    store: "ext.source.store", outside_store: "ext.source.outsideStore", external: "ext.source.external", policy: "ext.source.policy",
    unpacked: "ext.source.unpacked", component: "ext.source.component", unknown: "ext.source.unknown",
  };
  const REASON: Record<ExtensionDisableReason, Key> = {
    user: "ext.reason.user", permissions: "ext.reason.permissions", not_verified: "ext.reason.notVerified", flagged: "ext.reason.flagged",
    corrupted: "ext.reason.corrupted", sideload: "ext.reason.sideload", external: "ext.reason.external", policy: "ext.reason.policy",
    unsupported_manifest: "ext.reason.unsupportedManifest", incompatible: "ext.reason.incompatible", other: "ext.reason.other",
  };
  const KIND: Record<BrowserPolicyKind, Key> = {
    force_install: "ext.kind.forceInstall", extension_settings: "ext.kind.extensionSettings", install_sources: "ext.kind.installSources",
    allow: "ext.kind.allow", block: "ext.kind.block", search: "ext.kind.search", homepage: "ext.kind.homepage", startup: "ext.kind.startup",
    new_tab: "ext.kind.newTab", proxy: "ext.kind.proxy", devtools: "ext.kind.devtools", safe_browsing: "ext.kind.safeBrowsing", other: "ext.kind.other",
  };
  const SCOPE: Record<BrowserPolicy["scope"], Key> = { machine: "ext.scopeMachine", user: "ext.scopeUser", file: "ext.scopeFile" };
  /** API permissions explained in plain words; the others are listed as they are. */
  const PERMISSION: Record<string, Key> = {
    tabs: "ext.perm.tabs", history: "ext.perm.history", cookies: "ext.perm.cookies", webRequest: "ext.perm.webRequest",
    webRequestBlocking: "ext.perm.webRequestBlocking", declarativeNetRequest: "ext.perm.declarativeNetRequest",
    nativeMessaging: "ext.perm.nativeMessaging", debugger: "ext.perm.debugger", proxy: "ext.perm.proxy", management: "ext.perm.management",
    downloads: "ext.perm.downloads", clipboardRead: "ext.perm.clipboardRead", privacy: "ext.perm.privacy", scripting: "ext.perm.scripting",
    webNavigation: "ext.perm.webNavigation", topSites: "ext.perm.topSites", bookmarks: "ext.perm.bookmarks", storage: "ext.perm.storage",
  };

  let view = $state<View>("extensions");
  let data = $state<BrowserExtensions | null>(null);
  let icons = $state<Record<string, string>>({});
  let loading = $state(false);
  let error = $state("");
  let search = $state("");
  let filter = $state<Filter>("all");
  let where = $state("");
  let showComponents = $state(false);
  let selected = $state<string | null>(null);
  let selectedPolicy = $state<string | null>(null);
  let sortKey = $state<SortKey>("name");
  let ascending = $state(true);

  async function load(): Promise<void> {
    loading = true;
    try {
      data = await api.extensionsList();
      error = "";
      const keys = data.extensions.filter((e) => e.icon).map((e) => e.key);
      icons = keys.length ? await api.extensionIcons(keys) : {};
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => void load());

  const all = $derived(data?.extensions ?? []);
  const policies = $derived(data?.policies ?? []);
  const visible = $derived(all.filter((e) => showComponents || !e.component));
  const components = $derived(all.filter((e) => e.component).length);

  // ------------------------------------------------------------------ where: browser or profile
  const profileKey = (e: BrowserExtension) => `p:${e.browser}|${e.account}|${e.profileDir}`;
  const profileLabel = (e: BrowserExtension) => [e.profile, e.account].filter(Boolean).join(" · ");
  const places = $derived.by(() => {
    const out: { value: string; label: string }[] = [];
    for (const browser of [...new Set(visible.map((e) => e.browser))].sort()) {
      out.push({ value: `b:${browser}`, label: browser });
      const seen = new Map<string, string>();
      for (const e of visible.filter((x) => x.browser === browser)) seen.set(profileKey(e), profileLabel(e));
      if (seen.size > 1) for (const [value, label] of seen) out.push({ value, label: `${browser} · ${label}` });
    }
    return out;
  });
  const inPlace = (e: BrowserExtension) => !where || (where.startsWith("b:") ? e.browser === where.slice(2) : profileKey(e) === where);
  const placeBrowser = $derived(where ? where.slice(2).split("|")[0] : "");

  // ------------------------------------------------------------------ texts
  const warnFlags = (e: BrowserExtension) => e.flags.filter((f) => WARN_FLAGS.includes(f));
  const orderedFlags = (e: BrowserExtension) => [...warnFlags(e), ...e.flags.filter((f) => !WARN_FLAGS.includes(f))];
  const flagsText = (e: BrowserExtension) => orderedFlags(e).map((f) => t(FLAG[f].short)).join(", ");
  const stateText = (e: BrowserExtension) => (e.enabled ? t("common.on") : t("common.off"));
  const dateText = (ms: number) => (ms ? new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(new Date(ms)) : "—");
  const permissionText = (p: string) => (PERMISSION[p] ? `${t(PERMISSION[p])} (${p})` : p);

  // ------------------------------------------------------------------ table
  function sortBy(key: SortKey): void {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      ascending = true;
    }
  }
  const text = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
  function compare(a: BrowserExtension, b: BrowserExtension): number {
    switch (sortKey) {
      case "browser":
        return text(a.browser, b.browser);
      case "profile":
        return text(profileLabel(a), profileLabel(b));
      case "version":
        return text(a.version, b.version);
      case "state":
        return Number(b.enabled) - Number(a.enabled);
      case "source":
        return text(t(SOURCE[a.source]), t(SOURCE[b.source]));
      default:
        return text(a.name, b.name);
    }
  }

  const placed = $derived(visible.filter(inPlace));
  const counts = $derived(Object.fromEntries(FILTERS.map((f) => [f.key, placed.filter(f.test).length])) as Record<Filter, number>);
  const shown = $derived.by(() => {
    const test = FILTERS.find((f) => f.key === filter)?.test ?? (() => true);
    const words = search.toLowerCase().split(/\s+/).filter(Boolean);
    const list = placed.filter((e) => {
      if (!test(e)) return false;
      if (!words.length) return true;
      const haystack = `${e.name} ${e.id} ${e.browser} ${e.profile} ${e.description} ${e.account}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    return list.sort((a, b) => (ascending ? 1 : -1) * compare(a, b) || text(a.name, b.name) || text(a.key, b.key));
  });
  const current = $derived(all.find((e) => e.key === selected) ?? null);
  const forcedBy = $derived(current ? policies.filter((p) => p.browser === current.browser && p.extensionIds.some((id) => id.toLowerCase() === current.id.toLowerCase())) : []);

  // ------------------------------------------------------------------ policies
  const shownPolicies = $derived.by(() => {
    const words = search.toLowerCase().split(/\s+/).filter(Boolean);
    return policies
      .filter((p) => !placeBrowser || p.browser === placeBrowser)
      .filter((p) => !words.length || words.every((w) => `${p.name} ${p.data} ${p.browser} ${p.key}`.toLowerCase().includes(w)))
      .sort((a, b) => Number(b.flagged) - Number(a.flagged) || text(a.browser, b.browser) || text(a.name, b.name) || text(a.value, b.value));
  });
  const flaggedPolicies = $derived(policies.filter((p) => p.flagged).length);
  const currentPolicy = $derived(policies.find((p) => p.id === selectedPolicy) ?? null);
  const namesOf = (ids: string[]) => ids.map((id) => all.find((e) => e.id.toLowerCase() === id.toLowerCase())?.name ?? id);

  // Rust reads everything again and re-checks it; these only keep pointless buttons off.
  const canPage = $derived(view === "extensions" && !!(current ? !current.account : placeBrowser));
  const canFolder = $derived(view === "extensions" && !!current?.path && !!current?.pathExists);
  const canRemove = $derived(
    view === "policies" && !!currentPolicy?.removable && currentPolicy.scope !== "file" && (currentPolicy.scope === "user" || elevated) && !report.busy,
  );

  function openPage(): void {
    if (current) void act({ kind: "extension", op: "page", key: current.key });
    else if (placeBrowser) void act({ kind: "extension", op: "page", browser: placeBrowser });
  }
  async function removePolicy(): Promise<void> {
    if (!currentPolicy) return;
    const outcome = await act({ kind: "browser-policy", op: "remove", id: currentPolicy.id });
    if (outcome && !outcome.cancelled) {
      await load();
      if (!policies.some((p) => p.id === selectedPolicy)) selectedPolicy = null;
    }
  }
</script>

<div class="page">
  <div class="searchbar">
    <label class="search">
      <i class="icon">{"\uE721"}</i>
      <input type="search" placeholder={t("ext.search")} aria-label={t("ext.search")} bind:value={search} />
    </label>
  </div>

  <div class="title-row">
    <h2>{t("page.extensions")}</h2>
    <div class="segmented" role="radiogroup" aria-label={t("page.extensions")}>
      <button role="radio" aria-checked={view === "extensions"} class:on={view === "extensions"} onclick={() => (view = "extensions")}>
        {t("ext.viewExtensions")} <span class="num">{visible.length}</span>
      </button>
      <button role="radio" aria-checked={view === "policies"} class:on={view === "policies"} onclick={() => (view = "policies")}>
        {t("ext.viewPolicies")} <span class="num" class:warn={flaggedPolicies > 0}>{policies.length}</span>
      </button>
    </div>
    <span class="grow"></span>
    <div class="commandbar">
      {#if view === "extensions"}
        <button class="command" disabled={!canPage} onclick={openPage}><i class="icon">{"\uE8A7"}</i>{t("ext.openPage")}</button>
        <button class="command" disabled={!canFolder} onclick={() => current && act({ kind: "extension", op: "folder", key: current.key })}>
          <i class="icon">{"\uE838"}</i>{t("ext.openFolder")}</button>
      {:else}
        <button class="command" disabled={!canRemove} onclick={removePolicy}><i class="icon">{"\uE74D"}</i>{t("ext.removePolicy")}</button>
      {/if}
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{"\uE72C"}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{view === "extensions" ? t("ext.note") : t("ext.policyNote")}</p>

  <div class="filters" role="toolbar" aria-label={t("ext.filters")}>
    {#if places.length > 1}
      <select bind:value={where} aria-label={t("ext.where")}>
        <option value="">{t("ext.everywhere")}</option>
        {#each places as place (place.value)}<option value={place.value}>{place.label}</option>{/each}
      </select>
    {/if}
    {#if view === "extensions"}
      {#each FILTERS as f (f.key)}
        {#if f.key === "all" || counts[f.key] > 0}
          <button class="chip" class:on={filter === f.key} aria-pressed={filter === f.key} onclick={() => (filter = f.key)}>
            {t(f.label)} <span class="num">{counts[f.key]}</span>
          </button>
        {/if}
      {/each}
      {#if components > 0}
        <label class="check"><input type="checkbox" bind:checked={showComponents} />{t("ext.showComponents", { count: components })}</label>
      {/if}
    {/if}
  </div>

  {#if view === "extensions"}
    <div class="table">
      <div class="row head">
        {#each COLUMNS as column (column.key)}
          <button class="th" class:sorted={sortKey === column.key} aria-pressed={sortKey === column.key} onclick={() => sortBy(column.key)}>
            {#if sortKey === column.key}<i class="icon caret">{ascending ? "\uE70E" : "\uE70D"}</i>{/if}
            <span class="label">{t(column.label)}</span>
          </button>
        {/each}
        <span class="th static"><span class="label">{t("ext.colFlags")}</span></span>
      </div>
      {#each shown as e (e.key)}
        {@const warned = warnFlags(e)}
        <button class="row" class:sel={selected === e.key} class:off={!e.enabled} onclick={() => (selected = e.key)}>
          <span class="cell name" title={e.name}>
            {#if icons[e.key]}<img class="ext-icon" src={icons[e.key]} alt="" />{:else}<span class="ext-icon tile" aria-hidden="true">{e.name.charAt(0)}</span>{/if}
            <span class="text">{e.name}</span>
            {#if warned.length}
              <i class="icon mark" style:color="var(--warn)" title={warned.map((f) => t(FLAG[f].long)).join("\n")}>{"\uE7BA"}</i>
            {/if}
          </span>
          <span class="cell">{e.browser}</span>
          <span class="cell" title={profileLabel(e)}>{profileLabel(e)}</span>
          <span class="cell" title={e.version}>{e.version}</span>
          <span class="cell">{stateText(e)}</span>
          <span class="cell" title={t(SOURCE[e.source])}>{t(SOURCE[e.source])}</span>
          <span class="cell" class:warn={warned.length > 0} title={flagsText(e)}>{flagsText(e)}</span>
        </button>
      {:else}
        <p class="faint empty">{loading && !data ? t("common.reading") : all.length ? t("ext.empty") : t("ext.noBrowsers")}</p>
      {/each}
    </div>

    {#if current}
      {@const ordered = orderedFlags(current)}
      <section class="panel info" aria-live="polite">
        <div class="info-head">
          <h3 class="selectable">{current.name}</h3>
          <span class="faint">{[current.version, `${current.browser} · ${profileLabel(current)}`].filter(Boolean).join(" · ")}</span>
        </div>
        {#if current.description}<p class="selectable">{current.description}</p>{/if}
        {#each ordered as f (f)}
          {@const warn = WARN_FLAGS.includes(f)}
          <span class="reason" style:color={warn ? "var(--warn)" : "var(--ink2)"}><i class="icon">{warn ? "\uE7BA" : "\uE946"}</i>{t(FLAG[f].long)}</span>
        {/each}
        <div class="grid">
          <span class="faint">{t("ext.colState")}</span>
          <span>
            {#if current.enabled}{t("common.on")}
            {:else if current.disableReasons.length}{current.disableReasons.map((r) => t(REASON[r])).join("; ")}
            {:else}{t("common.off")}{/if}
          </span>
          <span class="faint">{t("ext.installed")}</span><span>{dateText(current.installedMs)}</span>
          <span class="faint">{t("ext.colSource")}</span><span>{t(SOURCE[current.source])}</span>
          {#if forcedBy.length}
            <span class="faint">{t("ext.forcedBy")}</span>
            <span class="mono selectable">{#each forcedBy as p (p.id)}<span class="line">{`${p.key}\\${p.value}`}</span>{/each}</span>
          {/if}
          <span class="faint">{t("ext.id")}</span><span class="mono selectable">{current.id}</span>
          {#if current.updateUrl}<span class="faint">{t("ext.updateUrl")}</span><span class="mono selectable">{current.updateUrl}</span>{/if}
          {#if current.manifestVersion}<span class="faint">{t("ext.manifest")}</span><span>{current.manifestVersion}</span>{/if}
          <span class="faint">{t("ext.permissions")}</span>
          <span>{#each current.permissions as p (p)}<span class="line">{permissionText(p)}</span>{:else}—{/each}</span>
          <span class="faint">{t("ext.sites")}</span>
          <span class="mono selectable">{#each current.hosts as h (h)}<span class="line">{h}</span>{:else}—{/each}</span>
          <span class="faint">{t("ext.folder")}</span>
          <span class="mono selectable">{current.path ? (current.pathExists ? current.path : t("ext.missing", { path: current.path })) : "—"}</span>
        </div>
        {#if current.account}<p class="faint">{t("ext.otherAccount", { account: current.account })}</p>{/if}
        {#if current.flags.includes("policy")}<p class="faint">{t("ext.policyForced")}</p>{/if}
        {#if !current.component && !current.account}<p class="faint">{t("ext.removeHint", { browser: current.browser })}</p>{/if}
      </section>
    {/if}

    <div class="faint footer">
      {error || t("ext.summary", { shown: shown.length, total: visible.length, profiles: data?.browsers.reduce((n, b) => n + b.profiles, 0) ?? 0 })}
      {#if data && !data.otherAccounts && !elevated} · {t("ext.adminForOthers")}{/if}
    </div>
  {:else}
    <div class="table policies">
      <div class="row head">
        <span class="th static"><span class="label">{t("ext.colPolicy")}</span></span>
        <span class="th static"><span class="label">{t("ext.colBrowser")}</span></span>
        <span class="th static"><span class="label">{t("ext.colAppliesTo")}</span></span>
        <span class="th static"><span class="label">{t("ext.colKind")}</span></span>
        <span class="th static"><span class="label">{t("ext.colValue")}</span></span>
      </div>
      {#each shownPolicies as p (p.id)}
        <button class="row" class:sel={selectedPolicy === p.id} onclick={() => (selectedPolicy = p.id)}>
          <span class="cell name" title={p.name}>
            <span class="text">{p.name}</span>
            {#if p.flagged}<i class="icon mark" style:color="var(--warn)" title={t("ext.policyFlagged")}>{"\uE7BA"}</i>{/if}
          </span>
          <span class="cell">{p.browser}</span>
          <span class="cell">{t(SCOPE[p.scope])}</span>
          <span class="cell">{t(KIND[p.kind])}</span>
          <span class="cell mono" title={p.data}>{p.data}</span>
        </button>
      {:else}
        <p class="faint empty">{loading && !data ? t("common.reading") : t("ext.noPolicies")}</p>
      {/each}
    </div>

    {#if currentPolicy}
      <section class="panel info" aria-live="polite">
        <div class="info-head">
          <h3 class="selectable">{currentPolicy.name}</h3>
          <span class="faint">{currentPolicy.browser} · {t(SCOPE[currentPolicy.scope])} · {t(KIND[currentPolicy.kind])}</span>
        </div>
        {#if currentPolicy.flagged}
          <span class="reason" style:color="var(--warn)"><i class="icon">{"\uE7BA"}</i>{t("ext.policyFlagged")}</span>
        {/if}
        <div class="grid">
          <span class="faint">{t("ext.colValue")}</span><span class="mono selectable cmd">{currentPolicy.data || "—"}</span>
          {#if currentPolicy.extensionIds.length}
            <span class="faint">{t("ext.forces")}</span><span class="selectable">{namesOf(currentPolicy.extensionIds).join(", ")}</span>
          {/if}
          <span class="faint">{currentPolicy.scope === "file" ? t("ext.file") : t("ext.registry")}</span>
          <span class="mono selectable">{currentPolicy.scope === "file" ? currentPolicy.key : `${currentPolicy.key}\\${currentPolicy.value}`}</span>
        </div>
        {#if currentPolicy.scope === "file"}<p class="faint">{t("ext.fileNote")}</p>
        {:else if !currentPolicy.removable}<p class="faint">{t("ext.keepNote")}</p>
        {:else if currentPolicy.scope === "machine" && !elevated}<p class="faint">{t("ext.adminNote")}</p>{/if}
      </section>
    {/if}

    <div class="faint footer">{error || t("ext.policySummary", { total: policies.length, flagged: flaggedPolicies })}</div>
  {/if}
</div>

<style>
  .page { gap: 8px; padding: 10px 20px 12px; }
  .searchbar { display: flex; justify-content: center; padding-bottom: 2px; }
  .search { position: relative; display: flex; align-items: center; width: min(640px, 100%); }
  .search .icon { position: absolute; left: 12px; font-size: 14px; color: var(--ink2); pointer-events: none; }
  .search input { width: 100%; min-width: 0; padding-left: 36px; }
  .title-row { display: flex; align-items: center; gap: 12px; min-height: 40px; flex-wrap: wrap; }
  .title-row h2 { padding-left: 4px; }
  .grow { flex: 1; }
  .lead { margin: 0; padding-left: 4px; }

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

  .filters { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; flex: none; }
  .filters select { min-width: 180px; max-width: 320px; }
  .check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--ink2); margin-left: 6px; }
  .num { color: var(--ink3); margin-left: 2px; }
  .num.warn { color: var(--warn); }

  /* Task Manager's table: a plain header with column rules, flat rows, hover and selection as overlays. */
  .table {
    --cols: minmax(240px, 2.2fr) 90px minmax(110px, 1fr) minmax(80px, 0.6fr) 70px minmax(120px, 0.9fr) minmax(160px, 1.6fr);
    flex: 1; min-height: 120px; overflow: auto; border-top: 1px solid var(--rule);
  }
  .table.policies { --cols: minmax(220px, 1.6fr) 90px 110px minmax(140px, 1fr) minmax(220px, 2fr); }
  .row { display: grid; grid-template-columns: var(--cols); min-width: 900px; align-items: stretch; font-size: 13px; }
  .head { position: sticky; top: 0; z-index: 1; background: var(--layer); border-bottom: 1px solid var(--rule); }
  .th {
    position: relative; display: flex; align-items: flex-end; min-height: 0; height: 40px; padding: 4px 8px 6px; border: 0;
    border-radius: 0; background: transparent; color: var(--ink2); font-size: 12px; line-height: 16px; font-weight: 400;
    text-align: left; white-space: nowrap; overflow: hidden;
  }
  .th + .th { border-left: 1px solid var(--rule); }
  button.th:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  button.th:active:not(:disabled) { background: var(--pressed); }
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
  .cell.warn { color: var(--warn); }
  button.row.off .cell.warn { color: var(--warn); }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .ext-icon { flex: none; width: 16px; height: 16px; }
  .tile {
    display: inline-flex; align-items: center; justify-content: center; border-radius: 3px; background: var(--control);
    border: 1px solid var(--control-stroke); color: var(--ink2); font-size: 10px; font-weight: 600; line-height: 1;
  }
  .mark { flex: none; font-size: 13px; }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .info { padding: 12px 16px; display: flex; flex-direction: column; gap: 8px; flex: none; max-height: 320px; overflow: auto; }
  .info p { margin: 0; }
  .info-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .reason { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
  .reason .icon { font-size: 13px; }
  .grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .mono { overflow-wrap: anywhere; }
  .line { display: block; }
  .cmd { white-space: pre-wrap; word-break: break-all; max-height: 4.8em; overflow: auto; }
  .footer { padding-left: 4px; }
</style>
