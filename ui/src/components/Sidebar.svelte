<script module lang="ts">
export interface PageDef {
  key: string;
  title: string;
  icon: string;
  section: string;
  count?: string;
  alert?: boolean;
}

export interface MenuEntry {
  label: string;
  run?: () => void;
  separator?: boolean;
}
</script>

<script lang="ts">
  import { t } from "../lib/i18n/index.svelte";
  import type { AppInfo } from "../lib/types";

  // A Windows 11 NavigationView (left mode): hamburger, items with a selection pill, section headers,
  // footer items. The hamburger collapses it to an icon rail; the choice is remembered on this PC.
  let {
    pages,
    current,
    info,
    scanning,
    lastScan,
    menu,
    onnavigate,
    onelevate,
    onscan,
    onsettings,
  }: {
    pages: PageDef[];
    current: string;
    info: AppInfo | null;
    scanning: boolean;
    lastScan: string;
    menu: MenuEntry[];
    onnavigate: (key: string) => void;
    onelevate: () => void;
    onscan: () => void;
    onsettings: () => void;
  } = $props();

  const KEY = "vigil.nav.compact";
  let compact = $state(read());
  let menuOpen = $state(false);

  function read(): boolean {
    try {
      return localStorage.getItem(KEY) === "1";
    } catch {
      return false;
    }
  }

  function toggle(): void {
    compact = !compact;
    try {
      localStorage.setItem(KEY, compact ? "1" : "0");
    } catch {
      // Storage unavailable: the choice lasts for this session only.
    }
  }

  function pick(entry: MenuEntry): void {
    menuOpen = false;
    entry.run?.();
  }
</script>

<svelte:window onclick={() => (menuOpen = false)} onkeydown={(e) => e.key === "Escape" && (menuOpen = false)} />

<aside class="nav" class:compact aria-label={t("nav.navigation")}>
  <div class="top">
    <button class="item hamburger" aria-label={compact ? t("nav.expand") : t("nav.collapse")} title={compact ? t("nav.expand") : t("nav.collapse")}
            aria-expanded={!compact} onclick={toggle}>
      <i class="icon">{"\uE700"}</i>
    </button>
    {#if !compact}<span class="app">Vigil</span>{/if}
  </div>

  <div class="scan">
    <button class="primary" disabled={scanning} onclick={onscan} title={compact ? (scanning ? t("nav.scanning") : t("nav.newScan")) : ""}
            aria-label={scanning ? t("nav.scanning") : t("nav.newScan")}>
      <i class="icon">{scanning ? "\uE895" : "\uE721"}</i>{#if !compact}<span>{scanning ? t("nav.scanning") : t("nav.newScan")}</span>{/if}
    </button>
  </div>

  <nav>
    {#each pages as page, index (page.key)}
      {#if page.section && (index === 0 || pages[index - 1].section !== page.section)}
        {#if compact}<div class="divider"></div>{:else}<div class="section">{page.section}</div>{/if}
      {/if}
      <button class="item" class:active={page.key === current} onclick={() => onnavigate(page.key)}
              aria-current={page.key === current ? "page" : undefined} title={compact ? page.title : ""}>
        <i class="icon">{page.icon}</i>
        {#if !compact}<span class="label">{page.title}</span>{/if}
        {#if page.count}<span class="badge num" class:alert={page.alert}>{page.count}</span>{/if}
      </button>
    {/each}
  </nav>

  <footer>
    {#if info && !compact}
      <div class="status">
        {#if info.elevated}
          <div class="mode ok"><i class="icon">{"\uE7EF"}</i>{t("nav.administrator")}</div>
          <div class="faint">{t("nav.administratorNote")}</div>
        {:else}
          <div class="mode warn"><i class="icon">{"\uE7EF"}</i>{t("nav.readOnly")}</div>
          <div class="faint">{t("nav.readOnlyNote")}</div>
          <button onclick={onelevate}>{t("nav.restartElevated")}</button>
        {/if}
        <div class="faint">{lastScan}</div>
      </div>
    {:else if info && !info.elevated}
      <button class="item" title={t("nav.readOnlyRestart")} aria-label={t("nav.restartElevated")} onclick={onelevate}>
        <i class="icon warn">{"\uE7EF"}</i>
      </button>
    {/if}
    <div class="anchor">
      <button class="item" class:open={menuOpen} aria-haspopup="menu" aria-expanded={menuOpen} title={compact ? t("nav.more") : ""}
              onclick={(e) => { e.stopPropagation(); menuOpen = !menuOpen; }}>
        <i class="icon">{"\uE712"}</i>{#if !compact}<span class="label">{t("nav.more")}</span>{/if}
      </button>
      {#if menuOpen}
        <div class="menu" role="menu">
          {#each menu as entry, index (index)}
            {#if entry.separator}<hr />{:else}<button role="menuitem" onclick={(e) => { e.stopPropagation(); pick(entry); }}>{entry.label}</button>{/if}
          {/each}
        </div>
      {/if}
    </div>
    <button class="item" onclick={onsettings} title={compact ? t("nav.settings") : ""}>
      <i class="icon">{"\uE713"}</i>{#if !compact}<span class="label">{t("nav.settings")}</span>{/if}
    </button>
  </footer>
</aside>

<style>
  .nav {
    width: 260px; flex: none; display: flex; flex-direction: column; padding: 4px 4px 4px; background: transparent;
    transition: width 0.12s ease-out;
  }
  .nav.compact { width: 56px; }
  .top { display: flex; align-items: center; gap: 6px; height: 44px; }
  .app { font-size: 12px; color: var(--ink2); }
  .scan { padding: 4px 4px 8px; display: flex; }
  .scan button { flex: 1; display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 34px; }
  .compact .scan button { padding: 5px 0; }
  .scan .icon { font-size: 14px; }
  nav { display: flex; flex-direction: column; gap: 2px; overflow-y: auto; overflow-x: hidden; flex: 1; min-height: 0; }
  .section { color: var(--ink2); font-size: 12px; font-weight: 600; padding: 10px 14px 4px; }
  .divider { height: 1px; background: var(--rule); margin: 6px 10px; flex: none; }
  .item {
    display: flex; align-items: center; gap: 14px; min-height: 36px; height: 36px; padding: 0 12px 0 14px; margin: 0;
    border: 0; border-radius: var(--radius); background: transparent; color: var(--ink); text-align: left; position: relative;
    font-weight: 400; flex: none; width: 100%;
  }
  .item:hover:not(:disabled) { background: var(--hover); }
  .item:active:not(:disabled) { background: var(--pressed); color: var(--ink2); }
  .item .icon { width: 16px; font-size: 16px; text-align: center; flex: none; }
  .item.active { background: var(--hover); }
  .item.active::before {
    content: ""; position: absolute; left: 0; top: 50%; height: 16px; margin-top: -8px; width: 3px; border-radius: 2px;
    background: var(--accent);
  }
  .item.open { background: var(--hover); }
  .label { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .hamburger { width: 40px; padding: 0 12px; }
  /* InfoBadge */
  .badge {
    min-width: 16px; height: 16px; padding: 0 5px; border-radius: 8px; font-size: 11px; line-height: 16px; text-align: center;
    background: var(--ink3); color: var(--surface); font-weight: 600;
  }
  .badge.alert { background: var(--bad); color: var(--on-accent); }
  .compact .badge { position: absolute; top: 4px; left: 26px; min-width: 14px; height: 14px; line-height: 14px; font-size: 10px; padding: 0 3px; }
  footer { display: flex; flex-direction: column; gap: 2px; padding-top: 6px; }
  .status { display: flex; flex-direction: column; gap: 6px; padding: 8px 12px 10px 14px; margin-bottom: 4px; border-top: 1px solid var(--rule); }
  .mode { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; }
  .mode .icon { font-size: 14px; }
  .mode.ok { color: var(--ok); }
  .mode.warn, .icon.warn { color: var(--warn); }
  .anchor { position: relative; }
  /* MenuFlyout, opening to the right of the pane. */
  .menu {
    position: absolute; left: calc(100% + 4px); bottom: 0; z-index: 60; min-width: 260px; padding: 4px;
    background: var(--flyout); border: 1px solid var(--rule); border-radius: 8px; box-shadow: var(--shadow-flyout);
    display: flex; flex-direction: column;
  }
  .menu button {
    border: 0; background: transparent; text-align: left; padding: 0 12px; min-height: 32px; border-radius: var(--radius); color: var(--ink);
  }
  .menu button:hover:not(:disabled) { background: var(--hover); }
  .menu hr { border: 0; border-top: 1px solid var(--rule); margin: 4px 0; }
</style>
