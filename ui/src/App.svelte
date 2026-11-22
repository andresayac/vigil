<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import ConsentDialog from "./components/ConsentDialog.svelte";
  import Modal from "./components/Modal.svelte";
  import ResultsDialog from "./components/ResultsDialog.svelte";
  import ScanDialog from "./components/ScanDialog.svelte";
  import SettingsDialog from "./components/SettingsDialog.svelte";
  import Sidebar, { type MenuEntry, type PageDef } from "./components/Sidebar.svelte";
  import * as api from "./lib/api";
  import { when } from "./lib/format";
  import { setLanguage, t } from "./lib/i18n/index.svelte";
  import { act, finishScan, isIgnored, loadReport, report, startScan } from "./lib/report.svelte";
  import { followWatch, stateLine, watch } from "./lib/watch.svelte";
  import Accounts from "./pages/Accounts.svelte";
  import Alerts from "./pages/Alerts.svelte";
  import type { AppInfo, Settings } from "./lib/types";
  import Findings from "./pages/Findings.svelte";
  import Extensions from "./pages/Extensions.svelte";
  import Firewall from "./pages/Firewall.svelte";
  import History from "./pages/History.svelte";
  import Network from "./pages/Network.svelte";
  import Optimize from "./pages/Optimize.svelte";
  import Overview from "./pages/Overview.svelte";
  import Protection from "./pages/Protection.svelte";
  import Posture from "./pages/Posture.svelte";
  import Performance from "./pages/Performance.svelte";
  import Processes from "./pages/Processes.svelte";
  import Programs from "./pages/Programs.svelte";
  import Quarantine from "./pages/Quarantine.svelte";
  import Reliability from "./pages/Reliability.svelte";
  import Services from "./pages/Services.svelte";
  import Startup from "./pages/Startup.svelte";
  import Storage from "./pages/Storage.svelte";
  import Tasks from "./pages/Tasks.svelte";
  import System from "./pages/System.svelte";

  let page = $state("overview");
  let info = $state<AppInfo | null>(null);
  let settings = $state<Settings | null>(null);
  let focusPid = $state<number | null>(null);
  let resource = $state<string | null>(null);
  let findingsFocus = $state<{ ids?: string[]; caption?: string; id?: string; verdict?: string } | null>(null);
  let scanOpen = $state(false);
  let settingsOpen = $state(false);
  let aboutOpen = $state(false);
  let notice = $state("");

  const elevated = $derived(info?.elevated ?? false);

  onMount(async () => {
    // Windows 11: let the Mica material of the window show through the page.
    if (await api.hasMica()) document.documentElement.dataset.backdrop = "mica";
    [info, settings] = await Promise.all([api.appInfo(), api.getSettings()]);
    if (info.dataWarning) notice = info.dataWarning;
    await loadReport();
    // Started at sign-in (--tray): the window stays hidden until it is opened from the tray.
    if (!info.startHidden) requestAnimationFrame(() => void api.showWindow());
    stopWatch = await followWatch();
    stopOpen = await api.onOpenPage((request) => {
      go(pages.some((p) => p.key === request.page) ? request.page : "alerts");
      if (request.scan && !report.scanning) scanOpen = true;
    });
  });
  let stopWatch: (() => void) | null = null;
  let stopOpen: (() => void) | null = null;
  onDestroy(() => { stopWatch?.(); stopOpen?.(); });
  const unreadAlerts = $derived(watch.status?.unread ?? 0);

  // "auto" uses the language Rust resolved from Windows, so the page and the findings agree.
  $effect(() => {
    if (!settings) return;
    setLanguage(settings.language === "auto" ? info?.language || "auto" : settings.language);
  });

  $effect(() => {
    const theme = settings?.theme ?? "system";
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    // The native title bar and the Mica material follow the same theme as the page.
    void api.setWindowTheme(theme).catch(() => {});
  });

  const urgent = $derived((report.analysis?.items ?? []).filter((i) => ["remove", "disable"].includes(i.verdict) && !isIgnored(i.id)).length);
  const review = $derived((report.analysis?.items ?? []).filter((i) => i.verdict === "review" && !isIgnored(i.id)).length);

  const pages: PageDef[] = $derived([
    { key: "overview", title: t("page.overview"), icon: "", section: t("nav.security") },
    { key: "findings", title: t("page.findings"), icon: "", section: t("nav.security"), count: String(urgent || review || ""), alert: urgent > 0 },
    { key: "alerts", title: t("page.alerts"), icon: "\uEA8F", section: t("nav.security"), count: unreadAlerts ? String(unreadAlerts) : "" },
    { key: "protection", title: t("page.protection"), icon: "\uF760", section: t("nav.security") },
    { key: "posture", title: t("page.posture"), icon: "\uE9D5", section: t("nav.security") },
    { key: "firewall", title: t("page.firewall"), icon: "", section: t("nav.security") },
    { key: "accounts", title: t("page.accounts"), icon: "", section: t("nav.security") },
    { key: "extensions", title: t("page.extensions"), icon: "", section: t("nav.security") },
    { key: "quarantine", title: t("page.quarantine"), icon: "", section: t("nav.security") },
    { key: "history", title: t("page.history"), icon: "", section: t("nav.security") },
    { key: "performance", title: t("page.performance"), icon: "", section: t("nav.live") },
    { key: "processes", title: t("page.processes"), icon: "", section: t("nav.live") },
    { key: "network", title: t("page.network"), icon: "", section: t("nav.live") },
    { key: "services", title: t("page.services"), icon: "", section: t("nav.live") },
    { key: "optimize", title: t("page.optimize"), icon: "", section: t("nav.maintenance") },
    { key: "startup", title: t("page.startup"), icon: "", section: t("nav.maintenance") },
    { key: "tasks", title: t("page.tasks"), icon: "", section: t("nav.maintenance") },
    { key: "programs", title: t("page.programs"), icon: "", section: t("nav.maintenance") },
    { key: "storage", title: t("page.storage"), icon: "", section: t("nav.maintenance") },
    { key: "system", title: t("page.system"), icon: "", section: t("nav.maintenance") },
    { key: "reliability", title: t("page.reliability"), icon: "", section: t("nav.maintenance") },
  ]);

  const lastScan = $derived(report.analysis
    ? t(report.analysis.meta?.is_admin ? "nav.lastScan" : "nav.lastScanReadOnly", { when: when(String(report.analysis.meta?.started ?? "")) })
    : t("nav.noScanYet"));

  const tool = (op: string) => () => void act({ kind: "tuning", op, params: {} });
  const shell = (request: { op: string; url?: string; name?: string }) => () => void act({ kind: "shell", ...request });

  const menu: MenuEntry[] = $derived([
    { label: t("menu.openReport"), run: async () => { const opened = await api.openReport(); if (opened) { report.analysis = opened; page = "overview"; } } },
    { label: t("menu.exportHtml"), run: async () => { const path = await api.exportHtml(); if (path) notice = t("menu.exported", { path }); } },
    { label: "", separator: true },
    { label: t("menu.restorePoint"), run: tool("system.restore_point") },
    { label: t("menu.defenderFullScan"), run: tool("defender.full_scan") },
    { label: t("menu.defenderUpdate"), run: tool("defender.update") },
    { label: "", separator: true },
    { label: t("menu.windowsSecurity"), run: shell({ op: "url", url: "windowsdefender://" }) },
    { label: t("menu.taskScheduler"), run: shell({ op: "console", name: "taskschd.msc" }) },
    { label: t("menu.services"), run: shell({ op: "console", name: "services.msc" }) },
    { label: t("menu.eventViewer"), run: shell({ op: "console", name: "eventvwr.msc" }) },
    { label: "", separator: true },
    { label: t("menu.about"), run: () => (aboutOpen = true) },
  ]);

  function go(key: string, res?: string): void {
    resource = res ?? null;
    page = key;
  }

  function onstart(days: number, virustotal: boolean, useAi: boolean): void {
    scanOpen = false;
    page = "overview";
    void startScan(days, virustotal, useAi);
  }
</script>

<div class="shell">
  <Sidebar {pages} current={page} {info} scanning={report.scanning} {lastScan} {menu}
           watchLine={stateLine(watch.status)} watchState={!watch.status ? "" : !watch.status.owner ? "other" : watch.status.watching ? "on" : "paused"}
           onnavigate={(key) => go(key)} onelevate={() => void api.restartElevated()} onscan={() => (scanOpen = true)}
           onsettings={() => (settingsOpen = true)} />
  <main>
    {#if notice}
      <div class="notice" role="status">
        <i class="icon info">{""}</i><span class="selectable">{notice}</span>
        <button class="icon" aria-label={t("common.dismiss")} onclick={() => (notice = "")}>{""}</button>
      </div>
    {/if}
    {#key page}
      {#if page === "overview"}
        <Overview onopenitem={(id) => { findingsFocus = { id }; page = "findings"; }}
                  onopenids={(ids, caption) => { findingsFocus = { ids, caption }; page = "findings"; }}
                  onopenverdict={(verdict) => { findingsFocus = { verdict }; page = "findings"; }}
                  onscan={() => (scanOpen = true)} onpage={go} />
      {:else if page === "findings"}
        <Findings focus={findingsFocus} {elevated} />
      {:else if page === "firewall"}
        <Firewall {elevated} />
      {:else if page === "accounts"}
        <Accounts {elevated} />
      {:else if page === "extensions"}
        <Extensions {elevated} />
      {:else if page === "quarantine"}
        <Quarantine {elevated} />
      {:else if page === "history"}
        <History {elevated} />
      {:else if page === "alerts"}
        <Alerts onpage={go} />
      {:else if page === "protection"}
        <Protection {elevated} />
      {:else if page === "posture"}
        <Posture {elevated} onpage={go} />
      {:else if page === "performance"}
        <Performance cpuName={info?.cpuName ?? ""} initial={resource} {elevated} onshowprocess={(pid) => { focusPid = pid; page = "processes"; }} />
      {:else if page === "processes"}
        <Processes {focusPid} {elevated} autoRefresh={settings?.autoRefresh ?? true}
                   onshowfinding={(id) => { findingsFocus = { id }; page = "findings"; }} />
      {:else if page === "network"}
        <Network {elevated} />
      {:else if page === "services"}
        <Services {elevated} />
      {:else if page === "optimize"}
        <Optimize {elevated} onscan={() => (scanOpen = true)} onpage={go} />
      {:else if page === "startup"}
        <Startup {elevated} />
      {:else if page === "tasks"}
        <Tasks {elevated} />
      {:else if page === "programs"}
        <Programs {elevated} />
      {:else if page === "storage"}
        <Storage {elevated} />
      {:else if page === "system"}
        <System {elevated} onpage={go} />
      {:else if page === "reliability"}
        <Reliability {elevated} />
      {/if}
    {/key}
  </main>
</div>

<ScanDialog open={scanOpen} {settings} onclose={() => (scanOpen = false)} {onstart} />
<ConsentDialog offer={report.offer} onanswer={(send) => void finishScan(send)} />
<SettingsDialog open={settingsOpen} {settings} dataDir={info?.dataDir ?? ""} onclose={() => (settingsOpen = false)} onsaved={(s) => (settings = s)} />
<ResultsDialog outcome={report.outcome} onclose={() => (report.outcome = null)} />
<Modal title={t("about.title")} open={aboutOpen} onclose={() => (aboutOpen = false)} width={480}>
  <p><b>Vigil {info?.version ?? ""}</b></p>
  <p class="muted">{t("about.body")}</p>
  <p class="faint">{t("about.licence")} · github.com/andresayac/vigil</p>
</Modal>

<style>
  .shell { display: flex; height: 100%; }
  /* NavigationView content area: a layer with a rounded top-left corner over the window base (Mica). */
  main {
    flex: 1; min-width: 0; min-height: 0; position: relative; background: var(--layer);
    border-top: 1px solid var(--layer-stroke); border-left: 1px solid var(--layer-stroke); border-top-left-radius: 8px;
  }
  /* InfoBar */
  .notice {
    position: absolute; top: 12px; right: 20px; z-index: 30; display: flex; align-items: center; gap: 10px; max-width: 560px;
    background: var(--flyout); border: 1px solid var(--rule); border-radius: var(--radius); padding: 6px 6px 6px 14px;
    box-shadow: var(--shadow-flyout);
  }
  .notice .info { color: var(--accent); font-size: 16px; }
  .notice button { min-height: 28px; padding: 4px 8px; font-size: 12px; color: var(--ink2); }
  p { margin: 0; }
</style>
