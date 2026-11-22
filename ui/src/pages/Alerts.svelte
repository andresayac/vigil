<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import type { AlertKind, WatchAlert } from "../lib/types";
  import { KIND_LABEL, TARGET_LABEL, clock, setStatus, severityLook, since, stateLine, watch } from "../lib/watch.svelte";

  // Every change the background watch noticed, newest first. Titles and details are plain text from Rust
  // (they quote names and command lines read from the computer).
  let { onpage }: { onpage: (page: string) => void } = $props();

  let alerts = $state<WatchAlert[]>([]);
  let kind = $state<AlertKind | "all">("all");
  let error = $state("");
  let confirmClear = $state(false);

  async function load(): Promise<void> {
    try {
      alerts = await api.watchAlerts();
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  onMount(() => {
    void load();
    let stop: (() => void) | null = null;
    void api.onWatch(() => void load()).then((off) => (stop = off));
    return () => stop?.();
  });

  const KINDS: AlertKind[] = ["startup", "service", "task", "security", "port"];
  const SEVERITY: Record<WatchAlert["severity"], Key> = {
    info: "alerts.severity.info", warning: "alerts.severity.warning", critical: "alerts.severity.critical",
  };
  const shown = $derived(kind === "all" ? alerts : alerts.filter((a) => a.kind === kind));
  const counts = $derived(Object.fromEntries(KINDS.map((k) => [k, alerts.filter((a) => a.kind === k).length])) as Record<AlertKind, number>);
  const status = $derived(watch.status);

  async function markAll(): Promise<void> {
    setStatus(await api.watchMarkRead(null));
    await load();
  }

  async function clear(): Promise<void> {
    confirmClear = false;
    setStatus(await api.watchClear());
    await load();
  }

  async function open(alert: WatchAlert): Promise<void> {
    if (!alert.read) {
      setStatus(await api.watchMarkRead([alert.id]));
      await load();
    }
    if (TARGET_LABEL[alert.target]) onpage(alert.target);
  }

  async function notifications(pause: boolean): Promise<void> {
    setStatus(await api.watchPauseNotifications(pause));
  }

  async function watching(on: boolean): Promise<void> {
    setStatus(await api.watchSetWatching(on));
  }
</script>

<div class="page">
  <div class="page-head"><h1>{t("page.alerts")}</h1></div>
  <p class="muted note">{t("alerts.note")}</p>

  {#if status}
    <div class="state">
      <span class="pill" class:on={status.owner && status.watching} class:paused={status.owner && !status.watching}>
        <span class="dot"></span>{stateLine(status)}
      </span>
      {#if status.owner}
        <button onclick={() => void watching(!status.watching)}>
          <i class="icon">{status.watching ? "" : ""}</i>{status.watching ? t("watch.pause") : t("watch.resume")}
        </button>
      {/if}
      {#if status.notifyPausedUntil}
        <span class="faint">{t("watch.notificationsPausedUntil", { time: clock(status.notifyPausedUntil) })}</span>
        <button onclick={() => void notifications(false)}>{t("watch.resumeNotifications")}</button>
      {:else}
        <button onclick={() => void notifications(true)}><i class="icon">{""}</i>{t("watch.pauseNotifications")}</button>
      {/if}
      {#if !status.tasksWatched}<span class="faint">{t("watch.tasksNeedAdmin")}</span>{/if}
    </div>
    {#if status.error}<p class="warn-text selectable">{status.error}</p>{/if}
  {/if}

  <div class="bar">
    <div class="chips" role="tablist" aria-label={t("alerts.filter")}>
      <button role="tab" class="chip" class:active={kind === "all"} aria-selected={kind === "all"} onclick={() => (kind = "all")}>
        {t("alerts.all")} <span class="num">{alerts.length}</span>
      </button>
      {#each KINDS as k (k)}
        {#if counts[k]}
          <button role="tab" class="chip" class:active={kind === k} aria-selected={kind === k} onclick={() => (kind = k)}>
            {t(KIND_LABEL[k])} <span class="num">{counts[k]}</span>
          </button>
        {/if}
      {/each}
    </div>
    <div class="tools">
      <button disabled={!alerts.some((a) => !a.read)} onclick={() => void markAll()}><i class="icon">{""}</i>{t("alerts.markAllRead")}</button>
      {#if confirmClear}
        <span class="faint">{t("alerts.clearConfirm")}</span>
        <button class="danger" onclick={() => void clear()}>{t("alerts.clear")}</button>
        <button onclick={() => (confirmClear = false)}>{t("common.cancel")}</button>
      {:else}
        <button disabled={!alerts.length} onclick={() => (confirmClear = true)}><i class="icon">{""}</i>{t("alerts.clear")}</button>
      {/if}
    </div>
  </div>

  <div class="list">
    {#each shown as alert (alert.id)}
      {@const look = severityLook(alert)}
      <div class="row" class:unread={!alert.read}>
        <i class="icon sev {look.tone}" title={t(SEVERITY[alert.severity])}>{look.icon}</i>
        <div class="body">
          <div class="title selectable">{alert.title}</div>
          {#if alert.detail}<div class="detail faint selectable">{alert.detail}</div>{/if}
          <div class="meta faint">
            <span title={clock(alert.time)}>{since(alert.time)}</span> · <span>{t(KIND_LABEL[alert.kind])}</span>
            {#if !alert.read}· <span class="new">{t("alerts.unread")}</span>{/if}
          </div>
        </div>
        <div class="go">
          {#if TARGET_LABEL[alert.target]}
            <button class="link" onclick={() => void open(alert)}>{t("alerts.open", { page: t(TARGET_LABEL[alert.target]) })}</button>
          {:else if !alert.read}
            <button class="link" onclick={() => void open(alert)}>{t("alerts.markRead")}</button>
          {/if}
        </div>
      </div>
    {:else}
      <p class="faint empty">{alerts.length ? t("alerts.noneOfKind") : t("alerts.empty")}</p>
    {/each}
  </div>
  {#if error}<p class="faint">{error}</p>{/if}
</div>

<style>
  .note { margin: 0; max-width: 980px; }
  .state { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .state button .icon, .tools .icon { margin-right: 6px; font-size: 13px; }
  .pill { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; font-size: 13px; color: var(--ink2); margin-right: 6px; }
  .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--ink3); flex: none; }
  .pill.on .dot { background: var(--ok); }
  .pill.paused .dot { background: var(--warn); }
  .bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .chips, .tools { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .chip { border-radius: 14px; min-height: 28px; padding: 2px 12px; font-size: 13px; }
  .chip.active { background: var(--select); border-color: var(--accent); }
  .chip .num { color: var(--ink2); margin-left: 4px; }
  .list {
    flex: 1; min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px;
    display: flex; flex-direction: column;
  }
  .row { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--rule); }
  .row:last-child { border-bottom: 0; }
  .sev { font-size: 15px; color: var(--ink2); padding-top: 1px; }
  .sev.warn { color: var(--warn); }
  .sev.bad { color: var(--bad); }
  .body { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .title { overflow-wrap: anywhere; }
  .unread .title { font-weight: 600; }
  .detail { font-size: 12px; overflow-wrap: anywhere; }
  .meta { font-size: 12px; }
  .new { color: var(--accent); font-weight: 600; }
  .go { align-self: center; }
  .link { border: 0; background: transparent; padding: 0; color: var(--accent); text-align: left; white-space: nowrap; }
  .link:hover:not(:disabled) { background: transparent; text-decoration: underline; }
  .empty { padding: 30px; text-align: center; margin: 0; }
  .warn-text { color: var(--warn); margin: 0; font-size: 12px; }
  .danger { color: var(--bad); }
</style>
