<script lang="ts">
  import * as api from "../lib/api";
  import { t } from "../lib/i18n/index.svelte";
  import type { WatchAlert } from "../lib/types";
  import { clock, setStatus, severityLook, since, stateLine, watch } from "../lib/watch.svelte";

  // Overview's "Background watch" card: whether Vigil is watching, when it last looked, and the newest alerts.
  let { onpage }: { onpage: (page: string) => void } = $props();

  const status = $derived(watch.status);
  const recent = $derived((status?.recent ?? []).slice(0, 4));
  let busy = $state(false);

  async function toggle(): Promise<void> {
    if (!status) return;
    busy = true;
    try {
      setStatus(await api.watchSetWatching(!status.watching));
    } finally {
      busy = false;
    }
  }

  async function resumeNotifications(): Promise<void> {
    setStatus(await api.watchPauseNotifications(false));
  }

  async function open(alert: WatchAlert): Promise<void> {
    if (!alert.read) setStatus(await api.watchMarkRead([alert.id]));
    onpage(alert.target === "alerts" ? "alerts" : alert.target);
  }
</script>

{#if status}
  <section class="panel watch">
    <div class="head">
      <h2>{t("watch.title")}</h2>
      <span class="state" class:on={status.owner && status.watching} class:paused={status.owner && !status.watching}>
        <span class="dot"></span>{stateLine(status)}
      </span>
    </div>
    {#if status.notifyPausedUntil}
      <p class="faint">{t("watch.notificationsPausedUntil", { time: clock(status.notifyPausedUntil) })}
        <button class="link" onclick={resumeNotifications}>{t("watch.resumeNotifications")}</button></p>
    {/if}
    {#if recent.length}
      <div class="list">
        {#each recent as alert (alert.id)}
          {@const look = severityLook(alert)}
          <button class="alert" class:unread={!alert.read} onclick={() => void open(alert)}>
            <i class="icon {look.tone}">{look.icon}</i>
            <span class="title">{alert.title}</span>
            <span class="faint when">{since(alert.time)}</span>
          </button>
        {/each}
      </div>
    {:else}
      <p class="muted">{t("watch.nothingYet")}</p>
    {/if}
    {#if !status.tasksWatched}<p class="faint">{t("watch.tasksNeedAdmin")}</p>{/if}
    {#if status.logsHidden?.length}<p class="faint">{t("watch.logsNeedAdmin", { logs: status.logsHidden.join(", ") })}</p>{/if}
    <div class="actions">
      <button class="link" onclick={() => onpage("alerts")}>{status.unread ? t("watch.seeAllUnread", { count: status.unread }) : t("watch.seeAll")}</button>
      {#if status.owner}
        <button class="link" disabled={busy} onclick={toggle}>{status.watching ? t("watch.pause") : t("watch.resume")}</button>
      {/if}
    </div>
  </section>
{/if}

<style>
  .watch { display: flex; flex-direction: column; gap: 8px; }
  .head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .state { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--ink2); }
  .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--ink3); flex: none; }
  .state.on .dot { background: var(--ok); }
  .state.paused .dot { background: var(--warn); }
  p { margin: 0; }
  .list { display: flex; flex-direction: column; }
  .alert {
    display: grid; grid-template-columns: 18px minmax(0, 1fr) auto; align-items: center; gap: 8px; min-height: 30px; padding: 2px 6px;
    margin: 0 -6px; border: 0; background: transparent; text-align: left; border-radius: var(--radius);
  }
  .alert:hover:not(:disabled) { background: var(--hover); }
  .alert .icon { font-size: 14px; color: var(--ink2); }
  .alert .icon.warn { color: var(--warn); }
  .alert .icon.bad { color: var(--bad); }
  .alert .title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .alert.unread .title { font-weight: 600; }
  .when { font-size: 12px; white-space: nowrap; }
  .actions { display: flex; gap: 16px; flex-wrap: wrap; }
  .link { border: 0; background: transparent; padding: 0; color: var(--accent); text-align: left; min-height: 24px; }
  .link:hover:not(:disabled) { background: transparent; text-decoration: underline; }
</style>
