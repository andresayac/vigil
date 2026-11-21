<script lang="ts">
  import { t } from "../lib/i18n/index.svelte";
  import type { ActionOutcome } from "../lib/types";
  import Modal from "./Modal.svelte";

  let { outcome, onclose }: { outcome: ActionOutcome | null; onclose: () => void } = $props();
  const failed = $derived(outcome?.records.filter((r) => !r.ok).length ?? 0);
</script>

<Modal title={outcome?.error ? t("results.notDone") : failed ? t("results.someFailed") : t("results.done")} open={outcome !== null} {onclose} width={620}>
  {#if outcome}
    {#if outcome.message}<p class="muted">{outcome.message}</p>{/if}
    {#each outcome.records as record (record.id)}
      <div class="record">
        <span class="mark" class:bad={!record.ok}>{record.ok ? "✓" : "✕"}</span>
        <div><b>{record.label}</b><br /><span class="muted selectable">{record.message}</span>
          {#if record.ok}<br /><span class="faint">{record.can_undo ? t("results.canUndo") : t("results.cannotUndo")}</span>{/if}</div>
      </div>
    {/each}
  {/if}
  {#snippet footer()}<button class="primary" onclick={onclose}>{t("common.close")}</button>{/snippet}
</Modal>

<style>
  p { margin: 0; }
  .record { display: grid; grid-template-columns: 18px minmax(0, 1fr); gap: 8px; font-size: 13px; }
  .mark { color: var(--ok); font-weight: 700; }
  .mark.bad { color: var(--bad); }
</style>
