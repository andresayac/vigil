<script lang="ts">
  import type { Snippet } from "svelte";
  import { t } from "../lib/i18n/index.svelte";

  // In-app dialogs (scan options, settings, the AI preview), styled as a Windows 11 ContentDialog.
  // Confirmations of destructive actions are NOT shown here: Rust shows them in a native Windows dialog.
  let { title, open, onclose, children, footer, width = 560 }: {
    title: string;
    open: boolean;
    onclose: () => void;
    children: Snippet;
    footer?: Snippet;
    width?: number;
  } = $props();

  function onkey(event: KeyboardEvent): void {
    if (event.key === "Escape") onclose();
  }
</script>

{#if open}
  <div class="backdrop" role="presentation" onclick={onclose} onkeydown={onkey}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label={title} tabindex="-1" style:width="{width}px"
         onclick={(e) => e.stopPropagation()} onkeydown={onkey}>
      <header><h2>{title}</h2><button class="close icon" aria-label={t("common.close")} onclick={onclose}>{"\uE711"}</button></header>
      <div class="content">{@render children()}</div>
      {#if footer}<footer>{@render footer()}</footer>{/if}
    </div>
  </div>
{/if}

<style>
  .backdrop { position: fixed; inset: 0; z-index: 50; background: var(--smoke); display: grid; place-items: center; }
  .dialog {
    max-width: calc(100vw - 48px); max-height: calc(100vh - 48px); display: flex; flex-direction: column; overflow: hidden;
    background: var(--surface); border: 1px solid var(--rule); border-radius: var(--radius-card); box-shadow: var(--shadow-dialog);
  }
  header { display: flex; align-items: center; padding: 20px 20px 8px 24px; }
  header h2 { flex: 1; }
  .close { font-size: 12px; color: var(--ink2); min-height: 32px; width: 32px; padding: 0; }
  .content { padding: 4px 24px 20px; overflow: auto; display: flex; flex-direction: column; gap: 12px; }
  footer {
    display: flex; justify-content: flex-end; gap: 8px; padding: 20px 24px; background: var(--layer);
    border-top: 1px solid var(--rule);
  }
  footer :global(button) { min-width: 120px; }
</style>
