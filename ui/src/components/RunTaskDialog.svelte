<script lang="ts">
  import * as api from "../lib/api";
  import { t } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import Modal from "./Modal.svelte";

  // Task Manager's "Run new task". The page only asks: Rust resolves the program to one existing file,
  // shows the exact command line in a native confirmation and starts it without a shell.
  let { open, elevated, onclose }: { open: boolean; elevated: boolean; onclose: () => void } = $props();

  let path = $state("");
  let args = $state("");
  let admin = $state(false);

  $effect(() => {
    if (open) admin = elevated;
  });

  async function browse(): Promise<void> {
    const chosen = await api.chooseProgram();
    if (chosen) path = chosen;
  }

  async function start(): Promise<void> {
    if (!path.trim()) return;
    const outcome = await act({ kind: "run", path: path.trim(), args, admin: admin || elevated });
    if (outcome && !outcome.cancelled) {
      path = "";
      args = "";
      onclose();
    }
  }

  function onkey(event: KeyboardEvent): void {
    if (event.key === "Enter") void start();
  }
</script>

<Modal title={t("run.title")} {open} {onclose} width={520}>
  <p class="muted">{t("run.intro")}</p>
  <label class="field">
    <span>{t("run.program")}</span>
    <span class="line">
      <!-- svelte-ignore a11y_autofocus -->
      <input type="text" bind:value={path} placeholder="notepad" spellcheck="false" autocomplete="off" autofocus onkeydown={onkey} />
      <button onclick={browse} disabled={!api.inApp}>{t("run.browse")}</button>
    </span>
  </label>
  <label class="field">
    <span>{t("run.arguments")}</span>
    <input type="text" bind:value={args} spellcheck="false" autocomplete="off" onkeydown={onkey} />
    <span class="faint small">{t("run.argumentsHint")}</span>
  </label>
  <label class="check"><input type="checkbox" bind:checked={admin} disabled={elevated} />{t("run.admin")}</label>
  {#if elevated}<p class="faint indent">{t("run.adminElevated")}</p>{/if}
  {#snippet footer()}
    <button onclick={onclose}>{t("common.cancel")}</button>
    <button class="primary" disabled={!path.trim() || report.busy} onclick={start}>{t("run.start")}</button>
  {/snippet}
</Modal>

<style>
  p { margin: 0; }
  .field { display: flex; flex-direction: column; gap: 6px; color: var(--ink2); }
  .line { display: flex; gap: 8px; }
  .line input { flex: 1; }
  .field input { min-width: 0; font-family: var(--font-mono); font-size: 13px; }
  .small { font-size: 12px; }
  .indent { padding-left: 24px; }
</style>
