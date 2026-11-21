<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { size, when } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { act } from "../lib/report.svelte";
  import type { QuarantineEntry } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();
  let entries = $state<QuarantineEntry[]>([]);
  let selected = $state<string | null>(null);
  let error = $state("");

  async function load(): Promise<void> {
    try {
      entries = await api.quarantine();
      error = "";
    } catch (e) {
      error = String(e);
    }
  }
  onMount(() => void load());

  async function run(op: "restore" | "delete"): Promise<void> {
    if (!selected) return;
    await act({ kind: "journal", op, id: selected });
    selected = null;
    await load();
  }
</script>

<div class="page">
  <div class="page-head"><h1>{t("page.quarantine")}</h1></div>
  <p class="muted note">{t("quarantine.note")}</p>
  <div class="actions">
    <button disabled={!selected || !elevated} onclick={() => run("restore")}>{t("quarantine.restore")}</button>
    <button class="danger-outline" disabled={!selected || !elevated} onclick={() => run("delete")}>{t("quarantine.delete")}</button>
  </div>
  <div class="table">
    <div class="row head"><span>{t("quarantine.file")}</span><span>{t("quarantine.original")}</span><span>{t("quarantine.when")}</span><span class="r">{t("quarantine.size")}</span><span>SHA-256</span><span>{t("quarantine.reason")}</span></div>
    {#each entries as entry (entry.id)}
      <button class="row" class:sel={selected === entry.id} onclick={() => (selected = entry.id)}
              title={entry.state === "scheduled" ? t("quarantine.scheduled") : ""}>
        <span class="ellipsis">{entry.name}</span><span class="ellipsis" title={entry.original_path}>{entry.original_path}</span>
        <span>{when(entry.quarantined_at)}</span><span class="r num">{size(entry.size)}</span>
        <span class="mono ellipsis" title={entry.sha256}>{entry.sha256}</span><span class="ellipsis">{entry.reason}</span>
      </button>
    {:else}
      <p class="faint empty">{t("quarantine.empty")}</p>
    {/each}
  </div>
  <div class="faint">{error || t("quarantine.count", { count: entries.length })}</div>
</div>

<style>
  .note { margin: 0; max-width: 900px; }
  .actions { display: flex; gap: 6px; }
  .table { flex: 1; min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; }
  .row { display: grid; grid-template-columns: 180px minmax(240px, 2fr) 150px 90px 220px minmax(140px, 1fr); gap: 0 10px; align-items: center;
         width: 100%; padding: 0 10px; height: 28px; border: 0; border-radius: 0; background: transparent; text-align: left; font-size: 13px; }
  .row:nth-child(odd):not(.head) { background: var(--surface2); }
  .row.sel { background: var(--select); }
  .head { position: sticky; top: 0; background: var(--surface); font-size: 12px; font-weight: 600; color: var(--ink2); height: 34px; border-bottom: 1px solid var(--rule); }
  .r { text-align: right; }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty { padding: 30px; text-align: center; margin: 0; }
</style>
