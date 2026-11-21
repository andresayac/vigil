<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { when } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { JournalRecord } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();
  let records = $state<JournalRecord[]>([]);
  let selected = $state<string | null>(null);
  let error = $state("");

  async function load(): Promise<void> {
    try {
      records = (await api.journal()).slice().reverse();
      error = "";
    } catch (e) {
      error = String(e);
    }
  }
  onMount(() => void load());

  // Steps of one "Remove completely" share a batch id: show them under one heading.
  const groups = $derived.by(() => {
    const out: { batch: string | null; title: string; time: string; records: JournalRecord[] }[] = [];
    const byBatch = new Map<string, (typeof out)[number]>();
    for (const record of records) {
      if (record.batch) {
        let group = byBatch.get(record.batch);
        if (!group) {
          group = { batch: record.batch, title: t("history.removal", { item: record.item }), time: record.time, records: [] };
          byBatch.set(record.batch, group);
          out.push(group);
        }
        group.records.push(record);
      } else {
        out.push({ batch: null, title: "", time: record.time, records: [record] });
      }
    }
    return out;
  });

  const current = $derived(records.find((r) => r.id === selected) ?? null);
  const batch = $derived(current?.batch ?? null);
  const batchUndoable = $derived(batch ? records.some((r) => r.batch === batch && r.can_undo) : false);

  async function undo(all: boolean): Promise<void> {
    if (!current) return;
    await act(all && batch ? { kind: "journal", op: "undo_batch", id: batch } : { kind: "journal", op: "undo", id: current.id });
    await load();
  }
</script>

<div class="page">
  <div class="page-head"><h1>{t("page.history")}</h1></div>
  <p class="muted note">{t("history.note")}</p>
  <div class="actions">
    <button disabled={!current?.can_undo || report.busy || !elevated} onclick={() => undo(false)}>{t("history.undo")}</button>
    <button disabled={!batchUndoable || report.busy || !elevated} onclick={() => undo(true)}>{t("history.undoAll")}</button>
  </div>
  <div class="table">
    <div class="row head"><span>{t("history.when")}</span><span>{t("history.action")}</span><span>{t("history.target")}</span><span>{t("history.result")}</span><span>{t("history.undoColumn")}</span></div>
    {#each groups as group, index (group.batch ?? group.records[0].id + index)}
      {#if group.batch}
        <div class="row batch"><span>{when(group.time)}</span><span class="title">{group.title}</span><span></span><span></span><span></span></div>
      {/if}
      {#each group.records as record (record.id)}
        <button class="row" class:child={group.batch} class:sel={selected === record.id} onclick={() => (selected = record.id)}>
          <span>{when(record.time)}</span><span class="ellipsis">{record.op_label}</span>
          <span class="ellipsis" title={record.target}>{record.target}</span>
          <span class="ellipsis" class:failed={!record.ok} title={record.message}>{record.ok ? "" : `${t("history.failed")} `}{record.message}</span>
          <span>{record.undone ? t("history.undone") : record.can_undo ? t("history.available") : "—"}</span>
        </button>
      {/each}
    {:else}
      <p class="faint empty">{t("history.empty")}</p>
    {/each}
  </div>
  {#if current}
    <section class="panel detail selectable">
      <b>{current.label}</b><br />{current.message}{#if current.undo_message}<br /><span class="muted">{t("history.undoMessage", { message: current.undo_message })}</span>{/if}
    </section>
  {/if}
  {#if error}<p class="faint">{error}</p>{/if}
</div>

<style>
  .note { margin: 0; }
  .actions { display: flex; gap: 6px; }
  .table { flex: 1; min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; }
  .row { display: grid; grid-template-columns: 160px 200px minmax(200px, 1.5fr) minmax(200px, 2fr) 90px; gap: 0 10px; align-items: center;
         width: 100%; padding: 0 10px; height: 28px; border: 0; border-radius: 0; background: transparent; text-align: left; font-size: 13px; }
  .row.child { padding-left: 28px; }
  .row.sel { background: var(--select); }
  .batch { font-weight: 600; background: var(--surface2); }
  .batch .title { grid-column: span 3; }
  .head { position: sticky; top: 0; background: var(--surface); font-size: 12px; font-weight: 600; color: var(--ink2); height: 34px; border-bottom: 1px solid var(--rule); }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .failed { color: var(--bad); }
  .empty { padding: 30px; text-align: center; margin: 0; }
  .detail { padding: 10px 14px; font-size: 13px; }
</style>
