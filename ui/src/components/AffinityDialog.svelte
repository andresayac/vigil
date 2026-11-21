<script lang="ts">
  import * as api from "../lib/api";
  import { t } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { LogicalProcessor } from "../lib/types";
  import Modal from "./Modal.svelte";

  // Processor affinity of one process, like Task Manager's "Set affinity", as Windows CPU Sets (they span
  // processor groups). The page only asks: Rust checks the choice, confirms it natively and journals it.
  let { open, target, onclose }: {
    open: boolean;
    /** The process as it was when the dialog opened (PID + start time identify it). */
    target: { pid: number; createdMs: number; name: string } | null;
    onclose: () => void;
  } = $props();

  let processors = $state<LogicalProcessor[]>([]);
  let checked = $state<boolean[]>([]);
  let loading = $state(false);
  let error = $state("");

  $effect(() => {
    if (!open || !target) return;
    const { pid, createdMs } = target;
    let stale = false;
    loading = true;
    error = "";
    processors = [];
    checked = [];
    api.processAffinity(pid, createdMs)
      .then((a) => {
        if (stale) return;
        processors = a.processors;
        checked = a.processors.map((p) => a.allowed.includes(p.index));
      })
      .catch((e) => { if (!stale) error = String(e); })
      .finally(() => { if (!stale) loading = false; });
    return () => { stale = true; };
  });

  // Hybrid processors report more than one efficiency class: the highest is the performance cores.
  const classes = $derived([...new Set(processors.map((p) => p.efficiencyClass))]);
  const hybrid = $derived(classes.length > 1);
  const fastest = $derived(Math.max(0, ...classes));
  const cores = $derived.by(() => {
    const list: { key: string; members: LogicalProcessor[]; performance: boolean }[] = [];
    const byKey = new Map<string, (typeof list)[number]>();
    for (const p of processors) {
      const key = `${p.group}:${p.core}`;
      let core = byKey.get(key);
      if (!core) {
        core = { key, members: [], performance: p.efficiencyClass === fastest };
        byKey.set(key, core);
        list.push(core);
      }
      core.members.push(p);
    }
    return list;
  });
  const count = $derived(checked.filter(Boolean).length);

  const setAll = (value: boolean) => (checked = processors.map(() => value));
  const performanceOnly = () => (checked = processors.map((p) => p.efficiencyClass === fastest));

  async function apply(): Promise<void> {
    if (!target || !count) return;
    const cores = processors.filter((p) => checked[p.index]).map((p) => p.index);
    const outcome = await act({ kind: "process", op: "affinity", pid: target.pid, createdMs: target.createdMs, cores });
    if (outcome && !outcome.cancelled) onclose();
  }
</script>

<Modal title={t("affinity.title")} {open} {onclose} width={620}>
  <p class="muted">{t("affinity.intro", { name: target?.name ?? "" })}</p>
  {#if loading}
    <p class="faint">{t("affinity.reading")}</p>
  {:else if error}
    <p class="error">{error}</p>
  {:else if processors.length}
    <div class="shortcuts">
      <button onclick={() => setAll(true)}>{t("affinity.all")}</button>
      <button onclick={() => setAll(false)}>{t("affinity.none")}</button>
      {#if hybrid}<button onclick={performanceOnly}>{t("affinity.performance")}</button>{/if}
      <span class="grow"></span>
      <span class="faint">{t("affinity.selected", { count, total: processors.length })}</span>
    </div>
    <div class="cores" role="group" aria-label={t("affinity.title")}>
      {#each cores as core, n (core.key)}
        <div class="core">
          <span class="core-name">{t("affinity.core", { n: n + 1 })}</span>
          {#if hybrid}<span class="tag" class:perf={core.performance}>{core.performance ? t("affinity.pcore") : t("affinity.ecore")}</span>{/if}
          <span class="cpus">
            {#each core.members as p (p.index)}
              <label class="check"><input type="checkbox" bind:checked={checked[p.index]} />{t("affinity.cpu", { n: p.index })}</label>
            {/each}
          </span>
        </div>
      {/each}
    </div>
    <p class="faint">{t("affinity.hint")}</p>
  {/if}
  {#snippet footer()}
    <button onclick={onclose}>{t("common.cancel")}</button>
    <button class="primary" disabled={!count || loading || report.busy} onclick={apply}>{t("affinity.apply")}</button>
  {/snippet}
</Modal>

<style>
  p { margin: 0; }
  .error { color: var(--bad); }
  .shortcuts { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .grow { flex: 1; }
  .cores {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 2px 16px; max-height: 340px; overflow: auto;
    padding: 6px 10px; border: 1px solid var(--rule); border-radius: var(--radius);
  }
  .core { display: flex; align-items: center; gap: 8px; min-height: 32px; }
  .core-name { width: 58px; flex: none; color: var(--ink2); font-size: 13px; }
  .tag { flex: none; width: 46px; font-size: 12px; color: var(--ink3); }
  .tag.perf { color: var(--ink2); font-weight: 600; }
  .cpus { display: flex; gap: 14px; flex-wrap: wrap; }
  .cpus .check { font-size: 13px; }
</style>
