<script lang="ts">
  import { onMount } from "svelte";
  import { connections } from "../lib/api";
  import { exposedRemoteAccess, serviceOf } from "../lib/ports";
  import { t } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { Connection } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();
  let selected = $state<string | null>(null);
  const keyOf = (c: Connection) => `${c.protocol}|${c.local}|${c.remote}|${c.pid}`;

  let rows = $state<Connection[]>([]);
  let error = $state("");
  let loading = $state(false);
  let filter = $state("");
  let internetOnly = $state(false);
  let listening = $state(true);

  async function load(): Promise<void> {
    loading = true;
    try {
      rows = await connections();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => void load());

  const shown = $derived.by(() => {
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    return rows.filter((r) => {
      if (internetOnly && !r.public) return false;
      if (!listening && !r.remote) return false;
      const haystack = `${r.process} ${r.pid} ${r.local} ${r.remote} ${r.state} ${serviceOf(r)} ${r.exe}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
  });
  const current = $derived(shown.find((c) => keyOf(c) === selected) ?? null);
  async function processAct(op: string): Promise<void> {
    // Rust re-reads the live process by PID before acting (createdMs 0: no start time known here).
    if (current) await act({ kind: "process", op, pid: current.pid, createdMs: 0 });
  }
  const publicCount = $derived(rows.filter((r) => r.public).length);
  const listenCount = $derived(rows.filter((r) => !r.remote).length);
  const exposed = $derived(rows.filter(exposedRemoteAccess));
</script>

<div class="page">
  <div class="page-head">
    <h1>{t("page.network")}</h1>
    <span class="grow"></span>
    <input type="search" placeholder={t("network.filter")} bind:value={filter} />
    <label class="check" title={t("network.internetOnlyTip")}><input type="checkbox" bind:checked={internetOnly} /> {t("network.internetOnly")}</label>
    <label class="check"><input type="checkbox" bind:checked={listening} /> {t("network.listening")}</label>
    <button onclick={load} disabled={loading}>{loading ? t("common.reading") : t("common.refresh")}</button>
  </div>

  <div class="toolbar">
    <button class="danger-outline" disabled={!current || current.pid <= 4 || report.busy} onclick={() => processAct("terminate")}>{t("proc.end")}</button>
    <button disabled={!current?.exe || !elevated || report.busy} onclick={() => processAct("block")}>{t("proc.block")}</button>
    <button disabled={!current?.exe} onclick={() => current && act({ kind: "shell", op: "location", path: current.exe })}>{t("proc.location")}</button>
    <button disabled={!current?.remote} onclick={() => current && navigator.clipboard.writeText(current.remote)}>{t("network.copyRemote")}</button>
  </div>
  <div class="table">
    <div class="row head">
      <span>{t("network.process")}</span><span class="r">PID</span><span>{t("network.protocol")}</span><span>{t("network.local")}</span><span>{t("network.remote")}</span><span>{t("network.state")}</span><span>{t("network.service")}</span><span>{t("network.path")}</span>
    </div>
    {#each shown as c, i (`${c.protocol}|${c.local}|${c.remote}|${c.pid}|${i}`)}
      <button class="row" class:sel={selected === keyOf(c)} onclick={() => (selected = keyOf(c))}>
        <span class="ellipsis">{c.process}</span><span class="r num">{c.pid}</span><span>{c.protocol}</span>
        <span class="mono">{c.local}</span>
        <span class="mono" class:public={c.public} title={c.public ? t("network.publicTip") : ""}>{c.remote}</span>
        <span>{c.state}</span>
        <span class="ellipsis" class:exposed={exposedRemoteAccess(c)}
              title={exposedRemoteAccess(c) ? t("network.exposedTip") : ""}>{serviceOf(c)}</span>
        <span class="ellipsis" title={c.exe}>{c.exe}</span>
      </button>
    {/each}
  </div>

  <div class="faint">
    {error || t("network.summary", { shown: shown.length, total: rows.length, publicCount, listenCount })}
    {#if exposed.length}<span class="exposed"> · {t("network.exposed", { services: [...new Set(exposed.map(serviceOf))].join(", ") })}</span>{/if}
  </div>
</div>

<style>
  .table { flex: 1; min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; }
  .row {
    display: grid; grid-template-columns: minmax(150px, 1fr) 70px 80px 190px 210px 110px 150px minmax(240px, 2fr);
    gap: 0 10px; align-items: center; padding: 0 10px; height: 26px; font-size: 13px; min-width: 1310px;
  }
  .row:nth-child(even) { background: var(--surface2); }
  button.row { width: 100%; border: 0; border-radius: 0; background: transparent; text-align: left; }
  button.row:nth-child(even) { background: var(--surface2); }
  button.row.sel { background: var(--select); }
  .toolbar { display: flex; gap: 6px; }
  .head { position: sticky; top: 0; background: var(--surface); font-size: 12px; font-weight: 600; color: var(--ink2);
          height: 34px; border-bottom: 1px solid var(--rule); z-index: 1; }
  .r { text-align: right; }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .public { font-weight: 700; }
  .exposed { color: var(--warn); font-weight: 600; }
</style>
