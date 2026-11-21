<script lang="ts">
  import { pct } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";

  let { values }: { values: number[] } = $props();
</script>

<div class="cores" aria-label={t("chart.coresLabel")}>
  {#each values as value, index (index)}
    <div class="core" title={t("chart.core", { index: String(index), value: pct(value) })}>
      <div class="track"><div class="fill" style:height="{Math.min(100, value)}%"></div></div>
      <span>{index}</span>
    </div>
  {/each}
</div>

<style>
  .cores { display: flex; gap: 4px; height: 58px; }
  .core { flex: 1; min-width: 4px; display: flex; flex-direction: column; align-items: center; gap: 2px; }
  .track { flex: 1; width: 100%; background: var(--sunken); border: 1px solid color-mix(in srgb, var(--chart) 45%, transparent);
           display: flex; align-items: flex-end; overflow: hidden; }
  .fill { width: 100%; background: color-mix(in srgb, var(--chart) 75%, transparent); transition: height 0.4s ease; }
  span { font-size: 10px; color: var(--ink3); }
</style>
