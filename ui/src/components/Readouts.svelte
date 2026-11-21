<script module lang="ts">
export interface Readout {
  status?: "" | "ok" | "warn" | "bad";
  name: string;
  value: string;
  tip?: string;
}
</script>

<script lang="ts">
  import { stateColor } from "../lib/labels";


  let { rows, nameWidth = 170 }: { rows: Readout[]; nameWidth?: number } = $props();
</script>

<div class="readouts" style:grid-template-columns="12px {nameWidth}px minmax(0, 1fr)">
  {#each rows as row, index (index)}
    <span class="dot" style:background={row.status ? stateColor(row.status) : "transparent"}></span>
    <span class="name">{row.name}</span>
    <span class="value selectable" title={row.tip ?? row.value}>{row.value}</span>
  {/each}
</div>

<style>
  .readouts { display: grid; align-items: center; gap: 6px 10px; font-size: 13px; }
  .dot { width: 6px; height: 6px; border-radius: 3px; }
  .name { color: var(--ink3); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .value { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
</style>
