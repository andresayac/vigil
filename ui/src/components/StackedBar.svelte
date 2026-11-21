<script module lang="ts">
export interface Segment {
  name: string;
  value: number;
  color: string;
  note?: string;
}
</script>

<script lang="ts">
  import { size } from "../lib/format";


  let { segments, total }: { segments: Segment[]; total: number } = $props();
  const sum = $derived(total || segments.reduce((a, s) => a + s.value, 0) || 1);
</script>

<div class="stack">
  <div class="bar">
    {#each segments as segment (segment.name)}
      <div
        class="part"
        style:width="{(Math.max(0, segment.value) / sum) * 100}%"
        style:background={segment.color}
        title="{segment.name}: {size(segment.value)} ({Math.round((segment.value / sum) * 100)}%){segment.note ? `\n${segment.note}` : ''}"
      ></div>
    {/each}
  </div>
  <div class="legend">
    {#each segments as segment (segment.name)}
      <span title={segment.note ?? ""}><i style:background={segment.color}></i>{segment.name} <b class="num">{size(segment.value)}</b></span>
    {/each}
  </div>
</div>

<style>
  .bar { display: flex; height: 36px; overflow: hidden; background: var(--sunken); border: 1px solid color-mix(in srgb, var(--chart) 70%, transparent); }
  .part { height: 100%; border-right: 1px solid color-mix(in srgb, var(--chart) 70%, transparent); transition: width 0.4s ease; }
  .part:last-child { border-right: 0; }
  .legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 12px; color: var(--ink2); }
  .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px;
              border: 1px solid color-mix(in srgb, var(--chart) 70%, transparent); }
  .legend b { color: var(--ink); font-weight: 600; }
</style>
