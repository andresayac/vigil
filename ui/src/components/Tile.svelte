<script lang="ts">
  import Sparkline from "./Sparkline.svelte";

  let {
    title,
    value,
    detail = "",
    values = null,
    percent = true,
    level = "",
    selected = false,
    hue = "",
    onclick,
  }: {
    title: string;
    value: string;
    detail?: string;
    values?: number[] | null;
    percent?: boolean;
    level?: "" | "warn" | "bad";
    selected?: boolean;
    /** Resource hue of the sparkline (cpu, memory, disk, net, gpu): live measurements only. */
    hue?: string;
    onclick?: () => void;
  } = $props();
</script>

<button class="tile" class:selected {onclick} title={title} style:--chart={hue ? `var(--chart-${hue})` : undefined}>
  <div class="top">
    <span class="title">{title}</span>
    <span class="value num {level}">{value}</span>
  </div>
  <div class="detail">{detail}</div>
  {#if values}<Sparkline {values} {percent} />{/if}
</button>

<style>
  .tile {
    display: flex; flex-direction: column; gap: 2px; text-align: left; padding: 11px 14px 8px; min-width: 0;
    background: var(--surface); border: 1px solid var(--rule); border-radius: var(--radius-card); height: 112px;
  }
  .tile:hover:not(.selected):not(:disabled) { background: var(--control-hover); }
  .tile.selected { border-color: var(--accent); }
  .top { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
  .title { font-weight: 400; color: var(--ink2); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .value { font: 600 22px/28px var(--font-display); white-space: nowrap; }
  .value.warn { color: var(--warn); }
  .value.bad { color: var(--bad); }
  .detail { color: var(--ink3); font-size: 12px; line-height: 18px; min-height: 18px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 2px; }
</style>
