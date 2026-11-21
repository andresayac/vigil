<script module lang="ts">
export interface Line {
  values: number[];
  name: string;
  dashed?: boolean;
}
/** A change made from Vigil, shown at the moment it ran (timing, not proof of cause). */
export interface Marker {
  ago: number;
  label: string;
}
</script>

<script lang="ts">
  import { ago, niceCeiling } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";

  // A Task Manager style history chart: caption and maximum above the plot, time span and minimum below,
  // a grid in the resource's hue (--chart, set by the page). The newest sample is at the right edge.
  let {
    lines,
    percent = true,
    format = (v: number) => `${Math.round(v)}%`,
    height = 220,
    span = 60,
    caption = "",
    cursor = $bindable(null),
    markers = [],
    onpin,
  }: {
    lines: Line[];
    percent?: boolean;
    format?: (v: number) => string;
    /** Total height, labels included. */
    height?: number;
    /** Samples across the width (one per second). */
    span?: number;
    /** Text above the plot on the left (Task Manager's "% Utilization"); the legend follows it. */
    caption?: string;
    /** Samples ago under the pointer (0 = newest), shared by the charts of a page. */
    cursor?: number | null;
    /** Vigil's own actions in the visible window. */
    markers?: Marker[];
    /** Click on the chart: keep this moment. */
    onpin?: () => void;
  } = $props();

  let width = $state(600);
  const id = `c${Math.random().toString(36).slice(2, 9)}`;
  const plotHeight = $derived(Math.max(40, height - 44));
  const top = $derived(percent ? 100 : niceCeiling(Math.max(1, ...lines.flatMap((l) => l.values)) * 1.1));

  // Older samples to the left; missing history stays empty (no invented zeros).
  const slots = $derived(Math.max(span, ...lines.map((l) => l.values.length), 2));
  const xAt = (ago: number) => ((slots - 1 - ago) / (slots - 1)) * width;
  const yAt = (v: number) => plotHeight - Math.min(1, v / top) * (plotHeight - 1);

  function path(values: number[]): string {
    return values
      .map((v, i) => `${i ? "L" : "M"}${xAt(values.length - 1 - i).toFixed(1)},${yAt(v).toFixed(1)}`)
      .join("");
  }

  const valueAt = (line: Line, ago: number): number | undefined => line.values[line.values.length - 1 - ago];
  const shown = (line: Line): number | undefined => valueAt(line, cursor ?? 0);
  const recorded = $derived(Math.max(0, ...lines.map((l) => l.values.length)));
  const spanText = $derived(
    recorded < slots - 1
      ? t("chart.recorded", { count: recorded })
      : slots >= 120 ? t("chart.minutes", { count: Math.round(slots / 60) }) : t("chart.seconds", { count: slots }),
  );

  function move(event: PointerEvent): void {
    const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const k = Math.round((1 - (event.clientX - box.left) / Math.max(1, box.width)) * (slots - 1));
    cursor = Math.min(slots - 1, Math.max(0, k));
  }
</script>

<div class="chart" style:height="{height}px">
  <div class="row">
    <span class="legend">
      {#if caption}<span class="caption">{caption}</span>{/if}
      {#each lines as line (line.name)}
        <span class="item"><span class="key" class:dashed={line.dashed}></span>{line.name}
          <b class="num">{shown(line) === undefined ? "—" : format(shown(line) ?? 0)}</b></span>
      {/each}
    </span>
    <span class="num">{format(top)}</span>
  </div>
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="plot" bind:clientWidth={width} style:height="{plotHeight}px" onpointermove={move}
       onpointerleave={() => (cursor = null)} onclick={() => onpin?.()} title={t("chart.hint")}>
    <svg {width} height={plotHeight} aria-hidden="true">
      <defs>
        <linearGradient {id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="var(--chart)" stop-opacity="0.34" />
          <stop offset="1" stop-color="var(--chart)" stop-opacity="0.12" />
        </linearGradient>
      </defs>
      {#each Array.from({ length: 9 }, (_, i) => i + 1) as step (step)}
        <line x1="0" x2={width} y1={(plotHeight * step) / 10} y2={(plotHeight * step) / 10} class="grid" />
      {/each}
      {#each Array.from({ length: 19 }, (_, i) => i + 1) as step (step)}
        <line y1="0" y2={plotHeight} x1={(width * step) / 20} x2={(width * step) / 20} class="grid" />
      {/each}
      {#each lines as line, index (line.name)}
        {@const d = path(line.values)}
        {#if index === 0 && line.values.length > 1}
          <path d="{d}L{width},{plotHeight}L{xAt(line.values.length - 1)},{plotHeight}Z" fill="url(#{id})" />
        {/if}
        <path {d} fill="none" class:dashed={line.dashed} class="line" />
      {/each}
      {#each markers.filter((m) => m.ago >= 0 && m.ago < slots) as m (`${m.ago}|${m.label}`)}
        <g class="marker">
          <title>{m.label} ({m.ago === 0 ? t("chart.now") : ago(m.ago)})</title>
          <line x1={xAt(m.ago)} x2={xAt(m.ago)} y1="0" y2={plotHeight} />
          <path d="M{xAt(m.ago) - 5},0 L{xAt(m.ago) + 5},0 L{xAt(m.ago)},7 Z" />
        </g>
      {/each}
      {#if cursor !== null}
        <line x1={xAt(cursor)} x2={xAt(cursor)} y1="0" y2={plotHeight} class="cursor" />
        {#each lines as line (line.name)}
          {@const v = valueAt(line, cursor)}
          {#if v !== undefined}<circle cx={xAt(cursor)} cy={yAt(v)} r="3.2" class="dot" />{/if}
        {/each}
      {/if}
    </svg>
  </div>
  <div class="row foot">
    <span>{spanText}</span>
    {#if cursor !== null && cursor > 0}<span class="at">{ago(cursor)}</span>{/if}
    <span class="num">0</span>
  </div>
</div>

<style>
  .chart { width: 100%; display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; font-size: 12px; line-height: 16px; color: var(--ink2); }
  .legend { display: flex; align-items: center; gap: 14px; min-width: 0; overflow: hidden; white-space: nowrap; }
  .caption { color: var(--ink2); }
  .item { display: inline-flex; align-items: center; gap: 6px; }
  .item b { color: var(--ink); font-weight: 600; }
  .key { width: 12px; height: 2px; background: var(--chart); }
  .key.dashed { background: repeating-linear-gradient(90deg, var(--chart) 0 3px, transparent 3px 5px); }
  .plot {
    position: relative; width: 100%; background: var(--sunken); cursor: crosshair; overflow: hidden;
    border: 1px solid color-mix(in srgb, var(--chart) 70%, transparent);
  }
  svg { display: block; position: absolute; inset: 0; }
  .grid { stroke: color-mix(in srgb, var(--chart) 14%, transparent); stroke-width: 1; }
  .line { stroke: var(--chart); stroke-width: 1.5; stroke-linejoin: round; }
  .line.dashed { stroke-dasharray: 4 3; }
  .marker line { stroke: var(--ink2); stroke-width: 1; stroke-dasharray: 2 3; }
  .marker path { fill: var(--ink2); }
  .marker { cursor: help; }
  .cursor { stroke: var(--ink2); stroke-width: 1; stroke-dasharray: 3 3; }
  .dot { fill: var(--chart); stroke: var(--sunken); stroke-width: 1.5; }
  .foot .at { color: var(--ink); font-weight: 600; }
</style>
