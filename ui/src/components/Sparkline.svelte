<script lang="ts">
  let { values, percent = true, span = 60, height = 34 }: { values: number[]; percent?: boolean; span?: number; height?: number } = $props();
  let width = $state(200);
  const id = `s${Math.random().toString(36).slice(2, 9)}`;
  const top = $derived(percent ? 100 : Math.max(1, ...values) * 1.15);
  // The newest sample sits at the right edge; a short history leaves the left part empty.
  const slots = $derived(Math.max(span, values.length, 2));
  const points = $derived(
    values.map((v, i) => [((slots - values.length + i) / (slots - 1)) * width, height - Math.min(1, v / top) * (height - 2) - 1]),
  );
  const line = $derived(points.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(""));
  const left = $derived(points.length ? points[0][0] : width);
</script>

<div class="spark" bind:clientWidth={width} style:height="{height}px">
  <svg {width} {height} aria-hidden="true">
    <defs>
      <linearGradient {id} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="var(--chart)" stop-opacity="0.3" />
        <stop offset="1" stop-color="var(--chart)" stop-opacity="0.02" />
      </linearGradient>
    </defs>
    {#if points.length > 1}<path d="{line}L{width},{height}L{left},{height}Z" fill="url(#{id})" />{/if}
    <path d={line} fill="none" stroke="var(--chart)" stroke-width="1.4" stroke-linejoin="round" />
  </svg>
</div>

<style>
  .spark { width: 100%; }
  svg { display: block; }
</style>
