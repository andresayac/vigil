<script module lang="ts">
export interface TreeNode {
  name: string;
  path: string;
  size: number;
  files: number;
  isDir: boolean;
  children: TreeNode[];
  other: number;
}
</script>

<script lang="ts">
  import { size as fmtSize } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";

  let { node, onopen }: { node: TreeNode | null; onopen?: (child: TreeNode) => void } = $props();

  let width = $state(600);
  let height = $state(360);
  let hover = $state<string | null>(null);

  interface Box { x: number; y: number; w: number; h: number; node: TreeNode | null; index: number }

  /** Squarified treemap (Bruls, Huizing and van Wijk): rows whose aspect ratios stay close to 1. */
  function layout(entries: { area: number; node: TreeNode | null }[], x0: number, y0: number, w0: number, h0: number): Box[] {
    const out: Box[] = [];
    let items = entries;
    let x = x0, y = y0, w = w0, h = h0;
    const worst = (row: number[], side: number) => {
      const total = row.reduce((a, b) => a + b, 0);
      if (!total || !side) return Infinity;
      const max = Math.max(...row), min = Math.min(...row);
      if (min <= 0) return Infinity;
      return Math.max((side * side * max) / (total * total), (total * total) / (side * side * min));
    };
    while (items.length) {
      const side = Math.min(w, h);
      if (side <= 0) break;
      let count = 1;
      while (count < items.length &&
             worst(items.slice(0, count + 1).map((i) => i.area), side) <= worst(items.slice(0, count).map((i) => i.area), side)) {
        count += 1;
      }
      const row = items.slice(0, count);
      items = items.slice(count);
      const area = row.reduce((a, i) => a + i.area, 0);
      const thickness = area / side;
      let offset = 0;
      for (const item of row) {
        const length = thickness ? item.area / thickness : 0;
        if (w >= h) out.push({ x, y: y + offset, w: thickness, h: length, node: item.node, index: out.length });
        else out.push({ x: x + offset, y, w: length, h: thickness, node: item.node, index: out.length });
        offset += length;
      }
      if (w >= h) { x += thickness; w -= thickness; } else { y += thickness; h -= thickness; }
    }
    return out;
  }

  const boxes: Box[] = $derived.by(() => {
    if (!node) return [];
    const entries: { size: number; node: TreeNode | null }[] = node.children.filter((c) => c.size > 0).map((c) => ({ size: c.size, node: c }));
    if (node.other > 0) entries.push({ size: node.other, node: null });
    const total = entries.reduce((a, e) => a + e.size, 0);
    if (!total || width < 4 || height < 4) return [];
    const scale = (width * height) / total;
    return layout(entries.sort((a, b) => b.size - a.size).map((e) => ({ area: e.size * scale, node: e.node })), 0, 0, width, height);
  });

  function fill(box: Box): string {
    if (!box.node) return "color-mix(in srgb, var(--ink3) 35%, var(--sunken))";
    if (!box.node.isDir) return "color-mix(in srgb, var(--chart2) 55%, var(--surface))";
    return `color-mix(in srgb, var(--chart) ${78 - ((box.index % 5) * 40) / 5}%, var(--surface))`;
  }
</script>

<div class="map" bind:clientWidth={width} bind:clientHeight={height}>
  {#if !boxes.length}
    <p class="faint empty">{t("treemap.empty")}</p>
  {/if}
  {#each boxes as box (box.node?.path ?? "other")}
    {@const label = box.node ? box.node.name : t("treemap.other")}
    {@const bytes = box.node ? box.node.size : (node?.other ?? 0)}
    <button
      class="box"
      class:hover={hover === (box.node?.path ?? "other")}
      class:dark={box.index % 5 < 2 && box.node?.isDir}
      style:left="{box.x}px" style:top="{box.y}px" style:width="{box.w}px" style:height="{box.h}px"
      style:background={fill(box)}
      title="{box.node?.path ?? t('treemap.other')}&#10;{fmtSize(bytes)}"
      onmouseenter={() => (hover = box.node?.path ?? "other")}
      onmouseleave={() => (hover = null)}
      onclick={() => box.node && box.node.isDir && box.node.children.length && onopen?.(box.node)}
    >
      {#if box.w > 56 && box.h > 30}
        <span class="name">{label}</span>
        {#if box.h > 46}<span class="size">{fmtSize(bytes)}</span>{/if}
      {/if}
    </button>
  {/each}
</div>

<style>
  .map { position: relative; flex: 1; min-height: 260px; background: var(--sunken); border: 1px solid var(--rule); border-radius: 7px; overflow: hidden; }
  .empty { position: absolute; inset: 0; display: grid; place-items: center; margin: 0; }
  .box {
    position: absolute; border: 1px solid var(--surface); border-radius: 0; padding: 4px 6px; text-align: left;
    display: flex; flex-direction: column; justify-content: flex-start; overflow: hidden; color: var(--ink);
    font-size: 12px; font-weight: 600; cursor: default;
  }
  .box.dark { color: var(--on-chart); }
  .box.hover { filter: brightness(1.12); }
  .name, .size { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }
  .size { font-weight: 400; opacity: 0.9; }
</style>
