<script lang="ts">
  import { age, num } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import type { GpuUse, ProcessRow } from "../lib/types";

  let {
    rows,
    gpu = [],
    filter = "",
    tree = true,
    marks = new Map(),
    selected = $bindable(null),
    hold = false,
    held = $bindable(false),
    onopen,
  }: {
    rows: ProcessRow[];
    gpu?: GpuUse[];
    filter?: string;
    tree?: boolean;
    /** Lower-case exe path -> verdict of the matching finding (remove, disable, review). */
    marks?: Map<string, string>;
    selected?: string | null;
    /** Keep the order of the rows (the parent has a menu or a confirmation open). */
    hold?: boolean;
    /** Out: the order is being held (for a note under the table). */
    held?: boolean;
    onopen?: (row: ProcessRow) => void;
  } = $props();

  // While the pointer is over the rows (or the parent holds), existing rows keep their position so the
  // row under the pointer does not move away from a click; values keep updating. New rows follow their
  // siblings. An explicit sort or filter change applies at once.
  let pointer = $state(false);
  const holding = $derived(pointer || hold);
  $effect(() => {
    held = holding;
  });
  let ranks: Map<string, number> | null = null;
  let rankedFilter = "";
  const markColor = (verdict: string | undefined) => (verdict ? `var(--${verdict.replace("_", "-")})` : "");

  const ROW = 26;
  const keyOf = (r: ProcessRow) => `${r.pid}:${r.createdMs}`;
  const gpuByPid = $derived(new Map(gpu.map((g) => [g.pid, g])));
  const mb = (bytes: number) => num(bytes / 1048576, 1);

  interface Col {
    key: string;
    title: Key;
    width: string;
    numeric?: boolean;
    tip?: Key;
    value: (r: ProcessRow) => number | string;
    text: (r: ProcessRow) => string;
  }

  const COLS: Col[] = [
    { key: "name", title: "table.name", width: "minmax(220px, 1.3fr)", value: (r) => r.name.toLowerCase(), text: (r) => r.name },
    { key: "pid", title: "table.pid", width: "68px", numeric: true, value: (r) => r.pid, text: (r) => String(r.pid) },
    { key: "cpu", title: "table.cpu", width: "84px", numeric: true, value: (r) => r.cpu,
      text: (r) => (r.status === "suspended" ? t("table.suspended") : r.cpu >= 0.05 ? num(r.cpu, 1) : "") },
    { key: "mem", title: "table.memory", width: "104px", numeric: true, value: (r) => r.privateBytes,
      tip: "table.memoryTip", text: (r) => mb(r.privateBytes) },
    { key: "io", title: "table.disk", width: "90px", numeric: true, value: (r) => r.ioBps,
      tip: "table.diskTip", text: (r) => (r.ioBps / 1048576 >= 0.05 ? num(r.ioBps / 1048576, 1) : "") },
    { key: "gpu", title: "table.gpu", width: "64px", numeric: true, value: (r) => gpuByPid.get(r.pid)?.utilization ?? 0,
      tip: "table.gpuTip",
      text: (r) => { const u = gpuByPid.get(r.pid)?.utilization ?? 0; return u >= 0.5 ? num(u) : ""; } },
    { key: "vram", title: "table.vram", width: "88px", numeric: true, value: (r) => gpuByPid.get(r.pid)?.dedicated ?? 0,
      tip: "table.vramTip",
      text: (r) => { const d = gpuByPid.get(r.pid)?.dedicated ?? 0; return d ? num(d / 1048576) : ""; } },
    { key: "user", title: "table.user", width: "140px", value: (r) => r.user.toLowerCase(), text: (r) => r.user.split("\\").pop() ?? "" },
    { key: "started", title: "table.started", width: "76px", numeric: true, value: (r) => -r.createdMs, text: (r) => age(r.createdMs) },
    { key: "path", title: "table.path", width: "minmax(260px, 2fr)", value: (r) => r.exe.toLowerCase(), text: (r) => r.exe },
  ];
  const template = COLS.map((c) => c.width).join(" ");

  let sortKey = $state("name");
  let descending = $state(false);
  let collapsed = $state<Record<string, boolean>>({});

  function sortBy(key: string): void {
    ranks = null;
    if (sortKey === key) descending = !descending;
    else {
      sortKey = key;
      descending = COLS.find((c) => c.key === key)?.numeric ?? false;
    }
  }

  interface Item { row: ProcessRow; depth: number; children: number }

  const flat: Item[] = $derived.by(() => {
    const col = COLS.find((c) => c.key === sortKey) ?? COLS[0];
    if (filter !== rankedFilter) {
      ranks = null;
      rankedFilter = filter;
    }
    const frozen = holding ? ranks : null;
    const compare = (a: ProcessRow, b: ProcessRow) => {
      if (frozen) {
        const ra = frozen.get(keyOf(a)), rb = frozen.get(keyOf(b));
        if (ra !== undefined && rb !== undefined) return ra - rb;
        if (ra !== undefined) return -1;
        if (rb !== undefined) return 1;
      }
      const x = col.value(a), y = col.value(b);
      const order = x < y ? -1 : x > y ? 1 : a.pid - b.pid;
      return descending ? -order : order;
    };
    const remember = (items: Item[]): Item[] => {
      if (!frozen) ranks = new Map(items.map((item, i) => [keyOf(item.row), i]));
      return items;
    };
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    const matches = (r: ProcessRow) =>
      !words.length || words.every((w) => `${r.name} ${r.pid} ${r.user} ${r.exe}`.toLowerCase().includes(w));
    if (!tree) return remember(rows.filter(matches).sort(compare).map((row) => ({ row, depth: 0, children: 0 })));

    const byPid = new Map(rows.map((r) => [r.pid, r]));
    const kids = new Map<string, ProcessRow[]>();
    const roots: ProcessRow[] = [];
    for (const r of rows) {
      const parent = byPid.get(r.ppid);
      // A parent must have started before its child; otherwise the PID was reused.
      if (parent && parent.pid !== r.pid && parent.createdMs <= r.createdMs) {
        const k = keyOf(parent);
        const list = kids.get(k);
        if (list) list.push(r);
        else kids.set(k, [r]);
      } else roots.push(r);
    }
    const visible = new Map<string, boolean>();
    const check = (r: ProcessRow, depth: number): boolean => {
      const k = keyOf(r);
      const known = visible.get(k);
      if (known !== undefined || depth > 64) return known ?? false;
      let show = matches(r);
      for (const child of kids.get(k) ?? []) show = check(child, depth + 1) || show;
      visible.set(k, show);
      return show;
    };
    for (const r of roots) check(r, 0);

    const out: Item[] = [];
    const walk = (list: ProcessRow[], depth: number) => {
      if (depth > 64) return;
      for (const r of [...list].sort(compare)) {
        const k = keyOf(r);
        if (!visible.get(k)) continue;
        const shown = (kids.get(k) ?? []).filter((c) => visible.get(keyOf(c)));
        out.push({ row: r, depth, children: shown.length });
        if (shown.length && (!collapsed[k] || words.length)) walk(shown, depth + 1);
      }
    };
    walk(roots, 0);
    return remember(out);
  });

  let scroller: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let viewHeight = $state(600);
  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 8));
  const end = $derived(Math.min(flat.length, Math.ceil((scrollTop + viewHeight) / ROW) + 8));
  const window_ = $derived(flat.slice(start, end));

  function toggle(key: string, event: MouseEvent): void {
    event.stopPropagation();
    collapsed[key] = !collapsed[key];
  }

  function onkey(event: KeyboardEvent): void {
    if (!flat.length || !["ArrowDown", "ArrowUp", "Home", "End", "Enter"].includes(event.key)) return;
    event.preventDefault();
    const index = flat.findIndex((item) => keyOf(item.row) === selected);
    if (event.key === "Enter") {
      if (index >= 0) onopen?.(flat[index].row);
      return;
    }
    const next = event.key === "Home" ? 0 : event.key === "End" ? flat.length - 1
      : Math.min(flat.length - 1, Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)));
    selected = keyOf(flat[next].row);
    if (scroller) {
      const y = next * ROW;
      if (y < scroller.scrollTop) scroller.scrollTop = y;
      else if (y + ROW * 2 > scroller.scrollTop + viewHeight) scroller.scrollTop = y + ROW * 2 - viewHeight;
    }
  }
</script>

<div
  class="scroller"
  bind:this={scroller}
  bind:clientHeight={viewHeight}
  onscroll={() => (scrollTop = scroller?.scrollTop ?? 0)}
  onpointerenter={() => (pointer = true)}
  onpointerleave={() => (pointer = false)}
  onkeydown={onkey}
  tabindex="0"
  role="grid"
  aria-rowcount={flat.length}
>
  <div class="inner">
    <div class="head" style:grid-template-columns={template}>
      {#each COLS as col (col.key)}
        <button class="th" class:numeric={col.numeric} title={col.tip ? t(col.tip) : ""} onclick={() => sortBy(col.key)}>
          {t(col.title)}{#if sortKey === col.key}<i class="icon arrow">{descending ? "\uE70D" : "\uE70E"}</i>{/if}
        </button>
      {/each}
    </div>
    <div class="rows" style:height="{flat.length * ROW}px">
      {#each window_ as item, i (keyOf(item.row))}
        {@const key = keyOf(item.row)}
        <div
          class="row"
          class:sel={selected === key}
          class:odd={(start + i) % 2 === 1}
          class:suspended={item.row.status === "suspended"}
          style:transform="translateY({(start + i) * ROW}px)"
          style:grid-template-columns={template}
          onclick={() => (selected = key)}
          ondblclick={() => onopen?.(item.row)}
          role="row"
          tabindex="-1"
          onkeydown={() => {}}
        >
          <div class="cell name" style:padding-left="{6 + item.depth * 16}px">
            {#if tree && item.children}
              <button class="twisty icon" onclick={(e) => toggle(key, e)} aria-label={t("table.expand")}>
                {collapsed[key] ? "\uE76C" : "\uE70D"}
              </button>
            {:else}
              <span class="twisty"></span>
            {/if}
            <span class="text" title={item.row.cmdline || item.row.name}>{item.row.name}</span>
            {#if marks.get(item.row.exe.toLowerCase())}
              <span class="mark" style:background={markColor(marks.get(item.row.exe.toLowerCase()))}
                    title={t("table.findingMark")}></span>
            {/if}
          </div>
          {#each COLS.slice(1) as col (col.key)}
            <div class="cell" class:numeric={col.numeric} title={col.key === "path" ? item.row.exe : col.key === "user" ? item.row.user : ""}>
              {col.text(item.row)}
            </div>
          {/each}
        </div>
      {/each}
    </div>
  </div>
</div>

<style>
  .scroller {
    flex: 1; min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--rule);
    border-radius: 8px; outline: none;
  }
  .scroller:focus-visible { border-color: var(--focus); }
  .inner { min-width: 1420px; }
  .head {
    display: grid; position: sticky; top: 0; z-index: 2; background: var(--surface);
    border-bottom: 1px solid var(--rule);
  }
  .th {
    border: 0; border-radius: 0; background: transparent; color: var(--ink2); font-size: 12px; font-weight: 600;
    text-align: left; padding: 8px 8px; white-space: nowrap; display: flex; align-items: center; gap: 4px;
  }
  .th:hover { color: var(--ink); background: transparent; }
  .th.numeric { justify-content: flex-end; }
  .arrow { font-size: 9px; }
  .rows { position: relative; }
  .row {
    position: absolute; left: 0; right: 0; top: 0; height: 26px; display: grid; align-items: center;
    font-size: 13px; cursor: default;
  }
  .row.odd { background: var(--surface2); }
  .row:hover { background: color-mix(in srgb, var(--select) 55%, var(--surface)); }
  .row.sel { background: var(--select); }
  .row.suspended .cell { color: var(--ink3); }
  .cell { padding: 0 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .cell.numeric { text-align: right; font-variant-numeric: tabular-nums; }
  .cell.name { display: flex; align-items: center; gap: 4px; }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .mark { flex: none; width: 8px; height: 8px; border-radius: 4px; margin-left: auto; margin-right: 4px; }
  .twisty {
    flex: none; width: 16px; height: 16px; padding: 0; border: 0; background: transparent; color: var(--ink3);
    font-size: 9px; display: inline-flex; align-items: center; justify-content: center;
  }
  button.twisty:hover { color: var(--ink); background: transparent; }
</style>
