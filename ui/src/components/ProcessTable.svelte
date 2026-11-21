<script lang="ts">
  import { tick, untrack } from "svelte";
  import { age, num, pct } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { iconOf } from "../lib/icons.svelte";
  import { SECTIONS, displayName, groupProcesses, processKey, type Picked, type Section } from "../lib/process-groups";
  import type { GpuUse, ProcessRow } from "../lib/types";

  export type View = "grouped" | "tree" | "list";
  /** Whole-computer use in percent, shown above the column labels. */
  export interface Totals { cpu: number; memory: number; disk: number; gpu: number; vram: number }

  let {
    rows,
    gpu = [],
    filter = "",
    view = "grouped",
    marks = new Map(),
    selected = $bindable(null),
    picked = $bindable(null),
    hold = false,
    held = $bindable(false),
    totals = null,
    memoryTotal = 0,
    vramTotal = 0,
    onopen,
  }: {
    rows: ProcessRow[];
    gpu?: GpuUse[];
    filter?: string;
    view?: View;
    /** Lower-case exe path -> verdict of the matching finding (remove, disable, review). */
    marks?: Map<string, string>;
    selected?: string | null;
    /** Out: the process (or group) the selection stands for. */
    picked?: Picked | null;
    /** Keep the order of the rows (the parent has a menu or a confirmation open). */
    hold?: boolean;
    /** Out: the order is being held (for a note under the table). */
    held?: boolean;
    totals?: Totals | null;
    /** Physical memory and dedicated video memory in bytes, the scale of the heat map. */
    memoryTotal?: number;
    vramTotal?: number;
    onopen?: (row: ProcessRow) => void;
  } = $props();

  // While the pointer is over the rows (or the parent holds), existing rows keep their position so the
  // row under the pointer does not move away from a click; values keep updating. New rows follow their
  // siblings. An explicit sort, filter or view change applies at once.
  let pointer = $state(false);
  const holding = $derived(pointer || hold);
  $effect(() => {
    held = holding;
  });
  let ranks: Map<string, number> | null = null;
  let rankedFor = "";
  const markColor = (verdict: string | undefined) => (verdict ? `var(--${verdict.replace("_", "-")})` : "");

  const ROW = 28;
  const MB = 1048576;
  const gpuByPid = $derived(new Map(gpu.map((g) => [g.pid, g])));

  interface Values { cpu: number; mem: number; io: number; gpu: number; vram: number; suspended: boolean }
  interface RowItem {
    kind: "row";
    key: string;
    depth: number;
    label: string;
    row: ProcessRow;
    count: number;
    twisty: "" | "open" | "closed";
    icon: string;
    v: Values;
  }
  interface SectionItem { kind: "section"; key: string; label: string }
  type Item = RowItem | SectionItem;

  function values(members: ProcessRow[]): Values {
    const v: Values = { cpu: 0, mem: 0, io: 0, gpu: 0, vram: 0, suspended: members.length > 0 };
    for (const m of members) {
      const g = gpuByPid.get(m.pid);
      v.cpu += m.cpu;
      v.mem += m.privateBytes;
      v.io += m.ioBps;
      v.gpu += g?.utilization ?? 0;
      v.vram += g?.dedicated ?? 0;
      v.suspended &&= m.status === "suspended";
    }
    v.gpu = Math.min(100, v.gpu);
    return v;
  }

  // Heat map: the share of the resource a row uses, in five steps (Task Manager's tint).
  const heat = (share: number) => (share >= 0.4 ? 4 : share >= 0.15 ? 3 : share >= 0.05 ? 2 : share >= 0.01 ? 1 : 0);
  const DISK_SCALE = 100 * MB; // 100 MB/s reads as a busy disk

  interface Col {
    key: string;
    title: Key;
    width: string;
    numeric?: boolean;
    tip?: Key;
    total?: (totals: Totals) => number;
    share?: (v: Values) => number;
    value: (i: RowItem) => number | string;
    text: (i: RowItem) => string;
  }

  const zero = (unit: Key) => `${num(0)} ${t(unit)}`;
  const COLS: Col[] = [
    { key: "name", title: "table.name", width: "minmax(260px, 1.6fr)", value: (i) => i.label.toLowerCase(), text: (i) => i.label },
    { key: "status", title: "table.status", width: "92px", value: (i) => Number(i.v.suspended),
      text: (i) => (i.v.suspended ? t("table.suspended") : "") },
    { key: "pid", title: "table.pid", width: "68px", numeric: true, value: (i) => i.row.pid,
      text: (i) => (i.count > 1 ? "" : String(i.row.pid)) },
    { key: "cpu", title: "table.cpu", width: "76px", numeric: true, total: (x) => x.cpu, share: (v) => v.cpu / 100,
      value: (i) => i.v.cpu, text: (i) => (i.v.cpu >= 0.05 ? pct(i.v.cpu, 1) : pct(0)) },
    { key: "mem", title: "table.memory", width: "100px", numeric: true, tip: "table.memoryTip", total: (x) => x.memory,
      share: (v) => (memoryTotal ? v.mem / memoryTotal : 0), value: (i) => i.v.mem,
      text: (i) => `${num(i.v.mem / MB, 1)} ${t("unit.MB")}` },
    { key: "io", title: "table.disk", width: "88px", numeric: true, tip: "table.diskTip", total: (x) => x.disk,
      share: (v) => v.io / DISK_SCALE, value: (i) => i.v.io,
      text: (i) => (i.v.io / MB >= 0.05 ? `${num(i.v.io / MB, 1)} ${t("unit.MBps")}` : zero("unit.MBps")) },
    { key: "gpu", title: "table.gpu", width: "64px", numeric: true, tip: "table.gpuTip", total: (x) => x.gpu,
      share: (v) => v.gpu / 100, value: (i) => i.v.gpu, text: (i) => pct(i.v.gpu) },
    { key: "vram", title: "table.vram", width: "96px", numeric: true, tip: "table.vramTip", total: (x) => x.vram,
      share: (v) => (vramTotal ? v.vram / vramTotal : 0), value: (i) => i.v.vram,
      text: (i) => (i.v.vram ? `${num(i.v.vram / MB, 1)} ${t("unit.MB")}` : zero("unit.MB")) },
    { key: "user", title: "table.user", width: "128px", value: (i) => i.row.user.toLowerCase(),
      text: (i) => i.row.user.split("\\").pop() ?? "" },
    { key: "started", title: "table.started", width: "76px", numeric: true, value: (i) => -i.row.createdMs,
      text: (i) => age(i.row.createdMs) },
    { key: "path", title: "table.path", width: "minmax(240px, 2fr)", value: (i) => i.row.exe.toLowerCase(), text: (i) => i.row.exe },
  ];
  const template = COLS.map((c) => c.width).join(" ");
  const MIN_WIDTH = 260 + 240 + COLS.slice(1, -1).reduce((sum, c) => sum + parseInt(c.width, 10), 0);

  let sortKey = $state("name");
  let descending = $state(false);
  /** Tree view: branches the user closed (open by default). Grouped view: groups the user opened or closed. */
  let treeClosed = $state<Record<string, boolean>>({});
  let groupOpen = $state<Record<string, boolean>>({});

  function sortBy(key: string): void {
    ranks = null;
    if (sortKey === key) descending = !descending;
    else {
      sortKey = key;
      descending = COLS.find((c) => c.key === key)?.numeric ?? false;
    }
  }

  const grouping = $derived(groupProcesses(rows));
  const rowByKey = $derived(new Map(rows.map((r) => [processKey(r), r])));
  const parentByPid = $derived(new Map(rows.map((r) => [r.pid, r])));
  const SECTION_LABEL: Record<Section, Key> = { apps: "proc.groupApps", background: "proc.groupBackground", windows: "proc.groupWindows" };

  const flat: Item[] = $derived.by(() => {
    const col = COLS.find((c) => c.key === sortKey) ?? COLS[0];
    const context = `${view}|${filter}`;
    if (context !== rankedFor) {
      ranks = null;
      rankedFor = context;
    }
    const frozen = holding ? ranks : null;
    const compare = (a: RowItem, b: RowItem) => {
      if (frozen) {
        const ra = frozen.get(a.key), rb = frozen.get(b.key);
        if (ra !== undefined && rb !== undefined) return ra - rb;
        if (ra !== undefined) return -1;
        if (rb !== undefined) return 1;
      }
      const x = col.value(a), y = col.value(b);
      const order = x < y ? -1 : x > y ? 1 : a.row.pid - b.row.pid;
      return descending ? -order : order;
    };
    const remember = (items: Item[]): Item[] => {
      if (!frozen) ranks = new Map(items.map((item, i) => [item.key, i]));
      return items;
    };
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    const matches = (r: ProcessRow) =>
      !words.length || words.every((w) => `${r.name} ${r.description} ${r.pid} ${r.user} ${r.exe}`.toLowerCase().includes(w));
    const single = (r: ProcessRow, depth: number, label: string, twisty: RowItem["twisty"] = ""): RowItem =>
      ({ kind: "row", key: processKey(r), depth, label, row: r, count: 1, twisty, icon: r.exe, v: values([r]) });

    if (view === "list") return remember(rows.filter(matches).map((r) => single(r, 0, r.name)).sort(compare));

    if (view === "grouped") {
      const out: Item[] = [];
      for (const section of SECTIONS) {
        const items: { item: RowItem; members: RowItem[] }[] = [];
        for (const entry of grouping.entries) {
          if (entry.section !== section) continue;
          const shown = entry.members.filter(matches);
          if (!shown.length) continue;
          const group = entry.members.length > 1;
          const open = group && (groupOpen[entry.key] ?? words.length > 0);
          items.push({
            item: {
              kind: "row", key: entry.key, depth: 0, row: entry.main, count: entry.members.length, icon: entry.icon,
              label: group ? t("table.withCount", { name: entry.label, count: num(entry.members.length) }) : entry.label,
              twisty: group ? (open ? "open" : "closed") : "", v: values(entry.members),
            },
            members: open ? shown.map((m) => single(m, 1, displayName(m))).sort(compare) : [],
          });
        }
        if (!items.length) continue;
        out.push({ kind: "section", key: `s:${section}`,
                   label: t("table.withCount", { name: t(SECTION_LABEL[section]), count: num(items.length) }) });
        for (const { item, members } of items.sort((a, b) => compare(a.item, b.item))) out.push(item, ...members);
      }
      return remember(out);
    }

    // Tree: every process under the process that started it.
    const kids = new Map<string, ProcessRow[]>();
    const roots: ProcessRow[] = [];
    for (const r of rows) {
      const p = parentByPid.get(r.ppid);
      if (p && p.pid !== r.pid && p.createdMs <= r.createdMs) {
        const k = processKey(p);
        const list = kids.get(k);
        if (list) list.push(r);
        else kids.set(k, [r]);
      } else roots.push(r);
    }
    const visible = new Map<string, boolean>();
    const check = (r: ProcessRow, depth: number): boolean => {
      const k = processKey(r);
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
      const items = list.filter((r) => visible.get(processKey(r))).map((r) => {
        const shown = (kids.get(processKey(r)) ?? []).filter((c) => visible.get(processKey(c)));
        const open = !treeClosed[processKey(r)] || words.length > 0;
        return { item: single(r, depth, r.name, shown.length ? (open ? "open" : "closed") : ""), shown, open };
      });
      for (const { item, shown, open } of items.sort((a, b) => compare(a.item, b.item))) {
        out.push(item);
        if (shown.length && open) walk(shown, depth + 1);
      }
    };
    walk(roots, 0);
    return remember(out);
  });
  // What the selection stands for, for the command bar and the inspector of the page.
  $effect(() => {
    let next: Picked | null = null;
    if (selected?.startsWith("g:")) {
      const entry = grouping.byKey.get(selected);
      const row = entry?.main ?? rowByKey.get(selected.slice(2));
      if (row) next = { row, label: entry?.label ?? displayName(row), count: entry?.members.length ?? 1, members: entry?.members ?? [row] };
    } else if (selected) {
      const row = rowByKey.get(selected);
      if (row) next = { row, label: view === "grouped" ? displayName(row) : row.name, count: 1, members: [row] };
    }
    picked = next;
  });

  // A group key only exists in the grouped view: elsewhere the selection moves to the group's main process.
  $effect(() => {
    if (view !== "grouped" && selected?.startsWith("g:")) selected = selected.slice(2);
  });

  // A process selected from elsewhere (another page, the keyboard) opens its group and scrolls into view.
  $effect(() => {
    const key = selected;
    const grouped = view === "grouped";
    if (!key) return;
    untrack(() => {
      if (grouped && !key.startsWith("g:")) {
        const entry = grouping.of.get(key);
        if (entry && entry.members.length > 1 && !(groupOpen[entry.key] ?? false)) groupOpen[entry.key] = true;
      }
      void tick().then(reveal);
    });
  });

  let scroller: HTMLDivElement | undefined = $state();
  let head: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let viewHeight = $state(600);
  let rowsWidth = $state(0);
  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 8));
  const end = $derived(Math.min(flat.length, Math.ceil((scrollTop + viewHeight) / ROW) + 8));
  const window_ = $derived(flat.slice(start, end));

  function reveal(): void {
    const index = flat.findIndex((item) => item.key === selected);
    if (!scroller || index < 0) return;
    const y = index * ROW;
    if (y < scroller.scrollTop) scroller.scrollTop = y;
    else if (y + ROW > scroller.scrollTop + viewHeight) scroller.scrollTop = y + ROW * 2 - viewHeight;
  }

  function toggle(item: RowItem, event?: MouseEvent): void {
    event?.stopPropagation();
    const open = item.twisty !== "open";
    if (view === "tree") treeClosed[item.key] = !open;
    else {
      groupOpen[item.key] = open;
      // Closing a group that holds the selected process selects the group.
      if (!open && selected && grouping.of.get(selected)?.key === item.key) selected = item.key;
    }
  }

  function onscroll(): void {
    if (!scroller) return;
    scrollTop = scroller.scrollTop;
    if (head) head.scrollLeft = scroller.scrollLeft;
  }

  function onkey(event: KeyboardEvent): void {
    const keys = ["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "Home", "End", "Enter"];
    if (!flat.length || !keys.includes(event.key)) return;
    event.preventDefault();
    const rowsOnly = flat.filter((item): item is RowItem => item.kind === "row");
    const index = rowsOnly.findIndex((item) => item.key === selected);
    const current = rowsOnly[index];
    if (event.key === "Enter") {
      if (current) onopen?.(current.row);
      return;
    }
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      const opening = event.key === "ArrowRight";
      if (current?.twisty === (opening ? "closed" : "open")) toggle(current);
      else if (!opening && current?.depth) {
        // Left on a member goes to its group (grouped view) or its parent (tree).
        for (let i = index - 1; i >= 0; i--) {
          if (rowsOnly[i].depth < current.depth) {
            selected = rowsOnly[i].key;
            break;
          }
        }
      }
      return;
    }
    const next = event.key === "Home" ? 0 : event.key === "End" ? rowsOnly.length - 1
      : Math.min(rowsOnly.length - 1, Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)));
    selected = rowsOnly[next].key;
  }
</script>

<div class="table">
  <div class="head-wrap" bind:this={head}>
    <div class="head" style:grid-template-columns={template} style:width={rowsWidth ? `${rowsWidth}px` : ""}
         style:min-width="{MIN_WIDTH}px">
      {#each COLS as col (col.key)}
        <button class="th" class:numeric={col.numeric} class:sorted={sortKey === col.key} title={col.tip ? t(col.tip) : ""}
                onclick={() => sortBy(col.key)}>
          {#if sortKey === col.key}<i class="icon caret">{descending ? "" : ""}</i>{/if}
          <span class="total num">{col.total && totals ? pct(col.total(totals)) : ""}</span>
          <span class="label">{t(col.title)}</span>
        </button>
      {/each}
    </div>
  </div>
  <div
    class="scroller"
    bind:this={scroller}
    bind:clientHeight={viewHeight}
    {onscroll}
    onpointerenter={() => (pointer = true)}
    onpointerleave={() => (pointer = false)}
    onkeydown={onkey}
    tabindex="0"
    role="grid"
    aria-rowcount={flat.length}
  >
    <div class="rows" style:height="{flat.length * ROW}px" style:min-width="{MIN_WIDTH}px" bind:clientWidth={rowsWidth}>
      {#each window_ as item, i (item.key)}
        {#if item.kind === "section"}
          <div class="row section" style:transform="translateY({(start + i) * ROW}px)" role="row">
            <span>{item.label}</span>
          </div>
        {:else}
          {@const mark = marks.get(item.row.exe.toLowerCase())}
          {@const icon = iconOf(item.icon)}
          <div
            class="row"
            class:sel={selected === item.key}
            class:suspended={item.v.suspended}
            style:transform="translateY({(start + i) * ROW}px)"
            style:grid-template-columns={template}
            onclick={() => (selected = item.key)}
            ondblclick={() => (item.twisty ? toggle(item) : onopen?.(item.row))}
            role="row"
            tabindex="-1"
            aria-selected={selected === item.key}
            aria-expanded={item.twisty ? item.twisty === "open" : undefined}
            onkeydown={() => {}}
          >
            <div class="cell name" style:padding-left="{(view === 'list' ? 10 : 4) + item.depth * 22}px">
              {#if item.twisty}
                <button class="twisty icon" tabindex="-1" onclick={(e) => toggle(item, e)} aria-label={t("table.expand")}>
                  {item.twisty === "open" ? "" : ""}
                </button>
              {:else if view !== "list"}
                <span class="twisty"></span>
              {/if}
              {#if icon}<img class="app-icon" src={icon} alt="" />{:else}<i class="icon app-icon generic">{""}</i>{/if}
              <span class="text" title={item.count > 1 ? item.label : item.row.cmdline || item.row.name}>{item.label}</span>
              {#if mark}
                <span class="mark" style:background={markColor(mark)} title={t("table.findingMark")}></span>
              {/if}
            </div>
            {#each COLS.slice(1) as col (col.key)}
              {@const level = col.share ? heat(col.share(item.v)) : -1}
              <div class="cell" class:numeric={col.numeric} class:heat={level >= 0} style:--heat={level >= 0 ? `var(--heat-${level})` : null}
                   title={col.key === "path" ? item.row.exe : col.key === "user" ? item.row.user : ""}>
                {col.text(item)}
              </div>
            {/each}
          </div>
        {/if}
      {/each}
    </div>
  </div>
</div>

<style>
  .table { flex: 1; min-height: 0; display: flex; flex-direction: column; min-width: 0; }
  .head-wrap { overflow: hidden; flex: none; border-bottom: 1px solid var(--rule); }
  .head { display: grid; }
  .th {
    position: relative; display: flex; flex-direction: column; align-items: flex-start; justify-content: flex-end; gap: 0;
    min-height: 0; height: 52px; padding: 4px 8px 6px; border: 0; border-radius: 0; background: transparent;
    color: var(--ink2); font-size: 12px; line-height: 16px; font-weight: 400; text-align: left; white-space: nowrap;
  }
  .th + .th { border-left: 1px solid var(--rule); }
  .th:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  .th:active:not(:disabled) { background: var(--pressed); border-bottom-color: transparent; }
  .th.numeric { align-items: flex-end; }
  .th .total { font-size: 15px; line-height: 20px; color: var(--ink); font-weight: 400; min-height: 20px; }
  .th .label { max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
  .th.sorted .label { color: var(--ink); }
  .caret { position: absolute; top: 2px; left: 50%; transform: translateX(-50%); font-size: 8px; color: var(--ink2); }
  .scroller { flex: 1; min-height: 0; overflow: auto; outline: none; }
  .scroller:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; border-radius: 0; }
  .rows { position: relative; }
  .row {
    position: absolute; left: 0; right: 0; top: 0; height: 28px; display: grid; align-items: stretch; font-size: 13px;
    cursor: default;
  }
  /* Hover and selection lie over the heat-map tint instead of hiding it. */
  .row::after { content: ""; position: absolute; inset: 0; pointer-events: none; }
  .row:hover::after { background: var(--hover); }
  .row.sel::after { background: var(--table-select); }
  .row.suspended .cell { color: var(--ink3); }
  .row.section {
    display: flex; align-items: flex-end; padding: 0 0 4px 12px; font-weight: 600; font-size: 14px; color: var(--ink);
  }
  .row.section::after { display: none; }
  .cell {
    padding: 0 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; line-height: 28px;
  }
  .cell.numeric { text-align: right; font-variant-numeric: tabular-nums; }
  .cell.heat { background: var(--heat); box-shadow: inset 1px 0 0 var(--heat-rule); }
  .cell.name { display: flex; align-items: center; gap: 6px; }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .app-icon { flex: none; width: 16px; height: 16px; }
  .app-icon.generic { font-size: 16px; color: var(--ink2); }
  .mark { flex: none; width: 8px; height: 8px; border-radius: 4px; margin-left: auto; margin-right: 4px; }
  .twisty {
    flex: none; width: 20px; height: 20px; min-height: 0; padding: 0; border: 0; border-radius: var(--radius);
    background: transparent; color: var(--ink2); font-size: 10px; display: inline-flex; align-items: center;
    justify-content: center;
  }
  button.twisty:hover:not(:disabled) { color: var(--ink); background: var(--hover); }
</style>
