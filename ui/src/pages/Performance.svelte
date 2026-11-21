<script lang="ts">
  import { onMount } from "svelte";
  import CoreGrid from "../components/CoreGrid.svelte";
  import LineChart, { type Line, type Marker } from "../components/LineChart.svelte";
  import { journal } from "../lib/api";
  import Sparkline from "../components/Sparkline.svelte";
  import StackedBar, { type Segment } from "../components/StackedBar.svelte";
  import * as api from "../lib/api";
  import { num, pct, rate, size, uptime } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { PRIORITIES, priorityLabel } from "../lib/labels";
  import { acquire, live, release, series } from "../lib/live.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { Hardware, ProcessRow, Snapshot } from "../lib/types";

  // Task Manager's layout: the resources on the left (a live thumbnail and two lines each), the selected
  // one on the right (title, model, the large history chart, composition, statistics), then the processes
  // using it most, with their actions.
  let { cpuName, initial = null, elevated, onshowprocess }: {
    cpuName: string; initial?: string | null; elevated: boolean; onshowprocess: (pid: number) => void;
  } = $props();

  let selected = $state("cpu");
  $effect(() => {
    if (initial) selected = initial;
  });
  let paused = $state(false);
  // Changes made from Vigil in the last five minutes, marked on the charts (timing, not cause).
  let recent = $state<{ at: number; label: string }[]>([]);
  async function loadRecent(): Promise<void> {
    try {
      const since = Date.now() - 6 * 60_000;
      recent = (await journal())
        .filter((r) => r.ok && r.op !== "shell.location")
        .map((r) => ({ at: new Date(r.time).getTime(), label: r.label }))
        .filter((r) => Number.isFinite(r.at) && r.at >= since);
    } catch {
      recent = [];
    }
  }
  $effect(() => {
    void report.outcome;
    void loadRecent();
  });
  /** Seconds shown by the charts (the history keeps five minutes). */
  let range = $state(60);
  /** Samples ago under the pointer, shared by every chart of the page. */
  let cursor = $state<number | null>(null);
  const RANGES = [60, 120, 300];
  let frozen = $state<{ snap: Snapshot | null; history: Record<string, number[]>; processes: ProcessRow[]; at: number } | null>(null);
  let chosen = $state<{ pid: number; createdMs: number } | null>(null);
  let priorityOpen = $state(false);
  let hw = $state<Hardware | null>(null);

  function processAct(op: string, priority?: string): void {
    if (chosen) void act({ kind: "process", op, pid: chosen.pid, createdMs: chosen.createdMs, priority });
    priorityOpen = false;
  }

  onMount(() => {
    void acquire();
    // Model names, memory type and speed, disk media: read once (Rust caches it), never blocks the page.
    void api.hardware().then((h) => (hw = h)).catch(() => {});
    return () => void release();
  });

  $effect(() => {
    if (paused && !frozen) frozen = { snap: live.snapshot, history: { ...live.history }, processes: live.processes, at: Date.now() };
    if (!paused && frozen) frozen = null;
  });

  const snap = $derived(frozen ? frozen.snap : live.snapshot);
  const processes = $derived(frozen ? frozen.processes : live.processes);
  const hist = (key: string) =>
    frozen ? (frozen.history[key] ?? series(key, range)).slice(-range) : series(key, range);
  const markers: Marker[] = $derived.by(() => {
    const now = frozen ? frozen.at : (live.snapshot, Date.now());
    return recent.map((r) => ({ ago: Math.round((now - r.at) / 1000), label: r.label })).filter((m) => m.ago >= 0 && m.ago < range);
  });
  const recorded = $derived((frozen ? frozen.history.cpu : live.history.cpu)?.length ?? 0);
  const peak = (key: string) => Math.max(0, ...hist(key));
  const ghz = (mhz: number) => (mhz ? t("unit.ghz", { n: num(mhz / 1000, 2) }) : "—");
  const bits = (v: number) => rate(v, true);

  type Hue = "cpu" | "memory" | "disk" | "net" | "gpu";
  interface Resource { key: string; hue: Hue; title: string; line1: string; line2: string; values: number[]; percent: boolean; level: "" | "warn" | "bad" }

  // A disk key is "<number> <letters>" ("0 C:", "1 D: E:"): the number matches the hardware inventory.
  const diskNumber = (key: string) => Number(key.split(" ")[0]);
  const diskTitle = (key: string) => {
    const [n, ...letters] = key.split(" ");
    return letters.length ? t("res.diskLetters", { n, letters: letters.join(" ") }) : t("res.disk", { n });
  };
  const hwDisk = (key: string) => (hw?.disks ?? []).find((d: any) => d.number === diskNumber(key)) ?? null;
  const media = (disk: any) => (disk ? `${disk.media === "Unspecified" ? t("perf.disk") : disk.media}${disk.bus ? ` (${disk.bus})` : ""}` : "");
  const modules = $derived<any[]>(hw?.memory?.modules ?? []);

  const resources: Resource[] = $derived.by(() => {
    if (!snap) return [];
    const out: Resource[] = [];
    out.push({ key: "cpu", hue: "cpu", title: t("res.cpu"), line1: `${pct(snap.cpu)} ${snap.freqMhz ? ghz(snap.freqMhz) : ""}`, line2: "",
               values: hist("cpu"), percent: true, level: snap.cpu >= 95 ? "bad" : "" });
    const m = snap.memory;
    const used = m.total ? (m.used / m.total) * 100 : 0;
    out.push({ key: "memory", hue: "memory", title: t("res.memory"), line1: `${size(m.used)}/${size(m.total)} (${pct(used)})`, line2: "",
               values: hist("memory"), percent: true, level: used >= 95 ? "bad" : used >= 88 ? "warn" : "" });
    for (const disk of snap.disks)
      out.push({ key: `disk:${disk.key}`, hue: "disk", title: diskTitle(disk.key), line1: media(hwDisk(disk.key)), line2: pct(disk.active),
                 values: hist(`disk:${disk.key}`), percent: true, level: "" });
    // Virtual switches (Hyper-V, WSL, VPNs) multiply the adapters: show the two busiest of the range.
    const nets = [...snap.nets].sort((a, b) => peak(`net:${b.name}:recv`) + peak(`net:${b.name}:sent`)
                                              - peak(`net:${a.name}:recv`) - peak(`net:${a.name}:sent`)).slice(0, 2);
    for (const net of nets)
      out.push({ key: `net:${net.name}`, hue: "net", title: t("res.network"), line1: net.name,
                 line2: t("perf.sendReceive", { sent: bits(net.sentBps), received: bits(net.recvBps) }), values: hist(`net:${net.name}:recv`), percent: false, level: "" });
    snap.gpus.forEach((gpu, index) =>
      out.push({ key: `gpu:${gpu.luid}`, hue: "gpu", title: t("res.gpuN", { n: String(index) }), line1: gpu.name, line2: pct(gpu.utilization),
                 values: hist(`gpu:${gpu.luid}`), percent: true, level: "" }));
    return out;
  });

  $effect(() => {
    if (resources.length && !resources.some((r) => r.key === selected)) selected = "cpu";
  });
  const current = $derived(resources.find((r) => r.key === selected) ?? null);

  interface Detail {
    title: string; subtitle: string; caption: string; lines: Line[]; percent: boolean; format: (v: number) => string;
    caption2: string; lines2: Line[] | null; percent2: boolean; format2: (v: number) => string; cores: number[] | null;
    segments: Segment[] | null; total: number; extra: string; stats: [string, string][]; facts: [string, string][];
  }

  const detail: Detail | null = $derived.by(() => {
    if (!snap) return null;
    const base: Detail = { title: "", subtitle: "", caption: "", lines: [], percent: true, format: pct, caption2: "", lines2: null,
                           percent2: true, format2: pct, cores: null, segments: null, total: 0, extra: "", stats: [], facts: [] };
    const key = selected;
    if (key === "cpu") {
      const cpu = hw?.cpu;
      return { ...base, title: t("res.cpu"), subtitle: cpuName || cpu?.name || "", caption: t("perf.utilizationPct"),
               lines: [{ name: t("perf.utilization"), values: hist("cpu") }], cores: snap.perCore,
               stats: [[t("perf.utilization"), pct(snap.cpu)], [t("perf.speed"), ghz(snap.freqMhz)], [t("perf.processes"), num(snap.processes)],
                       [t("perf.threads"), num(snap.threads)], [t("perf.handles"), num(snap.handles)],
                       [t("perf.uptime"), uptime(snap.uptimeS)]],
               facts: [[t("perf.baseSpeed"), ghz(snap.baseMhz)], [t("perf.sockets"), String(cpu?.sockets ?? "—")], [t("perf.cores"), String(cpu?.cores ?? "—")],
                       [t("perf.logical"), String(snap.perCore.length)],
                       [t("perf.virtualization"), cpu ? (cpu.virtualization ? t("common.enabled") : t("common.disabled")) : "—"],
                       [t("perf.l2"), cpu?.l2Kb ? size(cpu.l2Kb * 1024, 0) : "—"], [t("perf.l3"), cpu?.l3Kb ? size(cpu.l3Kb * 1024, 0) : "—"]] };
    }
    if (key === "memory") {
      const m = snap.memory;
      const first = modules[0];
      const speed = first ? first.configuredSpeed || first.speed : 0;
      return { ...base, title: t("res.memory"), subtitle: `${size(m.total)}${first?.type ? ` ${first.type}` : ""}`, caption: t("perf.memoryUsage"),
               lines: [{ name: t("perf.inUse"), values: hist("memory") }], total: m.total,
               segments: [
                 { name: t("perf.inUse"), value: Math.max(0, m.used - m.modified), color: "var(--chart)", note: t("perf.inUseNote") },
                 { name: t("perf.modified"), value: m.modified, color: "color-mix(in srgb, var(--chart) 60%, var(--sunken))",
                   note: t("perf.modifiedNote") },
                 { name: t("perf.standby"), value: m.standby, color: "color-mix(in srgb, var(--chart) 25%, var(--sunken))",
                   note: t("perf.standbyNote") },
                 { name: t("perf.free"), value: m.free, color: "var(--sunken)", note: t("perf.freeNote") },
               ],
               extra: t("perf.memoryExtra"),
               stats: [[t("perf.inUseCompressed"), `${size(m.used)} (${size(m.compressed)})`], [t("perf.available"), size(m.available)],
                       [t("perf.committed"), `${size(m.commit)}/${size(m.commitLimit)}`], [t("perf.cached"), size(m.standby + m.modified)],
                       [t("perf.pagedPool"), size(m.pagedPool)], [t("perf.nonPagedPool"), size(m.nonpagedPool)]],
               facts: [[t("perf.speed"), speed ? t("unit.mts", { n: String(speed) }) : "—"],
                       [t("perf.slotsUsed"), modules.length ? t("perf.slotsValue", { used: modules.length, total: hw?.memory?.slots || modules.length }) : "—"],
                       [t("perf.formFactor"), first?.formFactor || "—"]] };
    }
    if (key.startsWith("gpu:")) {
      const gpu = snap.gpus.find((g) => `gpu:${g.luid}` === key);
      if (!gpu) return null;
      const info = (hw?.gpus ?? []).find((g: any) => g.name === gpu.name);
      const busy = [...gpu.engines].sort((a, b) => b[1] - a[1]).slice(0, 5);
      return { ...base, title: current?.title ?? t("res.gpu"), subtitle: gpu.name, caption: t("perf.gpuCaption"),
               lines: [{ name: t("perf.utilization"), values: hist(key) }],
               caption2: t("perf.dedicatedUsage"), lines2: [{ name: t("perf.dedicated"), values: hist(`vram:${gpu.luid}`) }],
               extra: busy.length ? t("perf.engines", { list: busy.map(([n, v]) => `${n} ${pct(v)}`).join(" · ") }) : "",
               stats: [[t("perf.utilization"), pct(gpu.utilization)], [t("perf.dedicatedMemory"), `${size(gpu.dedicatedUsed)}/${size(gpu.dedicatedTotal)}`],
                       [t("perf.sharedMemory"), `${size(gpu.sharedUsed)}/${size(gpu.sharedTotal)}`]],
               facts: [[t("perf.driverVersion"), info?.driverVersion || "—"], [t("perf.driverDate"), info?.driverDate || "—"]] };
    }
    if (key.startsWith("disk:")) {
      const disk = snap.disks.find((d) => `disk:${d.key}` === key);
      if (!disk) return null;
      const info = hwDisk(disk.key);
      return { ...base, title: diskTitle(disk.key), subtitle: info?.name ?? "", caption: t("perf.activeTime"),
               lines: [{ name: t("perf.activeTime"), values: hist(key) }],
               caption2: t("perf.transferRate"), lines2: [{ name: t("perf.read"), values: hist(`${key}:read`) }, { name: t("perf.write"), values: hist(`${key}:write`), dashed: true }],
               percent2: false, format2: (v: number) => rate(v),
               stats: [[t("perf.activeTime"), pct(disk.active)], [t("perf.readSpeed"), rate(disk.readBps)], [t("perf.writeSpeed"), rate(disk.writeBps)],
                       [t("perf.queue"), num(disk.queue, 1)]],
               facts: [[t("perf.capacity"), info?.size ? size(info.size, 0) : "—"], [t("perf.type"), media(info) || "—"], [t("perf.health"), info?.health || "—"],
                       [t("perf.temperature"), info?.temperature != null ? `${info.temperature} °C` : "—"]] };
    }
    if (key.startsWith("net:")) {
      const net = snap.nets.find((n) => `net:${n.name}` === key);
      if (!net) return null;
      return { ...base, title: t("res.network"), subtitle: net.name, caption: t("perf.throughput"), percent: false, format: bits,
               lines: [{ name: t("perf.receive"), values: hist(`${key}:recv`) }, { name: t("perf.send"), values: hist(`${key}:sent`), dashed: true }],
               extra: t("perf.netExtra"),
               stats: [[t("perf.send"), bits(net.sentBps)], [t("perf.receive"), bits(net.recvBps)]],
               facts: [[t("perf.adapter"), net.name], [t("perf.linkSpeed"), net.linkBps ? bits(net.linkBps / 8) : "—"]] };
    }
    return null;
  });

  interface Consumer { row: ProcessRow; value: number; text: string }

  const consumers: { title: string; column: string; items: Consumer[]; note: string } = $derived.by(() => {
    const rows = processes.filter((r) => r.pid > 4);
    const key = selected;
    if (key === "memory") {
      const items = [...rows].sort((a, b) => b.privateBytes - a.privateBytes).slice(0, 25)
        .map((row) => ({ row, value: row.privateBytes, text: size(row.privateBytes, 0) }));
      return { title: t("perf.mostMemory"), column: t("res.memory"), items, note: "" };
    }
    if (key.startsWith("gpu:")) {
      const use = new Map((snap?.gpuByPid ?? []).map((g) => [g.pid, g]));
      const items = rows.filter((r) => use.has(r.pid))
        .sort((a, b) => (use.get(b.pid)!.utilization - use.get(a.pid)!.utilization) || (use.get(b.pid)!.dedicated - use.get(a.pid)!.dedicated))
        .slice(0, 25).map((row) => { const g = use.get(row.pid)!; return { row, value: g.utilization, text: `${pct(g.utilization)} · ${size(g.dedicated, 0)}` }; });
      return { title: t("perf.mostGpu"), column: t("perf.colGpu"), items, note: "" };
    }
    if (key.startsWith("disk:")) {
      const items = rows.filter((r) => r.ioBps > 0).sort((a, b) => b.ioBps - a.ioBps).slice(0, 25)
        .map((row) => ({ row, value: row.ioBps, text: rate(row.ioBps) }));
      return { title: t("perf.mostIo"), column: t("perf.colIo"), items, note: t("perf.ioNote") };
    }
    if (key.startsWith("net:")) {
      return { title: t("res.network"), column: "", items: [], note: t("perf.netNote") };
    }
    const items = [...rows].sort((a, b) => b.cpu - a.cpu).slice(0, 25).map((row) => ({ row, value: row.cpu, text: pct(row.cpu, 1) }));
    return { title: t("perf.mostCpu"), column: t("res.cpu"), items, note: "" };
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>{t("page.performance")}</h1>
    <span class="grow"></span>
    <span class="faint">{paused ? t("perf.paused") : snap ? t("perf.everySecond", { uptime: uptime(snap.uptimeS) }) : live.error || t("perf.sampling")}</span>
    <div class="ranges" role="group" aria-label={t("perf.timeShown")}>
      {#each RANGES as seconds (seconds)}
        <button class:on={range === seconds} disabled={seconds > 60 && recorded < seconds / 2}
                title={seconds > 60 && recorded < seconds / 2 ? t("perf.notEnough") : ""}
                aria-pressed={range === seconds} onclick={() => (range = seconds)}>{t("perf.range", { count: seconds / 60 })}</button>
      {/each}
    </div>
    {#if paused}
      <button class="primary" onclick={() => (paused = false)}>{t("perf.backToLive")}</button>
    {:else}
      <button onclick={() => (paused = true)} title={t("perf.pauseTip")}><i class="icon">{"\uE769"}</i> {t("perf.pause")}</button>
    {/if}
  </div>

  <div class="body">
    <div class="resources" role="listbox" aria-label={t("perf.resources")}>
      {#each resources as r (r.key)}
        <button class="resource" class:selected={r.key === selected} role="option" aria-selected={r.key === selected}
                style:--chart={`var(--chart-${r.hue})`} onclick={() => (selected = r.key)}>
          <span class="thumb"><Sparkline values={r.values} percent={r.percent} span={range} height={40} /></span>
          <span class="text">
            <span class="name">{r.title}</span>
            {#if r.line1}<span class="line {r.level}">{r.line1}</span>{/if}
            {#if r.line2}<span class="line">{r.line2}</span>{/if}
          </span>
        </button>
      {/each}
    </div>

    <div class="detail" style:--chart={current ? `var(--chart-${current.hue})` : undefined}>
      {#if detail}
        <div class="detail-head">
          <h2 class="title">{detail.title}</h2>
          <span class="subtitle selectable">{detail.subtitle}</span>
        </div>
        <LineChart lines={detail.lines} percent={detail.percent} format={detail.format} caption={detail.caption}
                   height={detail.lines2 ? 230 : 300} span={range} bind:cursor {markers} onpin={() => (paused = true)} />
        {#if detail.lines2}
          <LineChart lines={detail.lines2} percent={detail.percent2} format={detail.format2} caption={detail.caption2}
                     height={150} span={range} bind:cursor {markers} onpin={() => (paused = true)} />
        {/if}
        {#if detail.cores}<CoreGrid values={detail.cores} />{/if}
        {#if detail.segments}
          <div class="composition">
            <span class="cap">{t("perf.composition")}</span>
            <StackedBar segments={detail.segments} total={detail.total} />
          </div>
        {/if}
        <div class="numbers">
          <div class="stats">
            {#each detail.stats as [name, value] (name)}
              <div class="stat"><div class="label">{name}</div><div class="value num selectable">{value}</div></div>
            {/each}
          </div>
          {#if detail.facts.length}
            <dl class="facts">
              {#each detail.facts as [name, value] (name)}<dt>{name}:</dt><dd class="selectable">{value}</dd>{/each}
            </dl>
          {/if}
        </div>
        {#if detail.extra}<p class="faint extra">{detail.extra}</p>{/if}

        <section class="panel consumers">
          <h3>{consumers.title}</h3>
          {#if consumers.items.length}
            <div class="list" role="listbox" aria-label={consumers.title}>
              <div class="list-head"><span>{t("network.process")}</span><span class="r">PID</span><span class="r">{consumers.column}</span></div>
              {#each consumers.items as item (`${item.row.pid}:${item.row.createdMs}`)}
                <button class="list-row" class:sel={chosen?.pid === item.row.pid && chosen?.createdMs === item.row.createdMs} title={item.row.exe || item.row.name}
                        onclick={() => (chosen = { pid: item.row.pid, createdMs: item.row.createdMs })} ondblclick={() => onshowprocess(item.row.pid)}>
                  <span class="pname">{item.row.name}</span><span class="r num">{item.row.pid}</span><span class="r num">{item.text}</span>
                </button>
              {/each}
            </div>
          {/if}
          {#if consumers.note}<p class="faint">{consumers.note}</p>{/if}
          <div class="actions">
            <button class="danger-outline" disabled={!chosen || report.busy} onclick={() => processAct("terminate")}>{t("proc.end")}</button>
            <button disabled={!chosen || report.busy} onclick={() => processAct("efficiency")}>{t("proc.efficiency")}</button>
            <div class="anchor">
              <button disabled={!chosen || report.busy} onclick={() => (priorityOpen = !priorityOpen)}>{t("proc.priority")}</button>
              {#if priorityOpen}
                <div class="pop">
                  {#each PRIORITIES as value (value)}<button onclick={() => processAct("priority", value)}>{t("proc.cpuPriority", { level: priorityLabel(value) })}</button>{/each}
                  <hr />
                  <button onclick={() => processAct("background")} title={t("proc.backgroundTip")}>{t("proc.background")}</button>
                </div>
              {/if}
            </div>
            {#if selected === "memory"}<button disabled={!chosen || report.busy} onclick={() => processAct("trim")}>{t("proc.trim")}</button>{/if}
            <button disabled={!chosen} onclick={() => chosen && onshowprocess(chosen.pid)}>{t("perf.showInProcesses")}</button>
          </div>
          {#if !elevated}<p class="faint">{t("perf.othersNeedAdmin")}</p>{/if}
        </section>
      {:else}
        <p class="muted">{live.error || t("perf.readingCounters")}</p>
      {/if}
    </div>
  </div>
</div>

<style>
  .pop hr { border: 0; border-top: 1px solid var(--rule); margin: 4px 0; }
  .ranges { display: inline-flex; border: 1px solid var(--control-stroke); border-radius: var(--radius); overflow: hidden; }
  .ranges button { border: 0; border-radius: 0; padding: 5px 12px 6px; background: var(--control); min-height: 30px; }
  .ranges button + button { border-left: 1px solid var(--control-stroke); }
  .ranges button.on { background: var(--select); color: var(--ink); font-weight: 600; box-shadow: inset 0 -2px 0 var(--accent); }
  .page-head .icon { font-size: 12px; margin-right: 4px; }
  .body { flex: 1; min-height: 0; display: grid; grid-template-columns: 236px minmax(0, 1fr); gap: 24px; }

  /* Resource list: Task Manager's left column. */
  .resources { display: flex; flex-direction: column; gap: 2px; overflow-y: auto; padding-right: 4px; }
  .resource {
    display: flex; align-items: center; gap: 12px; padding: 8px 10px; border: 0; border-radius: var(--radius); background: transparent;
    text-align: left; min-height: 64px; position: relative;
  }
  .resource:hover:not(.selected) { background: var(--hover); }
  .resource.selected { background: var(--hover); }
  .resource.selected::before {
    content: ""; position: absolute; left: 0; top: 50%; height: 16px; margin-top: -8px; width: 3px; border-radius: 2px; background: var(--accent);
  }
  .thumb {
    flex: none; width: 70px; height: 46px; padding: 2px; background: var(--sunken);
    border: 1px solid color-mix(in srgb, var(--chart) 70%, transparent); display: flex; align-items: flex-end;
  }
  .text { display: flex; flex-direction: column; min-width: 0; }
  .name { font-size: 15px; line-height: 20px; }
  .line { font-size: 12px; line-height: 16px; color: var(--ink2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .line.warn { color: var(--warn); }
  .line.bad { color: var(--bad); }

  /* Selected resource. */
  .detail { display: flex; flex-direction: column; gap: 14px; overflow-y: auto; min-width: 0; padding-right: 6px; }
  .detail-head { display: flex; align-items: baseline; gap: 16px; }
  .title { font: 600 28px/36px var(--font-display); flex: none; }
  .subtitle { flex: 1; text-align: right; font-size: 18px; line-height: 24px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .composition { display: flex; flex-direction: column; gap: 4px; }
  .cap { font-size: 12px; color: var(--ink2); }
  .numbers { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(220px, 1fr); gap: 16px 32px; align-items: start; }
  .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px 24px; }
  .stat .label { font-size: 12px; line-height: 16px; color: var(--ink2); }
  .stat .value { font-size: 20px; line-height: 28px; font-weight: 400; }
  .facts { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 2px 16px; margin: 0; font-size: 12px; line-height: 18px; }
  .facts dt { color: var(--ink2); }
  .facts dd { margin: 0; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .extra { margin: 0; }

  .consumers { display: flex; flex-direction: column; gap: 10px; flex: none; }
  .list { max-height: 320px; overflow-y: auto; border: 1px solid var(--rule); border-radius: var(--radius); }
  .list-head, .list-row { display: grid; grid-template-columns: minmax(0, 1fr) 70px 140px; gap: 8px; padding: 0 12px; align-items: center; }
  .list-head { position: sticky; top: 0; background: var(--surface); height: 32px; font-size: 12px; color: var(--ink2); border-bottom: 1px solid var(--rule); }
  .list-row { width: 100%; height: 30px; min-height: 30px; border: 0; border-radius: 0; background: transparent; text-align: left; font-size: 13px; position: relative; }
  .list-row:hover { background: var(--hover); }
  .list-row.sel { background: var(--select); }
  .list-row.sel::before { content: ""; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px; border-radius: 2px; background: var(--accent); }
  .pname { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .r { text-align: right; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .anchor { position: relative; }
  .pop { position: absolute; bottom: 38px; left: 0; z-index: 10; display: flex; flex-direction: column; min-width: 170px; padding: 4px;
         background: var(--flyout); border: 1px solid var(--rule); border-radius: 8px; box-shadow: var(--shadow-flyout); }
  .pop button { border: 0; background: transparent; text-align: left; padding: 0 12px; min-height: 32px; }
  .pop button:hover:not(:disabled) { background: var(--hover); }
</style>
