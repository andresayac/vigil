<script lang="ts">
  import { onMount } from "svelte";
  import Readouts, { type Readout } from "../components/Readouts.svelte";
  import * as api from "../lib/api";
  import { day, num, size } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { stateColor } from "../lib/labels";
  import { live } from "../lib/live.svelte";
  import type { GpuAdapter, Hardware, Insight } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  let hw = $state<Hardware | null>(null);
  let found = $state<Insight[]>([]);
  let loading = $state(false);
  let error = $state("");
  let copied = $state(false);
  let adapters = $state<GpuAdapter[]>([]);

  async function load(force = false): Promise<void> {
    loading = true;
    try {
      hw = await api.hardware(force);
      found = await api.insights();
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => {
    void load();
    void api.appInfo().then((info) => (adapters = info.adapters.filter((a) => !a.software)));
  });

  const date = (v: unknown) => day(v);
  const ghz = (mhz: unknown) => (typeof mhz === "number" && mhz ? t("unit.ghz", { n: num(mhz / 1000, 2) }) : "—");
  const ageDays = (iso: unknown) => {
    const t = Date.parse(String(iso ?? "").slice(0, 10));
    return Number.isNaN(t) ? null : (Date.now() - t) / 86_400_000;
  };
  const problems = $derived(found.filter((i) => i.level === "warn" || i.level === "bad"));

  interface Card { title: string; rows: Readout[]; note?: string }

  const cards: Card[] = $derived.by(() => {
    if (!hw) return [];
    const out: Card[] = [];
    const os = hw.os ?? {}, computer = hw.computer ?? {};
    const uptimeS = live.snapshot?.uptimeS ?? 0;
    out.push({ title: t("system.windows"), rows: [
      { name: t("system.edition"), value: os.caption ?? "—" },
      { name: t("system.version"), value: t("system.versionValue", { version: String(os.version ?? ""), build: String(os.build ?? "?") }) },
      { name: t("system.architecture"), value: os.arch ?? "—" }, { name: t("system.installed"), value: date(os.installed) },
      ...(uptimeS ? [{ status: (uptimeS / 86400 >= 14 ? "warn" : "") as Readout["status"], name: t("system.runningFor"),
                       value: uptimeS >= 86400 ? t("system.days", { n: num(uptimeS / 86400, 1) }) : t("time.hoursShort", { n: num(uptimeS / 3600, 1) }) }] : []),
      { name: t("system.computer"), value: [computer.manufacturer, computer.model].filter(Boolean).join(" ") || "—" },
    ] });
    const cpu = hw.cpu ?? {};
    out.push({ title: t("system.processor"), rows: [
      { name: t("system.model"), value: cpu.name ?? "—" }, { name: t("system.coresThreads"), value: `${cpu.cores ?? "?"} / ${cpu.logical ?? "?"}` },
      { name: t("perf.baseSpeed"), value: ghz(cpu.maxMhz) },
      { name: t("system.cache"), value: `L2 ${size((cpu.l2Kb ?? 0) * 1024, 0)} · L3 ${size((cpu.l3Kb ?? 0) * 1024, 0)}` },
      { name: t("system.socket"), value: cpu.socket ?? "—" },
      { status: cpu.virtualization ? "ok" : "", name: t("perf.virtualization"), value: cpu.virtualization ? t("system.virtOn") : t("system.virtOff") },
    ] });
    const memory = hw.memory ?? {};
    const modules: any[] = memory.modules ?? [];
    out.push({ title: t("res.memory"), rows: [
      { name: t("system.installedMemory"), value: size(modules.reduce((a, m) => a + (m.capacity ?? 0), 0), 0) },
      { name: t("perf.slotsUsed"), value: t("perf.slotsValue", { used: modules.length, total: String(memory.slots ?? "?") }) },
      { name: t("system.maxSupported"), value: size(memory.maxCapacity ?? 0, 0) },
      ...modules.map((m) => ({
        status: (m.speed && m.configuredSpeed && m.configuredSpeed < m.speed * 0.95 ? "warn" : "") as Readout["status"],
        name: m.bank || m.slot || t("system.module"),
        value: `${size(m.capacity ?? 0, 0)} ${m.type ?? ""} · ${t("unit.mts", { n: String(m.configuredSpeed || m.speed) })} · ${m.manufacturer ?? ""} ${m.partNumber ?? ""}`,
        tip: t("system.moduleTip", { rated: String(m.speed), running: String(m.configuredSpeed) }),
      })),
    ] });
    const gpuRows: Readout[] = [];
    for (const gpu of hw.gpus ?? []) {
      const adapter = adapters.find((a) => a.name === gpu.name);
      gpuRows.push({ name: gpu.name ?? t("system.adapter"),
                     value: adapter?.dedicatedTotal ? t("system.dedicated", { size: size(adapter.dedicatedTotal, 0) }) : t("system.basicAdapter") });
      const age = ageDays(gpu.driverDate);
      const stale = age !== null && age > 365 && ["10DE", "1002", "8086"].includes(String(gpu.vendorId ?? "").toUpperCase());
      gpuRows.push({ status: stale ? "warn" : "", name: `  ${t("system.driver")}`, value: `${gpu.driverVersion ?? "—"} (${date(gpu.driverDate)})` });
      if (gpu.width) gpuRows.push({ name: `  ${t("system.display")}`, value: t("system.displayValue", { w: String(gpu.width), h: String(gpu.height), hz: String(gpu.refreshRate ?? "?") }) });
    }
    out.push({ title: t("system.graphics"), rows: gpuRows.length ? gpuRows : [{ name: t("system.adapters"), value: t("system.noneReported") }] });
    const diskRows: Readout[] = [];
    for (const disk of hw.disks ?? []) {
      const health = String(disk.health ?? "");
      const letters = (disk.letters ?? []).map((l: string) => (l.endsWith(":") ? l : `${l}:`)).join(", ");
      diskRows.push({ status: health.toLowerCase() === "healthy" ? "ok" : health ? "bad" : "", name: t("res.disk", { n: String(disk.number) }),
                      value: `${disk.name ?? "?"} · ${disk.media ?? "?"} ${disk.bus ?? ""} · ${size(disk.size ?? 0, 0)}${letters ? ` · ${letters}` : ""}`,
                      tip: t("system.healthTip", { health: health || t("common.unknown") }) });
      const details = [disk.temperature ? `${disk.temperature} °C` : "",
                       disk.wear !== null && disk.wear !== undefined ? t("system.worn", { pct: `${disk.wear}%` }) : "",
                       disk.powerOnHours ? t("system.poweredOn", { hours: num(Number(disk.powerOnHours)) }) : ""].filter(Boolean);
      if (details.length) diskRows.push({ status: (disk.temperature ?? 0) >= 60 || (disk.wear ?? 0) >= 80 ? "warn" : "", name: `  ${t("perf.health")}`, value: details.join(" · ") });
    }
    const trim = hw.trim?.ntfs;
    if (trim !== null && trim !== undefined) diskRows.push({ status: trim ? "ok" : "bad", name: "TRIM", value: trim ? t("common.on") : t("common.off") });
    out.push({ title: t("page.storage"), rows: diskRows.length ? diskRows : [{ name: t("system.disks"), value: t("system.noneReported") }],
               note: elevated ? "" : t("system.healthNeedsAdmin") });
    const board = hw.board ?? {}, bios = hw.bios ?? {};
    out.push({ title: t("system.board"), rows: [
      { name: t("system.motherboard"), value: [board.manufacturer, board.product].filter(Boolean).join(" ") || "—" },
      { name: "BIOS", value: `${bios.manufacturer ?? ""} ${bios.version ?? ""}`.trim() || "—" }, { name: t("system.biosDate"), value: date(bios.date) },
      ...(hw.pagefiles ?? []).map((p: any) => ({ name: t("system.pageFile"), value: t("system.pageFileValue", { path: String(p.path), size: String(p.allocatedMb), peak: String(p.peakMb) }) })),
    ] });
    const battery = hw.battery;
    if (battery) {
      const health = battery.designedCapacity && battery.fullCapacity ? `${Math.round((battery.fullCapacity / battery.designedCapacity) * 100)}%` : "—";
      out.push({ title: t("system.battery"), rows: [{ name: t("system.charge"), value: `${battery.charge}%` }, { name: t("perf.health"), value: health },
                                                   { name: t("system.cycles"), value: String(battery.cycles ?? "—") }] });
    }
    return out;
  });

  async function copySummary(): Promise<void> {
    const lines = cards.flatMap((card) => [card.title, ...card.rows.map((r) => `  ${r.name.trim()}: ${r.value}`), ""]);
    lines.push(...found.map((i) => `[${i.level}] ${i.text} ${i.fix}`.trim()));
    await navigator.clipboard.writeText(lines.join("\n"));
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
</script>

<div class="page scroll">
  <div class="page-head">
    <h1>{t("page.system")}</h1>
    <span class="grow"></span>
    <span class="faint">{loading ? t("system.reading") : error}</span>
    <button onclick={copySummary} disabled={!hw}>{copied ? t("common.copied") : t("system.copy")}</button>
    <button onclick={() => load(true)} disabled={loading}>{t("system.readAgain")}</button>
  </div>

  {#if found.length}
    <section class="panel health">
      <h2>{problems.length ? t("system.problems", { count: problems.length }) : t("system.allFine")}</h2>
      {#each found as insight, index (index)}
        <div class="insight">
          <span class="mark" style:color={stateColor(insight.level)}>{({ ok: "✓", warn: "!", bad: "✕" } as Record<string, string>)[insight.level] ?? "i"}</span>
          <span class="faint">{insight.area}</span>
          <span class:muted={insight.level === "ok" || insight.level === "info"} class="selectable">{insight.text}{insight.fix ? `  ${insight.fix}` : ""}</span>
        </div>
      {/each}
    </section>
  {/if}

  <div class="cards">
    {#each cards as card (card.title)}
      <section class="panel card">
        <h2>{card.title}</h2>
        <Readouts rows={card.rows} />
        {#if card.note}<p class="faint">{card.note}</p>{/if}
      </section>
    {/each}
  </div>
</div>

<style>
  .scroll { overflow-y: auto; }
  .health { display: flex; flex-direction: column; gap: 8px; }
  .insight { display: grid; grid-template-columns: 16px 80px minmax(0, 1fr); gap: 8px; align-items: start; }
  .mark { font-weight: 700; text-align: center; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(460px, 1fr)); gap: 14px; align-items: start; }
  .card { display: flex; flex-direction: column; gap: 10px; }
  .card p { margin: 0; }
</style>
