<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { niceCeiling, when } from "../lib/format";
  import { locale, t, type Key } from "../lib/i18n/index.svelte";
  import { iconOf } from "../lib/icons.svelte";
  import { act } from "../lib/report.svelte";
  import type { Reliability, ReliabilityCategory, ReliabilityEvent } from "../lib/types";

  // What went wrong lately, read from the Windows event logs. Read-only: the only actions open Windows' own
  // viewers. Every name, path and message comes from the logs and is shown as plain text.
  let { elevated }: { elevated: boolean } = $props();

  const PERIODS = [7, 30, 90];
  const ORDER: ReliabilityCategory[] = ["bluescreen", "shutdown", "app_crash", "app_hang", "service", "hardware", "disk", "update", "install"];
  /** Bars stack the problems; installs are context and get their own row of marks. */
  const STACK: ReliabilityCategory[] = ["bluescreen", "shutdown", "hardware", "app_crash", "app_hang", "service", "disk", "update"];
  const TONE: Record<ReliabilityCategory, "bad" | "warn" | "info"> = {
    bluescreen: "bad", shutdown: "bad", hardware: "bad", app_crash: "warn", app_hang: "warn", service: "warn", disk: "warn",
    update: "warn", install: "info",
  };
  const CATEGORY: Record<ReliabilityCategory, Key> = {
    bluescreen: "rel.cat.bluescreen", shutdown: "rel.cat.shutdown", app_crash: "rel.cat.appCrash", app_hang: "rel.cat.appHang",
    service: "rel.cat.service", hardware: "rel.cat.hardware", disk: "rel.cat.disk", update: "rel.cat.update", install: "rel.cat.install",
  };
  const KIND: Record<string, Key> = {
    bugcheck: "rel.kind.bugcheck", kernel_power: "rel.kind.kernelPower", power_loss: "rel.kind.powerLoss",
    power_button: "rel.kind.powerButton", unexpected: "rel.kind.unexpected", crash: "rel.kind.crash", hang: "rel.kind.hang",
    crashed: "rel.kind.crashed", start_failed: "rel.kind.startFailed", start_timeout: "rel.kind.startTimeout",
    stopped_with_error: "rel.kind.stoppedWithError", fatal: "rel.kind.fatal", corrected: "rel.kind.corrected",
    bad_block: "rel.kind.badBlock", controller_error: "rel.kind.controllerError", paging_error: "rel.kind.pagingError",
    retried: "rel.kind.retried", corruption: "rel.kind.corruption", needs_repair: "rel.kind.needsRepair",
    installed: "rel.kind.installed", install_failed: "rel.kind.installFailed", removed: "rel.kind.removed",
    remove_failed: "rel.kind.removeFailed",
  };
  const SUBJECT: Record<ReliabilityCategory, Key> = {
    bluescreen: "rel.field.stopCode", shutdown: "rel.field.subject", app_crash: "rel.field.program", app_hang: "rel.field.program",
    service: "rel.field.service", hardware: "rel.field.component", disk: "rel.field.device", update: "rel.field.update",
    install: "rel.field.product",
  };
  const SEVERITY_ICON: Record<string, { icon: string; tone: string }> = {
    critical: { icon: "", tone: "bad" }, error: { icon: "", tone: "bad" },
    warning: { icon: "", tone: "warn" }, info: { icon: "", tone: "" },
  };
  const BOOT_LOG = "Microsoft-Windows-Diagnostics-Performance/Operational";
  const ROWS = 8;

  let data = $state<Reliability | null>(null);
  let days = $state(30);
  let loading = $state(false);
  let error = $state("");
  let category = $state<ReliabilityCategory | "all">("all");
  let day = $state<string | null>(null);
  let only = $state<{ ids: string[]; title: string } | null>(null);
  let selected = $state<string | null>(null);
  let expanded = $state<Record<string, boolean>>({});
  let full = $state<Record<string, boolean>>({});
  let hover = $state<number | null>(null);
  let copied = $state(false);

  async function load(): Promise<void> {
    loading = true;
    try {
      data = await api.reliability(days);
      error = "";
      if (selected && !data.events.some((e) => e.id === selected)) selected = null;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => void load());

  function setDays(value: number): void {
    if (value === days) return;
    days = value;
    day = null;
    only = null;
    void load();
  }

  // ------------------------------------------------------------------ words
  const number = (n: number, digits = 0) => new Intl.NumberFormat(locale(), { maximumFractionDigits: digits }).format(n);
  const seconds = (ms: number) => t("rel.seconds", { n: number(ms / 1000, 1) });
  const dayKey = (d: Date) =>
    `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const dayLabel = (key: string, style: "short" | "long") =>
    new Intl.DateTimeFormat(locale(), style === "short" ? { day: "numeric", month: "short" } : { dateStyle: "full" })
      .format(new Date(`${key}T12:00:00`));
  /** "disk 2" for \Device\Harddisk2\DR3. */
  function device(name: string): string {
    const m = /harddisk(\d+)/i.exec(name);
    return m ? t("rel.disk", { n: m[1] }) : name;
  }
  function kindText(e: ReliabilityEvent): string {
    if (e.category === "update") return t("rel.kind.updateFailed");
    return KIND[e.kind] ? t(KIND[e.kind]) : e.kind;
  }
  function subjectText(e: ReliabilityEvent): string {
    if (e.category === "disk") return device(e.subject);
    return e.subject;
  }
  function headline(e: ReliabilityEvent): string {
    const subject = subjectText(e);
    if (e.category === "bluescreen" || e.category === "shutdown" || e.category === "hardware") return subject ? `${kindText(e)}: ${subject}` : kindText(e);
    return subject ? `${subject}: ${kindText(e)}` : kindText(e);
  }

  // ------------------------------------------------------------------ filters
  const events = $derived(data?.events ?? []);
  /** Events that pass the day and hint filters (the category chips count these). */
  const scoped = $derived(events.filter((e) => (!day || e.time.startsWith(day)) && (!only || only.ids.includes(e.id))));
  const visible = $derived(scoped.filter((e) => category === "all" || e.category === category));
  const counts = $derived(Object.fromEntries(ORDER.map((c) => [c, scoped.filter((e) => e.category === c).length])) as Record<ReliabilityCategory, number>);
  const problemCount = $derived(events.filter((e) => e.category !== "install").length);
  const current = $derived(events.find((e) => e.id === selected) ?? null);

  // ------------------------------------------------------------------ timeline
  const dayKeys = $derived.by(() => {
    const now = new Date();
    const span = data?.days ?? days;
    return Array.from({ length: span }, (_, i) => dayKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - (span - 1 - i))));
  });
  const columns = $derived.by(() => {
    const byDay = new Map<string, Partial<Record<ReliabilityCategory, number>>>();
    for (const e of events) {
      const key = e.time.slice(0, 10);
      const c = byDay.get(key) ?? {};
      c[e.category] = (c[e.category] ?? 0) + 1;
      byDay.set(key, c);
    }
    return dayKeys.map((key) => {
      const c = byDay.get(key) ?? {};
      return { key, counts: c, problems: STACK.reduce((sum, cat) => sum + (c[cat] ?? 0), 0), installs: c.install ?? 0 };
    });
  });
  // Counts: an even top keeps the middle line on a whole number (5 would put it at 2.5).
  const evenCeiling = (value: number) => {
    const ceiling = niceCeiling(value);
    return ceiling % 2 ? Math.max(2, ceiling + 1) : ceiling;
  };
  const top = $derived(evenCeiling(Math.max(1, ...columns.map((c) => c.problems))));
  const labelEvery = $derived(Math.max(1, Math.ceil(columns.length / 6)));
  const hovered = $derived(hover === null ? null : columns[hover] ?? null);

  // ------------------------------------------------------------------ sections
  interface Group { key: string; name: string; path: string; count: number; lastMs: number; last: string; module: string; moduleCount: number; events: ReliabilityEvent[] }
  function groups(list: ReliabilityEvent[]): Group[] {
    const map = new Map<string, Group>();
    for (const e of list) {
      const key = e.subject.toLowerCase();
      let g = map.get(key);
      if (!g) {
        g = { key, name: e.subject, path: e.path, count: 0, lastMs: e.timeMs, last: e.time, module: "", moduleCount: 0, events: [] };
        map.set(key, g);
      }
      g.count += 1;
      g.events.push(e);
    }
    for (const g of map.values()) {
      const modules = new Map<string, number>();
      for (const e of g.events) if (e.module) modules.set(e.module, (modules.get(e.module) ?? 0) + 1);
      const best = [...modules.entries()].sort((a, b) => b[1] - a[1])[0];
      if (best) [g.module, g.moduleCount] = best;
    }
    return [...map.values()].sort((a, b) => b.count - a.count || b.lastMs - a.lastMs);
  }
  const sections = $derived(ORDER.map((cat) => ({ cat, list: visible.filter((e) => e.category === cat) })).filter((s) => s.list.length));

  // ------------------------------------------------------------------ details
  function fields(e: ReliabilityEvent): { label: string; value: string; mono?: boolean; tone?: string }[] {
    const out: { label: string; value: string; mono?: boolean; tone?: string }[] = [
      { label: t("rel.field.when"), value: when(e.time, true) },
    ];
    if (e.subject) out.push({ label: t(SUBJECT[e.category]), value: subjectText(e) });
    if (e.version) out.push({ label: t("rel.field.version"), value: e.version });
    if (e.module) out.push({ label: t("rel.field.module"), value: e.moduleVersion ? `${e.module} (${e.moduleVersion})` : e.module });
    if (e.code) {
      const label = e.category === "bluescreen" ? "rel.field.stopCode" : e.category === "app_crash" ? "rel.field.exception" : "rel.field.errorCode";
      out.push({ label: t(label), value: e.codeName && e.category !== "bluescreen" ? `${e.code} (${e.codeName})` : e.code, mono: true });
    }
    if (e.parameters) {
      const label = e.category === "app_crash" ? "rel.field.offset" : e.category === "app_hang" ? "rel.field.hangType"
        : e.category === "service" ? "rel.field.timeout" : "rel.field.parameters";
      out.push({ label: t(label), value: e.parameters, mono: e.category !== "app_hang" });
    }
    if (e.path) {
      const dump = e.category === "bluescreen";
      out.push({ label: t(dump ? "rel.field.dump" : "rel.field.programFile"), value: e.path, mono: true });
      if (dump && e.pathExists !== null) out.push({ label: "", value: t(e.pathExists ? "rel.dumpKept" : "rel.dumpGone"), tone: "faint" });
    }
    if (e.publisher) out.push({ label: t("rel.field.publisher"), value: e.publisher });
    if (e.count) out.push({ label: t("rel.field.serviceCount"), value: number(e.count) });
    out.push({ label: t("rel.field.source"), value: t("rel.sourceValue", { provider: e.provider, id: e.eventId }) });
    out.push({ label: t("rel.field.log"), value: t("rel.logValue", { log: e.log, record: e.recordId }) });
    return out;
  }

  async function copy(e: ReliabilityEvent): Promise<void> {
    const lines = [headline(e), ...fields(e).map((f) => (f.label ? `${f.label}: ${f.value}` : `  ${f.value}`))];
    if (e.message) lines.push("", e.message);
    await navigator.clipboard.writeText(lines.join("\n"));
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  function showHint(ids: string[], title: string): void {
    only = { ids, title };
    category = "all";
    day = null;
    selected = ids[0] ?? null;
  }

  const boots = $derived(data?.boots ?? []);
  const bootsUnread = $derived(!!data?.unreadLogs.includes(BOOT_LOG));
  const otherUnread = $derived((data?.unreadLogs ?? []).filter((log) => log !== BOOT_LOG));
</script>

<div class="page scroll">
  <div class="page-head">
    <h1>{t("page.reliability")}</h1>
    <div class="segmented" role="radiogroup" aria-label={t("rel.period")}>
      {#each PERIODS as p (p)}
        <button role="radio" aria-checked={days === p} class:on={days === p} onclick={() => setDays(p)}>{t("common.days", { count: p })}</button>
      {/each}
    </div>
    <span class="grow"></span>
    <span class="faint">{loading ? t("common.reading") : ""}</span>
    <div class="commandbar">
      <button class="command" onclick={() => act({ kind: "shell", op: "tool", name: "reliability" })}><i class="icon">{""}</i>{t("rel.monitor")}</button>
      <button class="command" onclick={() => act({ kind: "shell", op: "console", name: "eventvwr.msc" })}><i class="icon">{""}</i>{t("menu.eventViewer")}</button>
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{""}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{t("rel.note")}</p>

  {#if error}
    <p class="warn-text selectable">{error}</p>
  {/if}

  {#if data}
    <section class="panel chart-panel">
      <div class="chart-head">
        <h2>{t("rel.chartTitle")}</h2>
        <span class="faint">{t("rel.problems", { count: problemCount })}</span>
        <span class="grow"></span>
        <span class="legend faint">
          <span><i class="swatch bad"></i>{t("rel.legendSerious")}</span>
          <span><i class="swatch warn"></i>{t("rel.legendProblems")}</span>
          <span><i class="dot"></i>{t("rel.cat.install")}</span>
        </span>
      </div>
      <div class="chart" role="group" aria-label={t("rel.chartTitle")}>
        <div class="axis-y faint num"><span>{number(top)}</span><span>{number(top / 2)}</span><span>0</span></div>
        <div class="plot" onmouseleave={() => (hover = null)} role="presentation">
          <div class="grid-line" style:top="0"></div>
          <div class="grid-line" style:top="50%"></div>
          <div class="bars">
            {#each columns as col, i (col.key)}
              <button class="col" class:picked={day === col.key} class:dim={day !== null && day !== col.key}
                      aria-label={`${dayLabel(col.key, "long")}: ${t("rel.problems", { count: col.problems })}`}
                      onmouseenter={() => (hover = i)} onfocus={() => (hover = i)}
                      onclick={() => { day = day === col.key ? null : col.key; only = null; }}>
                <span class="stack">
                  {#each STACK as cat (cat)}
                    {#if col.counts[cat]}
                      <i class="seg {TONE[cat]}" style:height="{((col.counts[cat] ?? 0) / top) * 100}%"></i>
                    {/if}
                  {/each}
                </span>
              </button>
            {/each}
          </div>
          {#if hovered && hover !== null}
            <div class="tip" style:left="{((hover + 0.5) / columns.length) * 100}%" class:right={hover > columns.length / 2}>
              <b>{dayLabel(hovered.key, "long")}</b>
              {#each STACK as cat (cat)}
                {#if hovered.counts[cat]}
                  <span class="tip-row"><i class="swatch {TONE[cat]}"></i>{t(CATEGORY[cat])}<b class="num">{hovered.counts[cat]}</b></span>
                {/if}
              {/each}
              {#if !hovered.problems}<span class="faint">{t("rel.noProblemsDay")}</span>{/if}
              {#if hovered.installs}<span class="faint">{t("rel.installsDay", { count: hovered.installs })}</span>{/if}
            </div>
          {/if}
        </div>
        <div></div>
        <div class="marks" aria-hidden="true">
          {#each columns as col (col.key)}<span class="mark">{#if col.installs}<i class="dot"></i>{/if}</span>{/each}
        </div>
        <div></div>
        <div class="axis-x faint">
          {#each columns as col, i (col.key)}
            <span>{i === columns.length - 1 ? t("rel.today") : (columns.length - 1 - i) % labelEvery === 0 && i < columns.length - labelEvery / 2 ? dayLabel(col.key, "short") : ""}</span>
          {/each}
        </div>
      </div>
    </section>

    {#if data.hints.length}
      <section class="panel hints">
        <h2>{t("rel.hintsTitle")}</h2>
        {#each data.hints as hint, index (index)}
          <div class="hint">
            <i class="icon sev {hint.severity === 'warn' ? 'warn' : ''}">{hint.severity === "warn" ? "" : ""}</i>
            <div class="hint-body">
              <b class="selectable">{hint.title}</b>
              <span class="selectable">{hint.text}</span>
            </div>
            {#if hint.events.length}
              <button class="link" onclick={() => showHint(hint.events, hint.title)}>{t("rel.showEvents")}</button>
            {/if}
          </div>
        {/each}
      </section>
    {:else if !problemCount}
      <section class="panel calm">
        <i class="icon ok">{""}</i>
        <span>{t("rel.allClear", { days: data.days })}</span>
      </section>
    {/if}

    <div class="bar">
      <div class="chips" role="tablist" aria-label={t("rel.filter")}>
        <button role="tab" class="chip" class:active={category === "all"} aria-selected={category === "all"} onclick={() => (category = "all")}>
          {t("rel.all")} <span class="num">{scoped.length}</span>
        </button>
        {#each ORDER as cat (cat)}
          <button role="tab" class="chip" class:active={category === cat} aria-selected={category === cat} disabled={!counts[cat]}
                  onclick={() => (category = cat)}>
            {t(CATEGORY[cat])} <span class="num">{counts[cat]}</span>
          </button>
        {/each}
      </div>
      {#if day || only}
        <div class="active-filter">
          <span class="faint">{day ? t("rel.showingDay", { date: dayLabel(day, "long") }) : t("rel.showingHint", { title: only?.title ?? "" })}</span>
          <button class="link" onclick={() => { day = null; only = null; }}>{t("rel.clearFilter")}</button>
        </div>
      {/if}
    </div>

    <div class="columns">
      <div class="sections">
        {#each sections as section (section.cat)}
          {@const grouped = section.cat === "app_crash" || section.cat === "app_hang"}
          <section class="panel section">
            <div class="section-head">
              <h2>{t(CATEGORY[section.cat])}</h2>
              <span class="faint num">{section.list.length}</span>
            </div>
            {#if grouped}
              {@const list = groups(section.list)}
              {#each full[section.cat] ? list : list.slice(0, ROWS) as g (g.key)}
                {@const open = !!expanded[`${section.cat}:${g.key}`]}
                {@const icon = g.path && /\.exe$/i.test(g.path) ? iconOf(g.path) : ""}
                <button class="row group" aria-expanded={open} onclick={() => (expanded[`${section.cat}:${g.key}`] = !open)}>
                  <i class="icon chevron">{open ? "" : ""}</i>
                  {#if icon}<img class="app-icon" src={icon} alt="" />{:else}<i class="icon app-icon generic">{""}</i>{/if}
                  <span class="name" title={g.path}>{g.name}</span>
                  <span class="count">{t(section.cat === "app_crash" ? "rel.crashes" : "rel.hangs", { count: g.count })}</span>
                  <span class="faint when">{t("rel.last", { when: when(g.last) })}</span>
                  {#if g.module}<span class="faint module" title={g.module}>{t("rel.inModule", { module: g.module, count: g.moduleCount })}</span>{/if}
                </button>
                {#if open}
                  {#each g.events as e (e.id)}
                    {@const look = SEVERITY_ICON[e.severity]}
                    <button class="row sub" class:sel={selected === e.id} onclick={() => (selected = e.id)}>
                      <i class="icon sev {look.tone}">{look.icon}</i>
                      <span class="time">{when(e.time)}</span>
                      <span class="what">{e.module || kindText(e)}{e.version ? ` · ${e.version}` : ""}</span>
                      <span class="faint mono detail">{e.codeName || e.code || e.parameters}</span>
                    </button>
                  {/each}
                {/if}
              {/each}
              {#if list.length > ROWS}
                <button class="link more" onclick={() => (full[section.cat] = !full[section.cat])}>
                  {full[section.cat] ? t("rel.showFewer") : t("rel.showAll", { count: list.length })}</button>
              {/if}
            {:else}
              {#each full[section.cat] ? section.list : section.list.slice(0, ROWS) as e (e.id)}
                {@const look = SEVERITY_ICON[e.severity]}
                <button class="row" class:sel={selected === e.id} onclick={() => (selected = e.id)}>
                  <i class="icon sev {look.tone}">{look.icon}</i>
                  <span class="time">{when(e.time)}</span>
                  <span class="what" title={headline(e)}>{headline(e)}</span>
                  <span class="faint mono detail">
                    {#if e.category === "bluescreen"}{e.code}{:else if e.code}{e.codeName || `${t("rel.field.errorCode")} ${e.code}`}{:else if e.version}{e.version}{/if}
                  </span>
                </button>
              {/each}
              {#if section.list.length > ROWS}
                <button class="link more" onclick={() => (full[section.cat] = !full[section.cat])}>
                  {full[section.cat] ? t("rel.showFewer") : t("rel.showAll", { count: section.list.length })}</button>
              {/if}
            {/if}
          </section>
        {:else}
          <p class="faint empty">{loading ? t("common.reading") : t("rel.noneHere")}</p>
        {/each}
      </div>

      <aside class="side">
        {#if current}
          {@const look = SEVERITY_ICON[current.severity]}
          <section class="panel detail-panel" aria-live="polite">
            <div class="detail-head">
              <i class="icon sev {look.tone}">{look.icon}</i>
              <h3 class="selectable">{headline(current)}</h3>
            </div>
            <span class="faint">{t(CATEGORY[current.category])}</span>
            <div class="grid">
              {#each fields(current) as f, i (i)}
                <span class="faint">{f.label}</span>
                <span class="selectable" class:mono={f.mono} class:faint={f.tone === "faint"}>{f.value}</span>
              {/each}
            </div>
            {#if current.message}
              <div class="message selectable">{current.message}</div>
            {/if}
            <div class="detail-actions">
              <button onclick={() => current && copy(current)}><i class="icon">{""}</i>{copied ? t("common.copied") : t("rel.copy")}</button>
              <button onclick={() => act({ kind: "shell", op: "console", name: "eventvwr.msc" })}><i class="icon">{""}</i>{t("menu.eventViewer")}</button>
            </div>
          </section>
        {:else}
          <section class="panel detail-panel empty-detail"><p class="faint">{t("rel.select")}</p></section>
        {/if}

        <section class="panel boot">
          <h2>{t("rel.bootTitle")}</h2>
          {#if boots.length}
            {@const average = boots.reduce((a, b) => a + b.bootMs, 0) / boots.length}
            {@const slowest = boots.reduce((a, b) => (b.bootMs > a.bootMs ? b : a), boots[0])}
            <div class="grid">
              <span class="faint">{t("rel.bootLast")}</span><span class="num">{seconds(boots[0].bootMs)}</span>
              <span class="faint">{t("rel.bootAverage", { count: boots.length })}</span><span class="num">{seconds(average)}</span>
              <span class="faint">{t("rel.bootSlowest")}</span><span><span class="num">{seconds(slowest.bootMs)}</span> <span class="faint">{when(slowest.time)}</span></span>
            </div>
            <p class="faint">{t("rel.bootNote")}</p>
          {:else}
            <p class="faint">{bootsUnread && !elevated ? t("rel.bootNeedsAdmin") : t("rel.bootNone")}</p>
          {/if}
        </section>
      </aside>
    </div>

    <div class="faint footer">
      {t("rel.footer", { count: events.length, when: when(new Date(data.readMs).toISOString()) })}
      {#if data.truncated} · {t("rel.truncated")}{/if}
      {#if otherUnread.length} · {t("rel.unread", { logs: otherUnread.join(", ") })}{/if}
    </div>
  {:else if !error}
    <p class="faint empty">{t("common.reading")}</p>
  {/if}
</div>

<style>
  .scroll { overflow-y: auto; }
  .lead { margin: -6px 0 0; }
  .warn-text { color: var(--warn); margin: 0; }
  .segmented {
    display: inline-flex; gap: 2px; padding: 2px; border-radius: var(--radius); background: var(--control);
    border: 1px solid var(--control-stroke);
  }
  .segmented button {
    min-height: 26px; padding: 2px 10px 3px; border: 1px solid transparent; background: transparent; color: var(--ink2);
    border-radius: 3px; font-size: 13px;
  }
  .segmented button:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  .segmented button.on {
    background: var(--surface); color: var(--ink); border-color: var(--control-stroke); font-weight: 600;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
  }
  .grow { flex: 1; }

  /* The timeline: one column per day, problems stacked, installs as marks below. */
  .chart-panel { display: flex; flex-direction: column; gap: 10px; flex: none; }
  .chart-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .legend { display: inline-flex; gap: 14px; flex-wrap: wrap; }
  .legend > span { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: var(--ink3); }
  .swatch.bad, .seg.bad { background: var(--bad); }
  .swatch.warn, .seg.warn { background: var(--warn); }
  .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--ink3); }
  .chart { display: grid; grid-template-columns: 32px minmax(0, 1fr); grid-template-rows: 140px 12px auto; column-gap: 6px; }
  .axis-y { display: flex; flex-direction: column; justify-content: space-between; align-items: flex-end; font-size: 11px; line-height: 1; }
  .plot { position: relative; border-bottom: 1px solid var(--rule-strong); }
  .grid-line { position: absolute; left: 0; right: 0; border-top: 1px dashed var(--rule); pointer-events: none; }
  .bars { position: absolute; inset: 0; display: flex; align-items: stretch; }
  .col {
    flex: 1 1 0; min-width: 0; min-height: 0; height: 100%; padding: 0 1px; border: 0; border-radius: 0; background: transparent;
    display: flex; align-items: flex-end; cursor: pointer;
  }
  .col:hover:not(:disabled), .col:focus-visible { background: var(--hover); }
  .col.picked { background: var(--table-select); }
  .col.dim .stack { opacity: 0.35; }
  .stack { display: flex; flex-direction: column-reverse; width: 100%; max-width: 18px; margin: 0 auto; height: 100%; gap: 1px; }
  .seg { display: block; width: 100%; min-height: 2px; border-radius: 1px; flex: none; }
  .marks { display: flex; align-items: center; }
  .mark { flex: 1 1 0; min-width: 0; display: flex; justify-content: center; }
  .axis-x { display: flex; font-size: 11px; line-height: 14px; }
  .axis-x span { flex: 1 1 0; min-width: 0; white-space: nowrap; overflow: visible; text-align: center; }
  .axis-x span:last-child { text-align: right; }
  .tip {
    position: absolute; top: 4px; z-index: 3; transform: translateX(8px); display: flex; flex-direction: column; gap: 4px;
    min-width: 180px; padding: 8px 10px; font-size: 12px; pointer-events: none;
    background: var(--flyout); border: 1px solid var(--rule-strong); border-radius: 8px; box-shadow: var(--shadow-flyout);
  }
  .tip.right { transform: translateX(calc(-100% - 8px)); }
  .tip-row { display: flex; align-items: center; gap: 6px; }
  .tip-row b { margin-left: auto; padding-left: 12px; }

  .hints { display: flex; flex-direction: column; gap: 10px; flex: none; }
  .hint { display: grid; grid-template-columns: 18px minmax(0, 1fr) auto; gap: 10px; align-items: start; }
  .hint-body { display: flex; flex-direction: column; gap: 2px; font-size: 13px; }
  .sev { font-size: 14px; line-height: 20px; color: var(--ink3); }
  .sev.warn { color: var(--warn); }
  .sev.bad { color: var(--bad); }
  .calm { display: flex; align-items: center; gap: 10px; flex: none; }
  .calm .ok { color: var(--ok); }
  .link {
    min-height: 0; padding: 2px 4px; border: 0; background: transparent; color: var(--accent); font-size: 13px; white-space: nowrap;
  }
  .link:hover:not(:disabled) { background: transparent; text-decoration: underline; }

  .bar { display: flex; align-items: center; justify-content: space-between; gap: 8px 16px; flex-wrap: wrap; }
  .chips { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .chip { border-radius: 14px; min-height: 28px; padding: 2px 12px; font-size: 13px; }
  .chip.active { background: var(--select); border-color: var(--accent); }
  .chip .num { color: var(--ink2); margin-left: 4px; }
  .active-filter { display: flex; align-items: center; gap: 8px; }

  .columns { display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 14px; align-items: start; }
  @media (max-width: 1100px) { .columns { grid-template-columns: minmax(0, 1fr); } }
  .sections { display: flex; flex-direction: column; gap: 12px; min-width: 0; }
  .section { display: flex; flex-direction: column; padding: 12px 8px 8px; }
  .section-head { display: flex; align-items: baseline; gap: 8px; padding: 0 8px 6px; }
  .row {
    position: relative; display: grid; grid-template-columns: 18px 150px minmax(0, 1fr) auto; align-items: center; gap: 10px;
    width: 100%; min-height: 32px; padding: 4px 8px; border: 0; border-radius: 4px; background: transparent; color: var(--ink);
    text-align: left; font-size: 13px;
  }
  .row:hover:not(:disabled) { background: var(--hover); }
  .row.sel { background: var(--table-select); }
  .row.group { grid-template-columns: 14px 16px minmax(120px, 1fr) auto auto minmax(0, 1.2fr); }
  .row.sub { padding-left: 38px; grid-template-columns: 18px 150px minmax(0, 1fr) auto; }
  .chevron { font-size: 10px; color: var(--ink2); }
  .app-icon { width: 16px; height: 16px; flex: none; }
  .app-icon.generic { font-size: 16px; color: var(--ink2); }
  .name, .what, .module { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
  .name { font-weight: 600; }
  .count, .when { white-space: nowrap; }
  .time { color: var(--ink2); white-space: nowrap; }
  .detail { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 260px; }
  .more { align-self: flex-start; margin: 4px 8px 0; }
  .empty { padding: 30px; text-align: center; margin: 0; }

  .side { display: flex; flex-direction: column; gap: 12px; position: sticky; top: 0; min-width: 0; }
  .detail-panel { display: flex; flex-direction: column; gap: 8px; }
  .detail-head { display: flex; align-items: flex-start; gap: 8px; }
  .detail-head h3 { overflow-wrap: anywhere; }
  .grid { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .mono { overflow-wrap: anywhere; }
  .message {
    max-height: 220px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; line-height: 18px;
    padding: 8px 10px; border-radius: 4px; background: var(--sunken); border: 1px solid var(--rule);
  }
  .detail-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .empty-detail p { margin: 0; }
  .boot { display: flex; flex-direction: column; gap: 8px; }
  .boot p { margin: 0; }
  .footer { padding: 0 4px 4px; }
</style>
