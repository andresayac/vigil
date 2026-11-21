<script lang="ts">
  import FindingDetail from "../components/FindingDetail.svelte";
  import { t } from "../lib/i18n/index.svelte";
  import { KINDS, VERDICT_ORDER, kindLabel, verdictColor, verdictLabel } from "../lib/labels";
  import { isIgnored, report } from "../lib/report.svelte";
  import type { Item } from "../lib/types";

  let { focus = null, elevated }: { focus?: { ids?: string[]; caption?: string; id?: string; verdict?: string } | null; elevated: boolean } = $props();

  const RANK: Record<string, number> = Object.fromEntries(VERDICT_ORDER.map((v, i) => [v, i]));
  let verdicts = $state<Record<string, boolean>>(Object.fromEntries(VERDICT_ORDER.map((v) => [v, v !== "trusted"])));
  let text = $state("");
  let kind = $state("");
  let showIgnored = $state(false);
  let ids = $state<string[] | null>(null);
  let caption = $state("");
  let selected = $state<string | null>(null);
  let sortKey = $state<"verdict" | "score" | "name" | "type" | "presence">("verdict");
  let descending = $state(false);

  $effect(() => {
    if (!focus) return;
    if (focus.ids) { ids = focus.ids; caption = focus.caption ?? ""; selected = focus.ids[0] ?? null; }
    if (focus.id) { ids = null; selected = focus.id; text = ""; const it = report.analysis?.items.find((i) => i.id === focus?.id); if (it) verdicts[it.verdict] = true; }
    if (focus.verdict) { ids = null; for (const v of VERDICT_ORDER) verdicts[v] = v === focus.verdict; }
  });

  const presence = (item: Item) => {
    const running = item.roles.some((r) => r.kind === "process");
    const autostart = item.roles.some((r) => r.persistent && r.active);
    return running && autostart ? t("findings.runningAutostart") : running ? t("findings.running") : autostart ? t("findings.autostart") : "";
  };

  const items = $derived(report.analysis?.items ?? []);
  const counts = $derived(Object.fromEntries(VERDICT_ORDER.map((v) => [v, items.filter((i) => i.verdict === v && (showIgnored || !isIgnored(i.id))).length])));

  const rows: Item[] = $derived.by(() => {
    const words = text.toLowerCase().split(/\s+/).filter(Boolean);
    const list = items.filter((item) => {
      if (ids) return ids.includes(item.id);
      if (!verdicts[item.verdict]) return false;
      if (kind && item.kind !== kind) return false;
      if (!showIgnored && isIgnored(item.id)) return false;
      if (!words.length) return true;
      const haystack = [item.title, item.subtitle, item.path ?? "", item.what, item.reason, item.commands.join(" "),
                        item.roles.map((r) => r.label).join(" "), item.id].join(" ").toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
    const key = (i: Item): [number, number] | string | number =>
      sortKey === "verdict" ? [RANK[i.verdict] ?? 9, -i.score] : sortKey === "score" ? i.score : sortKey === "name" ? i.title.toLowerCase()
      : sortKey === "type" ? kindLabel(i.kind) : presence(i);
    return list.sort((a, b) => {
      const x = key(a), y = key(b);
      const order = Array.isArray(x) && Array.isArray(y) ? x[0] - y[0] || x[1] - y[1] : x < y ? -1 : x > y ? 1 : 0;
      return descending ? -order : order;
    });
  });

  const current = $derived(items.find((i) => i.id === selected) ?? null);

  function sortBy(key: typeof sortKey): void {
    if (sortKey === key) descending = !descending;
    else { sortKey = key; descending = key === "score"; }
  }

  function clearIds(): void {
    ids = null;
    caption = "";
  }

  // virtual list
  const ROW = 30;
  let scroller: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let viewHeight = $state(600);
  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 6));
  const end = $derived(Math.min(rows.length, Math.ceil((scrollTop + viewHeight) / ROW) + 6));

  function onkey(event: KeyboardEvent): void {
    if (!["ArrowDown", "ArrowUp"].includes(event.key) || !rows.length) return;
    event.preventDefault();
    const index = rows.findIndex((r) => r.id === selected);
    const next = Math.min(rows.length - 1, Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)));
    selected = rows[next].id;
    if (scroller) {
      const y = next * ROW;
      if (y < scroller.scrollTop) scroller.scrollTop = y;
      else if (y + ROW * 2 > scroller.scrollTop + viewHeight) scroller.scrollTop = y + ROW * 2 - viewHeight;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>{t("page.findings")}</h1>
    <span class="grow"></span>
    <input type="search" placeholder={t("findings.search")} bind:value={text} />
  </div>
  <div class="filters">
    {#each VERDICT_ORDER as verdict (verdict)}
      <button class="chip" class:on={verdicts[verdict] && !ids} onclick={() => { clearIds(); verdicts[verdict] = !verdicts[verdict]; }}>
        {verdictLabel(verdict)} <span class="num">{counts[verdict]}</span>
      </button>
    {/each}
    <span class="grow"></span>
    {#if ids}<span class="faint">{caption}</span><button class="link" onclick={clearIds}>{t("findings.showAll")}</button>{/if}
    <select bind:value={kind} aria-label={t("findings.type")}>
      <option value="">{t("findings.allTypes")}</option>
      {#each KINDS as value (value)}<option {value}>{kindLabel(value)}</option>{/each}
    </select>
    <label class="check"><input type="checkbox" bind:checked={showIgnored} /> {t("findings.showIgnored")}</label>
  </div>

  <div class="split">
    <div class="list">
      <div class="head">
        <button onclick={() => sortBy("verdict")}>{t("findings.verdict")}</button><button onclick={() => sortBy("score")}>{t("findings.score")}</button>
        <button onclick={() => sortBy("name")}>{t("findings.name")}</button><button onclick={() => sortBy("type")}>{t("findings.type")}</button>
        <button onclick={() => sortBy("presence")}>{t("findings.presence")}</button>
      </div>
      <div class="rows" bind:this={scroller} bind:clientHeight={viewHeight} onscroll={() => (scrollTop = scroller?.scrollTop ?? 0)}
           onkeydown={onkey} tabindex="0" role="grid" aria-rowcount={rows.length}>
        <div style:height="{rows.length * ROW}px" style:position="relative">
          {#each rows.slice(start, end) as item, i (item.id)}
            {@const handled = item.actions_taken?.some((e) => e.ok)}
            <div class="row" class:sel={item.id === selected} class:odd={(start + i) % 2 === 1}
                 style:transform="translateY({(start + i) * ROW}px)" onclick={() => (selected = item.id)} role="row" tabindex="-1" onkeydown={() => {}}>
              <span class="verdict" style:--c={verdictColor(item.verdict)}>
                {verdictLabel(item.verdict)}{handled ? ` · ${t("findings.handled")}` : ""}{isIgnored(item.id) ? ` · ${t("findings.ignored")}` : ""}
              </span>
              <span class="score"><span class="meter"><span style:width="{item.score}%" style:background={item.score >= 70 ? "var(--remove)" : item.score >= 40 ? "var(--disable)" : item.score >= 15 ? "var(--review)" : "var(--no-signals)"}></span></span><span class="num faint">{item.score}</span></span>
              <span class="name" title={item.what || item.title}>{item.title}</span>
              <span class="muted">{kindLabel(item.kind)}</span>
              <span class="muted">{presence(item)}</span>
            </div>
          {/each}
        </div>
      </div>
      <div class="faint foot">{t("findings.shown", { shown: rows.length, total: items.length })}</div>
    </div>
    <aside class="panel side">
      {#if current}
        <FindingDetail item={current} {elevated} />
      {:else}
        <p class="muted empty">{report.analysis ? t("findings.select") : t("findings.runScan")}</p>
      {/if}
    </aside>
  </div>
</div>

<style>
  .filters { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .filters .grow { flex: 1; }
  select { font: inherit; color: var(--ink); background: var(--surface); border: 1px solid var(--rule-strong); border-radius: 5px; padding: 4px 8px; }
  .link { border: 0; background: transparent; color: var(--accent); padding: 0 6px; }
  .split { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(400px, 1fr); gap: 12px; }
  .list { display: flex; flex-direction: column; min-height: 0; background: var(--surface); border: 1px solid var(--rule); border-radius: 8px; overflow: hidden; }
  .head, .row { display: grid; grid-template-columns: 104px 92px minmax(160px, 1fr) 96px 100px; align-items: center; gap: 0 8px; padding: 0 10px; }
  .head { height: 34px; border-bottom: 1px solid var(--rule); }
  .head button { border: 0; background: transparent; padding: 0; text-align: left; font-size: 12px; font-weight: 600; color: var(--ink2); }
  .rows { flex: 1; min-height: 0; overflow-y: auto; outline: none; }
  .row { position: absolute; left: 0; right: 0; top: 0; height: 30px; font-size: 13px; cursor: default; }
  .row.odd { background: var(--surface2); }
  .row:hover { background: color-mix(in srgb, var(--select) 55%, var(--surface)); }
  .row.sel { background: var(--select); }
  .verdict { color: var(--c); font-weight: 600; border-left: 4px solid var(--c); padding-left: 8px; height: 100%; display: flex; align-items: center;
             white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-left: -10px; }
  .score { display: flex; align-items: center; gap: 6px; }
  .meter { width: 54px; height: 5px; border-radius: 3px; background: var(--rule); overflow: hidden; display: inline-block; }
  .meter span { display: block; height: 100%; }
  .name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row .muted { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .foot { padding: 6px 10px; border-top: 1px solid var(--rule); }
  .side { padding: 0; overflow-y: auto; }
  .empty { padding: 40px 30px; text-align: center; }
</style>
