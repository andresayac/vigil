<script lang="ts">
  import { onMount } from "svelte";
  import Readouts from "../components/Readouts.svelte";
  import Tile from "../components/Tile.svelte";
  import VerdictStrip from "../components/VerdictStrip.svelte";
  import WatchCard from "../components/WatchCard.svelte";
  import * as api from "../lib/api";
  import { changesOf } from "../lib/changes";
  import { pct, size, when as whenText } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { VERDICT_ORDER, riskColor, riskLabel, verdictColor, verdictLabel } from "../lib/labels";
  import { acquire, live, release, series } from "../lib/live.svelte";
  import { readouts } from "../lib/posture";
  import { isIgnored, report } from "../lib/report.svelte";
  import type { Item, Volume } from "../lib/types";

  let { onopenitem, onopenids, onopenverdict, onscan, onpage }: {
    onopenitem: (id: string) => void;
    onopenids: (ids: string[], caption: string) => void;
    onopenverdict: (verdict: string) => void;
    onscan: () => void;
    onpage: (page: string, resource?: string) => void;
  } = $props();

  let systemDrive = $state<Volume | null>(null);

  onMount(() => {
    void acquire();
    void api.volumes().then((all) => (systemDrive = all.find((v) => v.mount.toUpperCase().startsWith("C:")) ?? all[0] ?? null));
    return () => void release();
  });

  const a = $derived(report.analysis);
  const visible = $derived((a?.items ?? []).filter((i) => !isIgnored(i.id)));
  const strip = $derived(visible.filter((i) => i.verdict !== "trusted").map((i) => ({ id: i.id, verdict: i.verdict, title: i.title })));
  const counts = $derived(VERDICT_ORDER.map((v) => [v, visible.filter((i) => i.verdict === v).length] as const).filter(([, n]) => n > 0));
  const level = $derived(a?.summary?.risk_level ?? null);
  const when = $derived(whenText(String(a?.meta?.started ?? "")));
  const metaLine = $derived([
    when ? t("overview.scanned", { when }) : "",
    a?.meta?.is_admin ? t("overview.asAdmin") : t("overview.notAdmin"),
    a?.ai?.with_verdict ? t("overview.aiBy", { model: String(a.ai.model ?? "") })
      : a?.ai?.reason ? t("overview.aiSkipped", { reason: String(a.ai.reason) }) : "",
  ].filter(Boolean).join(" · "));

  function localHeadline(items: Item[]): string {
    const critical = items.filter((i) => !i.trusted && i.level === "critical").length;
    const suspicious = items.filter((i) => !i.trusted && i.level === "suspicious").length;
    if (critical) return t("overview.headlineCritical", { count: critical });
    if (suspicious) return t("overview.headlineSuspicious", { count: suspicious });
    return t("overview.headlineClean");
  }

  const top = $derived(visible.filter((i) => ["remove", "disable", "review"].includes(i.verdict) && !i.trusted).slice(0, 8));
  // Since the last scan: new findings first by verdict (remove, disable, review…), then by score.
  const changes = $derived(changesOf(a));
  const RANK: Record<string, number> = Object.fromEntries(VERDICT_ORDER.map((v, i) => [v, i]));
  const byId = $derived(new Map((a?.items ?? []).map((i) => [i.id, i])));
  const fresh = $derived((changes?.new ?? []).map((id) => byId.get(id)).filter((i): i is Item => !!i && !isIgnored(i.id))
    .sort((x, y) => (RANK[x.verdict] ?? 9) - (RANK[y.verdict] ?? 9) || y.score - x.score));
  const altered = $derived((changes?.changed ?? []).map((c) => ({ item: byId.get(c.id), what: c.what }))
    .filter((c): c is { item: Item; what: string[] } => !!c.item && !isIgnored(c.item.id))
    .sort((x, y) => (RANK[x.item.verdict] ?? 9) - (RANK[y.item.verdict] ?? 9) || y.item.score - x.item.score));
  const sinceWhen = $derived(whenText(changes?.previous.started ?? ""));
  const tally = $derived(changes ? [
    changes.new.length ? t("overview.sinceNew", { count: changes.new.length }) : "",
    changes.gone.length ? t("overview.sinceGone", { count: changes.gone.length }) : "",
    changes.changed.length ? t("overview.sinceChanged", { count: changes.changed.length }) : "",
    changes.posture.length ? t("overview.sinceSettings", { count: changes.posture.length }) : "",
  ].filter(Boolean).join(" · ") : "");

  const snap = $derived(live.snapshot);
  const gpu = $derived(snap ? [...snap.gpus].sort((x, y) => y.dedicatedTotal - x.dedicatedTotal)[0] : undefined);
</script>

<div class="page scroll">
  <div class="tiles">
    <Tile title={t("res.cpu")} hue="cpu" value={snap ? pct(snap.cpu) : "—"} detail={snap ? t("overview.logical", { count: snap.perCore.length }) : ""}
          values={series("cpu")} onclick={() => onpage("performance", "cpu")} />
    <Tile title={t("res.memory")} hue="memory" value={snap ? pct((snap.memory.used / snap.memory.total) * 100) : "—"}
          detail={snap ? t("overview.available", { size: size(snap.memory.available) }) : ""} values={series("memory")} onclick={() => onpage("performance", "memory")} />
    {#if gpu}
      <Tile title={t("res.gpu")} hue="gpu" value={pct(gpu.utilization)}
            detail={t("overview.vram", { used: size(gpu.dedicatedUsed), total: size(gpu.dedicatedTotal, 0) })}
            values={series(`gpu:${gpu.luid}`)} onclick={() => onpage("performance", `gpu:${gpu.luid}`)} />
    {/if}
    {#if systemDrive}
      {@const free = systemDrive.total ? (systemDrive.free / systemDrive.total) * 100 : 0}
      <Tile title={t("overview.drive", { drive: systemDrive.mount.replace(/\\$/, "") })} value={t("overview.free", { size: size(systemDrive.free, 0) })}
            detail={t("overview.freeShare", { pct: pct(free), total: size(systemDrive.total) })}
            level={free < 5 ? "bad" : free < 12 ? "warn" : ""} onclick={() => onpage("storage")} />
    {/if}
  </div>

  {#if report.scanning}
    <section class="panel progress">
      <h2>{report.title ? t(report.title) : ""}</h2>
      <div class="bar"><div></div></div>
      <pre class="mono log">{report.log.join("\n")}</pre>
    </section>
  {/if}
  {#if report.error}<p class="error">{report.error}</p>{/if}

  {#if !a && report.loaded && !report.scanning}
    <section class="empty">
      <h1>{t("overview.emptyTitle")}</h1>
      <p class="muted">{t("overview.emptyBody")}</p>
      <div><button class="primary" onclick={onscan}>{t("overview.firstScan")}</button></div>
    </section>
    <div class="watch-alone"><WatchCard onpage={(key) => onpage(key)} /></div>
  {:else if a}
    <section class="hero">
      <div class="risk" style:color={riskColor(level)}>{riskLabel(level)}</div>
      <h1 class="headline selectable">{a.summary?.headline || localHeadline(visible)}</h1>
      {#if a.summary?.summary}<p class="muted selectable body">{a.summary.summary}</p>{/if}
      <div class="faint">{metaLine}</div>
    </section>

    <VerdictStrip items={strip} onopen={onopenitem} />
    <div class="counts">
      {#each counts as [verdict, count] (verdict)}
        <button class="count" style:color={verdictColor(verdict)} onclick={() => onopenverdict(verdict)}>
          <span class="num">{count}</span> {verdictLabel(verdict)}
        </button>
      {/each}
    </div>

    <div class="columns">
      <section class="panel">
        <h2>{t("overview.first")}</h2>
        {#if a.summary?.priority_actions?.length}
          {#each a.summary.priority_actions as action, index (index)}
            {@const ids = (action.ids ?? []).filter((id) => a.items.some((i) => i.id === id))}
            <h3>{index + 1}. {action.title}</h3>
            {#if action.detail}<p class="muted selectable">{action.detail}</p>{/if}
            {#if ids.length}
              <button class="link" onclick={() => onopenids(ids, action.title ?? "")}>{t("overview.showItems", { count: ids.length })}</button>
            {/if}
          {/each}
        {:else if top.length}
          {#each top as item (item.id)}
            <button class="link" onclick={() => onopenitem(item.id)}>{verdictLabel(item.verdict)} · {item.title}</button>
            {#if item.reason || item.subtitle}<p class="faint">{item.reason || item.subtitle}</p>{/if}
          {/each}
        {:else}
          <p class="muted">{t("overview.nothing")}</p>
        {/if}
        {#if a.summary?.good_practices?.length}
          <h3 class="habits">{t("overview.habits")}</h3>
          <ul>
            {#each a.summary.good_practices as practice, index (index)}<li class="muted">{practice}</li>{/each}
          </ul>
        {/if}
      </section>

      <div class="side">
        <WatchCard onpage={(key) => onpage(key)} />
        {#if changes}
          <section class="panel since">
            <h2>{sinceWhen ? t("overview.since", { when: sinceWhen }) : t("overview.sinceUndated")}</h2>
            {#if !tally}
              <p class="muted">{t("overview.sinceNothing")}</p>
            {:else}
              <p class="muted">{tally}</p>
              {#if fresh.length}
                <h3>{t("overview.sinceNewTitle")}</h3>
                <div class="list">
                  {#each fresh.slice(0, 5) as item (item.id)}
                    <button class="link" onclick={() => onopenitem(item.id)}>{verdictLabel(item.verdict)} · {item.title}</button>
                  {/each}
                  {#if fresh.length > 1}
                    <button class="link more" onclick={() => onopenids(fresh.map((i) => i.id), t("findings.newSince"))}>{t("overview.sinceShowNew", { count: fresh.length })}</button>
                  {/if}
                </div>
              {/if}
              {#if altered.length}
                <h3>{t("overview.sinceChangedTitle")}</h3>
                <div class="list">
                  {#each altered.slice(0, 4) as change (change.item.id)}
                    <button class="link" onclick={() => onopenitem(change.item.id)}>{change.item.title}</button>
                    {#if change.what.length}<p class="faint selectable">{change.what.join(" · ")}</p>{/if}
                  {/each}
                </div>
                {#if altered.length > 4}<p class="faint">{t("overview.sinceMore", { count: altered.length - 4 })}</p>{/if}
              {/if}
              {#if changes.posture.length}
                <h3>{t("overview.sinceSettingsTitle")}</h3>
                <ul>{#each changes.posture.slice(0, 8) as line, index (index)}<li class="muted selectable">{line}</li>{/each}</ul>
              {/if}
              {#if changes.gone.length}
                <h3>{t("overview.sinceGoneTitle")}</h3>
                {#each changes.gone.slice(0, 4) as gone, index (index)}
                  <p class="muted selectable">{gone.title}{gone.path && gone.path !== gone.title ? ` · ${gone.path}` : ""}</p>
                {/each}
                {#if changes.gone.length > 4}<p class="faint">{t("overview.sinceMore", { count: changes.gone.length - 4 })}</p>{/if}
              {/if}
            {/if}
          </section>
        {/if}
        <section class="panel">
          <h2>{t("overview.security")}</h2>
          <Readouts rows={readouts(a.posture ?? {})} nameWidth={200} />
        </section>
        {#if a.notes?.length}
          <section class="panel">
            <h2>{t("overview.coverage")}</h2>
            {#each a.notes.slice(0, 12) as note, index (index)}
              <p class="muted selectable">{String(note.area ?? "").replace(/^./, (c) => c.toUpperCase())}: {note.message}</p>
            {/each}
          </section>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .scroll { overflow-y: auto; gap: 14px; padding: 22px 30px 30px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
  .hero { display: flex; flex-direction: column; gap: 6px; max-width: 1050px; }
  .risk { font: 600 15px var(--font-display); }
  .headline { font: 400 25px/1.25 var(--font-display); }
  .body { margin: 0; max-width: 960px; }
  .counts { display: flex; flex-wrap: wrap; gap: 4px 20px; }
  .count { border: 0; background: transparent; padding: 0; font: 600 15px var(--font-display); }
  .count:hover:not(:disabled) { background: transparent; text-decoration: underline; }
  .columns { display: grid; grid-template-columns: minmax(0, 3fr) minmax(360px, 2fr); gap: 16px; align-items: start; }
  .columns .panel { display: flex; flex-direction: column; gap: 8px; }
  .side { display: flex; flex-direction: column; gap: 16px; }
  .panel p { margin: 0; }
  .habits { margin-top: 8px; }
  .since h3 { margin-top: 6px; }
  .since p { overflow-wrap: anywhere; }
  .since .list { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
  .since .link { min-height: 24px; padding: 2px 0; }
  .since .more { margin-top: 4px; }
  ul { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 4px; }
  .link { border: 0; background: transparent; padding: 0; color: var(--accent); text-align: left; }
  .link:hover:not(:disabled) { background: transparent; text-decoration: underline; }
  .empty { display: flex; flex-direction: column; gap: 10px; max-width: 900px; padding-top: 30px; }
  .empty p { margin: 0; }
  .watch-alone { max-width: 560px; }
  .progress { display: flex; flex-direction: column; gap: 10px; }
  .bar { height: 4px; background: var(--sunken); border-radius: 2px; overflow: hidden; position: relative; }
  .bar div { position: absolute; inset: 0 60% 0 0; background: var(--chart); animation: slide 1.4s ease-in-out infinite; }
  @keyframes slide { from { transform: translateX(-100%); } to { transform: translateX(250%); } }
  .log { max-height: 200px; overflow: auto; margin: 0; white-space: pre-wrap; color: var(--ink2); user-select: text; }
  .error { color: var(--bad); margin: 0; }
  @media (max-width: 1200px) { .columns { grid-template-columns: 1fr; } }
</style>
