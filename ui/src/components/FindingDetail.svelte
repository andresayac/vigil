<script lang="ts">
  import * as api from "../lib/api";
  import { changesOf, sinceLast } from "../lib/changes";
  import { num, when } from "../lib/format";
  import { t, type Key } from "../lib/i18n/index.svelte";
  import { kindLabel, verdictColor, verdictLabel } from "../lib/labels";
  import { act, isIgnored, report, toggleIgnored } from "../lib/report.svelte";
  import type { ActionSpec, Item } from "../lib/types";
  import Pill from "./Pill.svelte";

  let { item, elevated }: { item: Item; elevated: boolean } = $props();

  const SOURCE: Record<string, Key> = { ai: "detail.sourceAi", heuristic: "detail.sourceRules", automatic: "detail.sourceAuto" };
  const GROUPS: [string, Key][] = [["contain", "detail.groupContain"], ["disable", "detail.groupDisable"], ["remove", "detail.groupRemove"],
                                   ["fix", "detail.groupFix"], ["inspect", "detail.groupInspect"]];

  let specs = $state<ActionSpec[]>([]);
  let copied = $state(false);

  $effect(() => {
    const id = item.id;
    specs = [];
    void api.planActions(id).then((list) => {
      if (item.id === id) specs = list;
    });
  });

  const file = $derived((item.file ?? {}) as Record<string, any>);
  const vt = $derived((item.vt ?? {}) as Record<string, any>);
  const net = $derived((item.network ?? {}) as Record<string, any>);
  const signals = $derived([...item.flags].filter((f) => f.weight > 0).sort((a, b) => b.weight - a.weight));
  const facts = $derived(Object.entries(item.facts ?? {})
    .filter(([k, v]) => !["topic", "uninstall", "registry_key", "folder"].includes(k) && v !== null && v !== "" &&
            !(Array.isArray(v) && !v.length) && !(typeof v === "object" && v && !Object.keys(v).length))
    .slice(0, 24));
  const since = $derived(sinceLast(changesOf(report.analysis), item.id));
  const manual = $derived((item.remediation ?? []).filter((s: any) => s.note || s.command).slice(0, 10) as any[]);

  function signature(): string {
    if (file.exists === false) return t("detail.sigMissing");
    const status = String(file.sig_status ?? "");
    const signer = file.signer ? ` · ${file.signer}` : "";
    const known: Record<string, Key> = { Valid: "detail.sigValid", NotSigned: "detail.sigNotSigned", HashMismatch: "detail.sigBroken",
                                         NotTrusted: "detail.sigUntrusted", UnknownError: "detail.sigUnknown" };
    return known[status] ? `${t(known[status])}${status === "NotSigned" || status === "HashMismatch" ? "" : signer}` : status;
  }

  function show(value: unknown): string {
    if (Array.isArray(value)) return value.slice(0, 20).map((v) => (typeof v === "object" && v ? Object.entries(v).map(([a, b]) => `${a}: ${b}`).join(", ") : String(v))).join(", ");
    if (value && typeof value === "object") return Object.entries(value).slice(0, 12).map(([a, b]) => `${a}: ${b}`).join("; ");
    return String(value ?? "");
  }

  const fileRows = $derived(([
    [t("detail.signature"), signature()], [t("detail.publisher"), file.company], [t("detail.description"), file.description],
    [t("detail.product"), file.product], [t("detail.version"), file.version], [t("detail.originalName"), file.original],
    [t("detail.size"), typeof file.size === "number" ? t("unit.bytes", { n: num(file.size) }) : ""],
    [t("detail.created"), file.created], [t("detail.modified"), file.modified], ["SHA-256", item.sha256], ["VirusTotal", vt.summary],
  ] as [string, unknown][]).filter(([, v]) => v !== undefined && v !== null && v !== ""));

  function text(): string {
    const lines = [`${item.title} [${verdictLabel(item.verdict)}]`, item.subtitle];
    for (const [k, v] of [[t("detail.what"), item.what], [t("detail.why"), item.reason], [t("detail.recommendation"), item.action],
                          [t("detail.path"), item.path], ["SHA-256", item.sha256]]) {
      if (v) lines.push(`${k}: ${v}`);
    }
    if (item.flags.length) lines.push(`${t("detail.signals")}: ${item.flags.filter((f) => f.weight > 0).map((f) => f.text).join("; ")}`);
    for (const r of item.roles) lines.push(`- ${r.label}`);
    for (const c of item.commands) lines.push(`> ${c}`);
    return lines.filter(Boolean).join("\n");
  }

  async function copy(): Promise<void> {
    await navigator.clipboard.writeText(text());
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  const run = (index: number) => act({ kind: "finding", itemId: item.id, index });
</script>

<div class="detail">
  <h2 class="selectable">{item.title}</h2>
  {#if item.subtitle && item.subtitle !== item.title}<p class="muted selectable">{item.subtitle}</p>{/if}
  <div class="pills">
    <Pill text={verdictLabel(item.verdict)} color={verdictColor(item.verdict)} solid />
    <Pill text={kindLabel(item.kind)} color="var(--ink2)" />
    <Pill text={SOURCE[item.verdict_source] ? t(SOURCE[item.verdict_source]) : (item.verdict_source || t("detail.sourceRules"))} color="var(--ink3)" />
    {#if item.confidence}<Pill text={t(item.confidence === "high" ? "detail.confidenceHigh" : item.confidence === "low" ? "detail.confidenceLow" : "detail.confidenceMedium")} color="var(--ink3)" />{/if}
    {#if item.score}<Pill text={t("detail.score", { score: String(item.score) })} color="var(--ink3)" />{/if}
  </div>

  {#if item.what}<p class="selectable">{item.what}</p>{/if}
  {#if item.reason}<h4>{t("detail.why")}</h4><p class="selectable">{item.reason}</p>{/if}
  {#if item.action}<h4>{t("detail.recommendation")}</h4><p class="selectable">{item.action}</p>{/if}

  {#if since}
    <h4>{t("detail.since")}</h4>
    {#if since.isNew}<p class="muted">{t("detail.sinceNew")}</p>{/if}
    {#if since.what.length}<ul>{#each since.what as line, index (index)}<li class="selectable">{line}</li>{/each}</ul>{/if}
  {/if}

  {#if specs.length || !item.trusted}
    <h4>{t("detail.actions")}</h4>
    {#if !elevated && specs.some((s) => s.admin)}
      <p class="faint">{t("detail.needsAdmin")}</p>
    {/if}
    {#each specs as spec, index (spec.op + index)}
      {#if spec.steps.length}
        <div><button class="danger" title={spec.explain} disabled={report.busy || (spec.admin && !elevated)} onclick={() => run(index)}>{spec.label}</button></div>
        <p class="faint">{spec.explain}</p>
      {/if}
    {/each}
    {#each GROUPS as [group, title] (group)}
      {@const members = specs.map((s, i) => [s, i] as const).filter(([s]) => s.group === group && !s.steps.length)}
      {#if members.length || group === "inspect"}
        <div class="group">
          <span class="faint caption">{t(title)}</span>
          <div class="buttons">
            {#each members as [spec, index] (spec.op + index)}
              <button class:danger-outline={spec.destructive} disabled={report.busy || (spec.admin && !elevated)}
                      title="{spec.explain}{spec.reversible ? '' : `  ${t('detail.cannotUndo')}`}" onclick={() => run(index)}>{spec.label}</button>
            {/each}
            {#if group === "inspect"}
              <button onclick={() => toggleIgnored(item.id)}>{isIgnored(item.id) ? t("detail.unignore") : t("detail.ignore")}</button>
              <button onclick={copy}>{copied ? t("common.copied") : t("detail.copy")}</button>
            {/if}
          </div>
        </div>
      {/if}
    {/each}
  {/if}

  {#if item.actions_taken?.length}
    <h4>{t("detail.alreadyDone")}</h4>
    {#each item.actions_taken.slice(-12) as entry, index (index)}
      <p class="muted">{entry.ok ? t("detail.done") : t("detail.failed")} · {entry.label} · {when(entry.time)}<br />{entry.message}</p>
    {/each}
  {/if}

  {#if signals.length}
    <h4>{t("detail.signals")}</h4>
    <div class="kv signals">
      {#each signals as flag (flag.code)}<span class="faint weight">+{flag.weight}</span><span class="selectable">{flag.text}</span>{/each}
    </div>
  {/if}

  {#if item.roles.length}
    <h4>{t("detail.where")}</h4>
    <ul>{#each item.roles.slice(0, 24) as role, index (index)}<li class="selectable">{role.label}</li>{/each}</ul>
  {/if}

  {#if item.path || item.file}
    <h4>{t("detail.file")}</h4>
    {#if item.path}<pre class="mono code">{item.path}</pre>{/if}
    <div class="kv">{#each fileRows as [k, v] (k)}<span class="faint">{k}</span><span class="selectable wrap">{v}</span>{/each}</div>
  {/if}

  {#if item.commands.length}
    <h4>{t("detail.commandLines", { count: item.commands.length })}</h4>
    {#each item.commands as command, index (index)}<pre class="mono code">{command}</pre>{/each}
  {/if}
  {#each item.decoded as decoded, index (index)}<h4>{t("detail.decoded")}</h4><pre class="mono code">{decoded}</pre>{/each}

  {#if Object.keys(net).length}
    <h4>{t("detail.network")}</h4>
    <div class="kv">
      {#if net.listen?.length}<span class="faint">{t("detail.listening")}</span><span class="wrap">{net.listen.join(", ")}</span>{/if}
      {#if net.exposed?.length}<span class="faint">{t("detail.reachable")}</span><span class="wrap">{net.exposed.join(", ")}</span>{/if}
      {#if net.remote?.length}<span class="faint">{t("detail.connected")}</span><span class="wrap">{net.remote.join(", ")}{(net.remote_total ?? 0) > net.remote.length ? ` ${t("detail.more", { count: net.remote_total - net.remote.length })}` : ""}</span>{/if}
    </div>
  {/if}

  {#if item.members?.length}
    <h4>{t("detail.components", { count: item.members.length })}</h4>
    {#each item.members.slice(0, 60) as member, index (index)}<p class="selectable"><b>{String(member.name ?? "")}</b><br /><span class="faint">{String(member.path ?? "")}</span></p>{/each}
  {/if}

  {#if facts.length}
    <h4>{t("detail.details")}</h4>
    <div class="kv">{#each facts as [k, v] (k)}<span class="faint">{k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase())}</span><span class="selectable wrap">{show(v).slice(0, 600)}</span>{/each}</div>
  {/if}

  {#if manual.length}
    <h4>{t("detail.manual")}</h4>
    {#each manual as step, index (index)}
      <p>{step.title ?? ""}</p>
      {#if step.command}<pre class="mono code">{step.command}</pre>{/if}
      {#if step.note}<p class="faint">{step.note}</p>{/if}
    {/each}
  {/if}
</div>

<style>
  .detail { display: flex; flex-direction: column; gap: 8px; padding: 18px 22px 26px; }
  p { margin: 0; }
  h4 { margin: 10px 0 0; font: 600 13.5px var(--font-display); color: var(--ink2); }
  .pills { display: flex; flex-wrap: wrap; gap: 6px; }
  .group { display: grid; grid-template-columns: 84px minmax(0, 1fr); gap: 8px; align-items: start; }
  .caption { padding-top: 6px; }
  .buttons { display: flex; flex-wrap: wrap; gap: 6px; }
  button.danger { background: var(--remove); border-color: var(--remove); color: #fff; font-weight: 600; }
  button.danger:hover:not(:disabled) { background: color-mix(in srgb, var(--remove) 88%, #000); }
  button.danger:disabled { background: var(--surface); color: var(--ink3); border-color: var(--rule); }
  .kv { display: grid; grid-template-columns: 112px minmax(0, 1fr); gap: 4px 10px; font-size: 13px; }
  .signals { grid-template-columns: 34px minmax(0, 1fr); }
  .weight { text-align: right; }
  .wrap { overflow-wrap: anywhere; }
  .code { margin: 0; padding: 7px 9px; background: var(--sunken); border: 1px solid var(--rule); border-radius: 5px;
          white-space: pre-wrap; word-break: break-all; user-select: text; }
  ul { margin: 0; padding-left: 18px; }
</style>
