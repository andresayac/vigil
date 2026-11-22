<script lang="ts">
  // "Investigate with AI" for one finding: the AI agent reads with Vigil's read-only tools and
  // answers; it never acts. Every text here came from the model or the computer: always
  // interpolated, never markup.
  import * as api from "../lib/api";
  import { t } from "../lib/i18n/index.svelte";
  import type { Key } from "../lib/i18n/en";
  import { verdictColor, verdictLabel } from "../lib/labels";
  import type { InvestigationView } from "../lib/types";

  let { itemId, onnavigate }: { itemId: string; onnavigate?: (page: string) => void } = $props();

  let running = $state(false);
  let read = $state<string[]>([]);
  let result = $state<InvestigationView | null>(null);
  let message = $state("");
  let showCalls = $state(false);

  $effect(() => api.subscribe(api.onInvestigate((p) => {
    if (running && p.phase === "tool" && p.text) read = [...read.slice(-7), p.text];
  })));

  async function start(): Promise<void> {
    running = true;
    read = [];
    result = null;
    message = "";
    try {
      const view = await api.investigateFinding(itemId);
      if (view) result = view;
      else message = t("investigate.notStarted");
    } catch (error) {
      message = t("investigate.error", { error: String(error) });
    } finally {
      running = false;
    }
  }

  const pageName = (page: string): string => t(`page.${page}` as Key);
  const confidence = (level: string): string => t(`investigate.conf.${level}` as Key);
  const size = (bytes: number): string => (bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`);
</script>

<section class="investigate" aria-live="polite">
  {#if !result && !running}
    <div class="start">
      <button class="primary" onclick={start}><i class="icon">{""}</i>{t("investigate.button")}</button>
      <p class="faint">{t("investigate.note")}</p>
      {#if message}<p class="note">{message}</p>{/if}
    </div>
  {:else if running}
    <div class="start">
      <div class="busy">
        <span class="spinner" aria-hidden="true"></span>
        <span>{t("investigate.running")}</span>
        <span class="grow"></span>
        <button onclick={() => void api.investigateCancel()}><i class="icon">{""}</i>{t("investigate.stop")}</button>
      </div>
      {#each read as line, i (i)}
        <div class="faint mono">{t("investigate.reading", { tool: line })}</div>
      {/each}
    </div>
  {:else if result}
    <h3>{t("investigate.title")}</h3>
    <div class="verdict-line">
      <span class="verdict" style:--c={verdictColor(result.verdict)}>{verdictLabel(result.verdict)}</span>
      <span class="faint">{t("investigate.confidence", { level: confidence(result.confidence) })}</span>
    </div>
    {#if result.guardNote}<p class="guard">{result.guardNote}</p>{/if}
    <p class="selectable">{result.conclusion}</p>

    {#if result.evidence.length}
      <h4>{t("investigate.evidence")}</h4>
      <ul>
        {#each result.evidence as e, i (i)}
          <li>
            <span class="selectable">{e.text}</span>
            {#if e.page && onnavigate}
              <button class="link" onclick={() => onnavigate?.(e.page)}>{t("investigate.open", { page: pageName(e.page) })}</button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}

    {#if result.suggestedAction}
      <h4>{t("investigate.suggested")}</h4>
      <p class="selectable">{result.suggestedAction}</p>
      <p class="faint">{t("investigate.suggestedNote")}</p>
    {/if}

    {#if result.openQuestions.length}
      <h4>{t("investigate.questions")}</h4>
      <ul>
        {#each result.openQuestions as q, i (i)}<li class="selectable">{q}</li>{/each}
      </ul>
    {/if}

    <div class="meta faint">
      <span>{t("investigate.destination", { destination: result.destination })}</span>
      {#if result.local}<span>{t("investigate.local")}</span>{/if}
      {#if result.anonymized}<span>{t("investigate.anonymized")}</span>{/if}
      {#if result.limit}<span>{t("investigate.limit", { limit: result.limit })}</span>{/if}
    </div>

    <button class="link calls" onclick={() => (showCalls = !showCalls)} aria-expanded={showCalls}>
      <i class="icon">{showCalls ? "" : ""}</i>{t("investigate.calls", { count: result.calls.length })}
    </button>
    {#if showCalls}
      <div class="log">
        {#each result.calls as c, i (i)}
          <div class="call" class:failed={!c.ok}>
            <span class="mono">{c.name}</span>
            <span class="mono faint args">{JSON.stringify(c.input)}</span>
            <span class="faint num">{size(c.bytes)} · {c.ms} ms{c.ok ? "" : ` · ${t("investigate.failedCall")}`}</span>
          </div>
        {/each}
      </div>
    {/if}

    <div class="again">
      <button onclick={start}><i class="icon">{""}</i>{t("investigate.button")}</button>
    </div>
  {/if}
</section>

<style>
  .investigate { border-top: 1px solid var(--rule); margin: 0 22px 22px; padding-top: 14px; display: flex; flex-direction: column; gap: 6px; }
  .start { display: flex; flex-direction: column; gap: 6px; }
  .start > button { align-self: flex-start; }
  button > .icon { margin-right: 6px; }
  .busy { display: flex; align-items: center; gap: 8px; }
  .grow { flex: 1; }
  .spinner { width: 14px; height: 14px; border-radius: 50%; border: 2px solid var(--rule-strong); border-top-color: var(--accent); animation: spin 0.9s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
  h3 { margin: 0; font-size: 15px; }
  h4 { margin: 6px 0 0; font-size: 13px; }
  p { margin: 0; font-size: 13px; }
  ul { margin: 0; padding-left: 18px; font-size: 13px; display: flex; flex-direction: column; gap: 3px; }
  .verdict-line { display: flex; align-items: baseline; gap: 10px; }
  .verdict { color: var(--c); font-weight: 600; border-left: 4px solid var(--c); padding-left: 8px; }
  .guard { color: var(--warn); }
  .note { font-size: 13px; }
  .meta { display: flex; flex-direction: column; gap: 2px; font-size: 12px; margin-top: 4px; }
  .link { border: 0; background: transparent; color: var(--accent); padding: 0 0 0 6px; font-size: 13px; }
  .calls { align-self: flex-start; padding-left: 0; }
  .log { display: flex; flex-direction: column; gap: 2px; font-size: 12px; }
  .call { display: grid; grid-template-columns: 150px minmax(0, 1fr) auto; gap: 8px; }
  .call.failed .mono:first-child { color: var(--warn); }
  .args { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mono { font-family: var(--mono, Consolas, monospace); font-size: 12px; }
  .again { margin-top: 6px; }
</style>
