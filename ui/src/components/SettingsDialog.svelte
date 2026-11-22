<script lang="ts">
  import * as api from "../lib/api";
  import { isLocalAddress, providerName, staysLocal } from "../lib/ai";
  import { LANGUAGES, t, type Key } from "../lib/i18n/index.svelte";
  import type { AiProvider, Effort, SecretChanges, Settings, WatchSettings } from "../lib/types";
  import { refreshWatch, setStatus } from "../lib/watch.svelte";
  import Modal from "./Modal.svelte";

  let { open, settings, dataDir = "", onclose, onsaved }: {
    open: boolean;
    settings: Settings | null;
    dataDir?: string;
    onclose: () => void;
    onsaved: (settings: Settings) => void;
  } = $props();

  let draft = $state<Settings | null>(null);
  let providers = $state<AiProvider[]>([]);
  /** Typed secret values (never shown back) and whether a stored one is being replaced or removed. */
  let secretInput = $state<Record<string, string>>({});
  let secretMode = $state<Record<string, "keep" | "replace" | "remove">>({});
  let models = $state<string[]>([]);
  let modelsNote = $state("");
  let loadingModels = $state(false);
  let error = $state("");
  let saving = $state(false);
  /** Background watch: saved with the other settings; Start with Windows runs at once (it changes Windows). */
  let watchDraft = $state<WatchSettings | null>(null);
  let autostart = $state(false);
  let autostartBusy = $state(false);
  let autostartError = $state("");

  $effect(() => {
    if (open && settings) {
      draft = structuredClone($state.snapshot(settings));
      secretInput = {};
      secretMode = {};
      models = [];
      modelsNote = "";
      error = "";
      void api.aiProviders().then((list) => (providers = list)).catch(() => (providers = []));
      watchDraft = null;
      autostartError = "";
      void api.watchStatus().then((status) => {
        watchDraft = structuredClone(status.settings);
        autostart = status.autostart;
      }).catch(() => (watchDraft = null));
    }
  });

  // "Automatic" and "Off" are single choices; the two API standards and the local agents are groups.
  const GROUPS: { kind: AiProvider["kind"]; label: Key }[] = [
    { kind: "api", label: "settings.ai.apis" },
    { kind: "local-agent", label: "settings.ai.localAgents" },
  ];
  /** Address examples for each API standard (its own service, or a server on this computer). */
  const ENDPOINT_EXAMPLES: Record<string, string> = {
    "openai-compatible": "https://api.openai.com/v1 · http://localhost:11434/v1 (Ollama) · http://localhost:1234/v1 (LM Studio)",
    "anthropic-compatible": "https://api.anthropic.com · http://localhost:11434 (Ollama)",
  };
  const EFFORTS: [Effort, Key][] = [
    ["low", "effort.low"], ["medium", "effort.medium"], ["high", "effort.high"], ["xhigh", "effort.xhigh"], ["max", "effort.max"],
  ];
  const DAYS = [7, 14, 30, 60, 90];

  const provider = $derived(providers.find((p) => p.id === draft?.ai.provider));
  const endpoint = $derived(draft?.ai.endpoint || provider?.defaultEndpoint || "");
  const local = $derived(staysLocal(provider, endpoint));
  const suggestions = $derived([...new Set([...(provider?.suggestedModels ?? []), ...models])]);
  const insecure = $derived(!!provider?.needsEndpoint && !!draft?.ai.endpoint && /^http:\/\//i.test(draft.ai.endpoint)
    && !isLocalAddress(draft.ai.endpoint));
  /** The provider's default model applies only at its own address (another server has other models). */
  const defaultModel = $derived(provider?.defaultModel && (!draft?.ai.endpoint || draft.ai.endpoint === provider.defaultEndpoint)
    ? provider.defaultModel : "");

  function pickProvider(id: string): void {
    if (!draft) return;
    draft.ai.provider = id;
    draft.ai.model = "";
    draft.ai.endpoint = "";
    models = [];
    modelsNote = "";
  }

  async function refreshModels(): Promise<void> {
    if (!draft || !provider) return;
    loadingModels = true;
    modelsNote = "";
    try {
      models = await api.aiModels(provider.id, endpoint);
      modelsNote = models.length ? t("settings.ai.modelsFound", { count: models.length }) : t("settings.ai.noModels");
    } catch (e) {
      models = [];
      modelsNote = String(e);
    } finally {
      loadingModels = false;
    }
  }

  const stored = (id: string) => !!draft?.secrets[id];
  const mode = (id: string) => secretMode[id] ?? (stored(id) ? "keep" : "replace");

  /** Start with Windows is a change to Windows: Rust confirms it natively and journals it (undo from History). */
  async function changeAutostart(box: HTMLInputElement): Promise<void> {
    const wanted = box.checked;
    autostartBusy = true;
    autostartError = "";
    try {
      const outcome = await api.setAutostart(wanted);
      const failed = outcome.records.find((r) => !r.ok);
      if (failed) autostartError = failed.message;
      await refreshWatch();
      autostart = (await api.watchStatus()).autostart;
    } catch (e) {
      autostartError = String(e);
    } finally {
      box.checked = autostart;
      autostartBusy = false;
    }
  }

  async function save(): Promise<void> {
    if (!draft) return;
    const secrets: SecretChanges = {};
    for (const id of new Set([...Object.keys(secretInput), ...Object.keys(secretMode)])) {
      if (mode(id) === "remove") secrets[id] = "";
      else if (mode(id) === "replace" && secretInput[id]?.trim()) secrets[id] = secretInput[id].trim();
    }
    saving = true;
    try {
      const saved = await api.saveSettings(draft, Object.keys(secrets).length ? secrets : null);
      if (watchDraft) setStatus(await api.watchConfigure($state.snapshot(watchDraft)));
      onsaved(saved);
      onclose();
    } catch (e) {
      error = String(e);
    } finally {
      saving = false;
    }
  }
</script>

{#snippet secretField(id: string, label: string, note = "")}
  <div class="setting">
    <div class="text"><span>{label}</span><span class="faint">{note ? `${note} ` : ""}{t("settings.secretNote")}</span></div>
    <div class="control">
      {#if mode(id) === "keep"}
        <span class="saved"><i class="icon">{""}</i>{t("settings.saved")}</span>
        <button onclick={() => (secretMode[id] = "replace")}>{t("settings.replace")}</button>
        <button onclick={() => { secretMode[id] = "remove"; secretInput[id] = ""; }}>{t("settings.remove")}</button>
      {:else if mode(id) === "remove"}
        <span class="faint">{t("settings.willRemove")}</span>
        <button onclick={() => (secretMode[id] = "keep")}>{t("settings.undo")}</button>
      {:else}
        <input type="password" autocomplete="off" spellcheck="false" placeholder={t("settings.pasteKey")}
               aria-label={label} bind:value={secretInput[id]} />
        {#if stored(id)}<button onclick={() => { secretMode[id] = "keep"; secretInput[id] = ""; }}>{t("common.cancel")}</button>{/if}
      {/if}
    </div>
  </div>
{/snippet}

<Modal title={t("settings.title")} {open} {onclose} width={720}>
  {#if draft}
    <section>
      <h3>{t("settings.appearance")}</h3>
      <div class="group">
        <div class="setting">
          <div class="text"><span>{t("settings.theme")}</span></div>
          <select bind:value={draft.theme} aria-label={t("settings.theme")}>
            <option value="system">{t("settings.themeSystem")}</option>
            <option value="light">{t("settings.themeLight")}</option>
            <option value="dark">{t("settings.themeDark")}</option>
          </select>
        </div>
        <div class="setting">
          <div class="text"><span>{t("settings.language")}</span><span class="faint">{t("settings.languageNote")}</span></div>
          <select bind:value={draft.language} aria-label={t("settings.language")}>
            <option value="auto">{t("settings.languageAuto")}</option>
            {#each LANGUAGES as lang (lang.code)}<option value={lang.code}>{lang.name}</option>{/each}
          </select>
        </div>
      </div>
    </section>

    <section>
      <h3>{t("settings.ai.title")}</h3>
      <div class="group">
        <div class="setting">
          <div class="text"><span>{t("settings.ai.provider")}</span><span class="faint">{t("settings.ai.providerNote")}</span></div>
          <select value={draft.ai.provider} onchange={(e) => pickProvider(e.currentTarget.value)} aria-label={t("settings.ai.provider")}>
            <option value="auto">{t("ai.automatic")}</option>
            {#each GROUPS as group (group.kind)}
              {@const members = providers.filter((p) => p.kind === group.kind)}
              {#if members.length}
                <optgroup label={t(group.label)}>
                  {#each members as p (p.id)}
                    <option value={p.id}>{p.name}{p.available ? "" : ` — ${t("settings.ai.notAvailableShort")}`}</option>
                  {/each}
                </optgroup>
              {/if}
            {/each}
            <option value="off">{t("ai.off")}</option>
          </select>
        </div>

        {#if draft.ai.provider !== "off"}
          <div class="status" class:ok={provider?.available} class:warn={provider && !provider.available}>
            <span class="dot"></span>
            <span>{provider ? (provider.available ? t("settings.ai.available") : t("settings.ai.notAvailable")) : t("settings.ai.checking")}{provider?.note ? ` · ${provider.note}` : ""}</span>
          </div>
          <div class="privacy" class:local>
            <i class="icon">{local ? "" : ""}</i>
            <span>{local ? t("settings.ai.staysLocal")
              : draft.ai.provider === "auto" ? t("settings.ai.sentAuto")
              : t("settings.ai.sentTo", { destination: providerName(provider, draft.ai.provider) })}</span>
          </div>
        {/if}

        {#if provider?.needsEndpoint}
          <div class="setting">
            <div class="text"><span>{t("settings.ai.endpoint")}</span><span class="faint selectable">{ENDPOINT_EXAMPLES[provider.id] ?? provider.defaultEndpoint ?? ""}</span></div>
            <input type="text" spellcheck="false" placeholder={provider.defaultEndpoint ?? ""} bind:value={draft.ai.endpoint}
                   aria-label={t("settings.ai.endpoint")} />
          </div>
          {#if insecure}<p class="warn-text">{t("settings.ai.insecure")}</p>{/if}
        {/if}

        {#if provider && provider.kind !== "auto" && provider.kind !== "off"}
          <div class="setting">
            <div class="text"><span>{t("settings.ai.model")}</span>
              <span class="faint">{defaultModel ? t("settings.ai.modelDefault", { model: defaultModel })
                : provider.kind === "api" ? t("settings.ai.modelRequired") : t("settings.ai.modelNote")}</span></div>
            <div class="control">
              <input type="text" list="vigil-models" spellcheck="false" placeholder={defaultModel || t("settings.ai.modelPlaceholder")}
                     bind:value={draft.ai.model} aria-label={t("settings.ai.model")} />
              <datalist id="vigil-models">{#each suggestions as m (m)}<option value={m}></option>{/each}</datalist>
              {#if provider.needsEndpoint}
                <button onclick={refreshModels} disabled={loadingModels} title={t("settings.ai.refreshModelsTip")}>
                  {loadingModels ? t("settings.ai.refreshing") : t("settings.ai.refreshModels")}</button>
              {/if}
            </div>
          </div>
          {#if modelsNote}<p class="faint note">{modelsNote}</p>{/if}
        {/if}

        {#if provider?.secret}{@render secretField(provider.secret, t("settings.ai.apiKey"), t("settings.ai.apiKeyNote"))}{/if}

        {#if provider?.supportsEffort}
          <div class="setting">
            <div class="text"><span>{t("settings.ai.effort")}</span><span class="faint">{t("settings.ai.effortNote")}</span></div>
            <select bind:value={draft.ai.effort} aria-label={t("settings.ai.effort")}>
              {#each EFFORTS as [value, label] (value)}<option {value}>{t(label)}</option>{/each}
            </select>
          </div>
        {/if}

        {#if draft.ai.provider !== "off"}
          <div class="setting">
            <div class="text"><span>{t("settings.ai.anonymize")}</span><span class="faint">{t("settings.ai.anonymizeNote")}</span></div>
            <input type="checkbox" class="toggle" role="switch" bind:checked={draft.ai.redact} aria-label={t("settings.ai.anonymize")} />
          </div>
        {/if}
      </div>
    </section>

    <section>
      <h3>{t("settings.scan")}</h3>
      <div class="group">
        <div class="setting">
          <div class="text"><span>{t("settings.eventLogs")}</span><span class="faint">{t("settings.eventLogsNote")}</span></div>
          <select bind:value={draft.days} aria-label={t("settings.eventLogs")}>
            {#each DAYS as d (d)}<option value={d}>{t("common.days", { count: d })}</option>{/each}
          </select>
        </div>
        <div class="setting">
          <div class="text"><span>{t("settings.virustotal")}</span><span class="faint">{t("settings.virustotalNote")}</span></div>
          <input type="checkbox" class="toggle" role="switch" bind:checked={draft.virustotal} aria-label={t("settings.virustotal")} />
        </div>
        {@render secretField("virustotal", t("settings.virustotalKey"))}
      </div>
    </section>

    <section>
      <h3>{t("settings.safety")}</h3>
      <div class="group">
        <div class="setting">
          <div class="text"><span>{t("settings.restorePoint")}</span><span class="faint">{t("settings.restorePointNote")}</span></div>
          <input type="checkbox" class="toggle" role="switch" bind:checked={draft.restorePoint} aria-label={t("settings.restorePoint")} />
        </div>
      </div>
    </section>

    {#if watchDraft}
      <section>
        <h3>{t("settings.watch.title")}</h3>
        <div class="group">
          <div class="setting">
            <div class="text"><span>{t("settings.watch.watching")}</span><span class="faint">{t("settings.watch.watchingNote")}</span></div>
            <input type="checkbox" class="toggle" role="switch" bind:checked={watchDraft.watching} aria-label={t("settings.watch.watching")} />
          </div>
          <div class="setting">
            <div class="text"><span>{t("settings.watch.close")}</span><span class="faint">{t("settings.watch.closeNote")}</span></div>
            <select value={watchDraft.closeToTray ? "tray" : "quit"} aria-label={t("settings.watch.close")}
                    onchange={(e) => watchDraft && (watchDraft.closeToTray = e.currentTarget.value === "tray")}>
              <option value="tray">{t("settings.watch.closeTray")}</option>
              <option value="quit">{t("settings.watch.closeQuit")}</option>
            </select>
          </div>
          <div class="setting">
            <div class="text"><span>{t("settings.watch.autostart")}</span><span class="faint">{t("settings.watch.autostartNote")}</span></div>
            <input type="checkbox" class="toggle" role="switch" checked={autostart} disabled={autostartBusy}
                   aria-label={t("settings.watch.autostart")} onchange={(e) => void changeAutostart(e.currentTarget)} />
          </div>
          {#if autostartError}<p class="warn-text">{autostartError}</p>{/if}
          <div class="setting notify">
            <div class="text"><span>{t("settings.watch.notify")}</span><span class="faint">{t("settings.watch.notifyNote")}</span></div>
            <div class="checks">
              <label><input type="checkbox" bind:checked={watchDraft.notifyStartup} />{t("settings.watch.notifyStartup")}</label>
              <label><input type="checkbox" bind:checked={watchDraft.notifyServices} />{t("settings.watch.notifyServices")}</label>
              <label><input type="checkbox" bind:checked={watchDraft.notifyTasks} />{t("settings.watch.notifyTasks")}</label>
              <label><input type="checkbox" bind:checked={watchDraft.notifySecurity} />{t("settings.watch.notifySecurity")}</label>
              <label><input type="checkbox" bind:checked={watchDraft.notifyPorts} />{t("settings.watch.notifyPorts")}</label>
            </div>
          </div>
        </div>
      </section>
    {/if}

    <section>
      <h3>{t("settings.processes")}</h3>
      <div class="group">
        <div class="setting">
          <div class="text"><span>{t("settings.autoRefresh")}</span><span class="faint">{t("settings.autoRefreshNote")}</span></div>
          <input type="checkbox" class="toggle" role="switch" bind:checked={draft.autoRefresh} aria-label={t("settings.autoRefresh")} />
        </div>
      </div>
    </section>

    {#if dataDir}<p class="faint selectable">{t("settings.dataDir", { path: dataDir })}</p>{/if}
    {#if error}<p class="error">{error}</p>{/if}
  {/if}
  {#snippet footer()}
    <button onclick={onclose}>{t("common.cancel")}</button>
    <button class="primary" onclick={save} disabled={saving}>{t("common.save")}</button>
  {/snippet}
</Modal>

<style>
  section { display: flex; flex-direction: column; gap: 6px; }
  section h3 { font-size: 14px; }
  .group { display: flex; flex-direction: column; gap: 2px; }
  /* SettingsCard: label and description on the left, the control on the right. */
  .setting {
    display: flex; align-items: center; gap: 16px; min-height: 56px; padding: 8px 14px; background: var(--layer);
    border: 1px solid var(--rule); border-radius: var(--radius);
  }
  .text { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .text .faint { font-size: 12px; line-height: 16px; }
  .control { display: flex; align-items: center; gap: 6px; flex: none; }
  .setting select { min-width: 220px; max-width: 300px; }
  .setting input[type="text"], .setting input[type="password"] { min-width: 220px; width: 240px; }
  .saved { display: inline-flex; align-items: center; gap: 6px; color: var(--ok); font-weight: 600; margin-right: 4px; }
  .status, .privacy { display: flex; align-items: center; gap: 8px; padding: 6px 14px; font-size: 13px; color: var(--ink2); }
  .status .dot { width: 8px; height: 8px; border-radius: 4px; background: var(--ink3); flex: none; }
  .status.ok .dot { background: var(--ok); }
  .status.warn .dot { background: var(--warn); }
  .privacy .icon { font-size: 14px; }
  .privacy.local { color: var(--ok); font-weight: 600; }
  .note { margin: 0; padding: 0 14px; }
  .warn-text { margin: 0; padding: 0 14px; color: var(--warn); font-size: 12px; }
  .error { color: var(--bad); margin: 0; }
  .notify { align-items: flex-start; }
  .checks { display: flex; flex-direction: column; gap: 6px; flex: none; min-width: 220px; }
  .checks label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  p.faint { margin: 4px 0 0; font-size: 12px; }
</style>
