<script lang="ts">
  import * as api from "../lib/api";
  import { providerName } from "../lib/ai";
  import { t } from "../lib/i18n/index.svelte";
  import type { AiProvider, AiStatus, Settings } from "../lib/types";
  import Modal from "./Modal.svelte";

  let { open, settings, onclose, onstart }: {
    open: boolean;
    settings: Settings | null;
    onclose: () => void;
    onstart: (days: number, virustotal: boolean, useAi: boolean) => void;
  } = $props();

  let useAi = $state(true);
  let virustotal = $state(false);
  let days = $state(30);
  let status = $state<AiStatus | null>(null);
  let providers = $state<AiProvider[]>([]);

  $effect(() => {
    if (open && settings) {
      days = settings.days;
      virustotal = settings.virustotal;
      useAi = settings.ai.provider !== "off";
      status = null;
      void Promise.all([api.aiStatus(), api.aiProviders()]).then(([s, list]) => {
        status = s;
        providers = list;
      });
    }
  });

  const provider = $derived(providers.find((p) => p.id === status?.provider));
  const reviewer = $derived(
    !status ? t("scan.checkingAi")
      : status.destination ? (status.local ? t("scan.usesLocal", { destination: status.destination }) : t("scan.uses", { destination: status.destination }))
      : t("scan.aiNotAvailable", { problem: status.problem ?? "" }),
  );
  const DAYS = [7, 14, 30, 60, 90];
</script>

<Modal title={t("scan.title")} {open} {onclose} width={560}>
  <p class="muted">{t("scan.intro")}</p>
  <label class="check"><input type="checkbox" bind:checked={useAi} disabled={settings?.ai.provider === "off"} />
    {t("scan.useAi", { provider: providerName(provider, status?.provider ?? settings?.ai.provider ?? "") })}</label>
  <p class="faint indent">{settings?.ai.provider === "off" ? t("scan.aiOffHint") : reviewer}</p>
  <label class="row">{t("scan.eventLogs")}
    <select bind:value={days}>{#each DAYS as d (d)}<option value={d}>{t("common.days", { count: d })}</option>{/each}</select>
  </label>
  <label class="check"><input type="checkbox" bind:checked={virustotal} /> {t("scan.virustotal")}</label>
  {#if virustotal && !settings?.secrets.virustotal}<p class="faint indent">{t("scan.virustotalNoKey")}</p>{/if}
  <p class="faint">{status?.local ? t("scan.localNote") : t("scan.consentNote")}</p>
  {#snippet footer()}
    <button onclick={onclose}>{t("common.cancel")}</button>
    <button class="primary" onclick={() => onstart(days, virustotal, useAi)}>{t("scan.start")}</button>
  {/snippet}
</Modal>

<style>
  p { margin: 0; }
  .indent { padding-left: 28px; }
  .row { display: flex; align-items: center; gap: 10px; color: var(--ink2); }
</style>
