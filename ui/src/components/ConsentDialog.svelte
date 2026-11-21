<script lang="ts">
  import { t } from "../lib/i18n/index.svelte";
  import type { ReviewOffer } from "../lib/types";
  import Modal from "./Modal.svelte";

  // Shows exactly what would leave the computer before the AI review starts (or that nothing leaves it,
  // when the model runs on this computer).
  let { offer, onanswer }: { offer: ReviewOffer | null; onanswer: (send: boolean) => void } = $props();
  let showData = $state(false);
</script>

<Modal title={offer?.local ? t("consent.titleLocal") : t("consent.title")} open={offer !== null} onclose={() => onanswer(false)} width={720}>
  {#if offer}
    <div class="where" class:local={offer.local}>
      <i class="icon">{offer.local ? "" : ""}</i>
      <div>
        <div class="dest">{offer.destination}</div>
        <div class="faint">{offer.local ? t("consent.staysLocal") : t("consent.leaves")}</div>
      </div>
    </div>
    <p>{t("consent.items", { count: offer.pending })}</p>
    <p class="muted">{offer.redact ? t("consent.redacted") : t("consent.notRedacted")} {t("consent.copySaved")}</p>
    <button class="link" onclick={() => (showData = !showData)}>
      {showData ? t("consent.hideData", { count: offer.preview.length }) : t("consent.showData", { count: offer.preview.length })}
    </button>
    {#if showData}<pre class="mono data">{JSON.stringify(offer.preview, null, 1)}</pre>{/if}
  {/if}
  {#snippet footer()}
    <button onclick={() => onanswer(false)}>{t("consent.skip")}</button>
    <button class="primary" onclick={() => onanswer(true)}>{offer?.local ? t("consent.review") : t("consent.send")}</button>
  {/snippet}
</Modal>

<style>
  p { margin: 0; }
  .where { display: flex; align-items: center; gap: 12px; padding: 10px 14px; border: 1px solid var(--rule); border-radius: var(--radius);
           background: var(--layer); }
  .where .icon { font-size: 20px; color: var(--ink2); }
  .where.local { border-color: color-mix(in srgb, var(--ok) 45%, var(--rule)); background: color-mix(in srgb, var(--ok) 8%, var(--surface)); }
  .where.local .icon { color: var(--ok); }
  .dest { font-weight: 600; overflow-wrap: anywhere; }
  .link { border: 0; background: transparent; padding: 0; color: var(--accent); text-align: left; min-height: 0; }
  .data { max-height: 340px; overflow: auto; margin: 0; padding: 10px; background: var(--sunken); border: 1px solid var(--rule); border-radius: 6px;
          white-space: pre-wrap; word-break: break-all; user-select: text; }
</style>
