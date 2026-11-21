<script lang="ts">
  import { verdictColor, verdictLabel } from "../lib/labels";

  let { items, onopen }: { items: { id: string; verdict: string; title: string }[]; onopen: (id: string) => void } = $props();
</script>

<!-- One sliver per finding, ordered by severity: hover names it, click opens it. -->
<div class="strip" role="list">
  {#each items as item (item.id)}
    <button
      class="sliver"
      style:background={verdictColor(item.verdict)}
      title="{verdictLabel(item.verdict)} · {item.title}"
      aria-label="{verdictLabel(item.verdict)}: {item.title}"
      onclick={() => onopen(item.id)}
    ></button>
  {/each}
</div>

<style>
  .strip { display: flex; height: 46px; background: var(--sunken); border-radius: 3px; overflow: hidden; gap: 1px; }
  .sliver { flex: 1 1 0; min-width: 1px; border: 0; border-radius: 0; padding: 0; cursor: pointer; }
  .sliver:hover { filter: brightness(1.2); }
</style>
