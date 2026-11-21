<script lang="ts">
  let { fraction }: { fraction: number } = $props();
  const value = $derived(Math.max(0, Math.min(1, fraction || 0)));
  const color = $derived(value >= 0.95 ? "var(--bad)" : value >= 0.85 ? "var(--warn)" : "var(--chart)");
</script>

<div class="track" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(value * 100)}>
  <div class="fill" style:width="{Math.max(2, value * 100)}%" style:background={color}></div>
</div>

<style>
  .track { height: 10px; background: var(--sunken); border-radius: 5px; overflow: hidden; }
  .fill { height: 100%; border-radius: 5px; transition: width 0.4s ease; }
</style>
