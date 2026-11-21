<script lang="ts">
  let { text, color = "var(--ink3)", solid = false }: { text: string; color?: string; solid?: boolean } = $props();
</script>

<span
  class="pill"
  style:background={solid ? color : `color-mix(in srgb, ${color} 12%, var(--surface))`}
  style:color={solid ? "var(--on-chart)" : color}
  style:border-color={solid ? color : `color-mix(in srgb, ${color} 35%, var(--surface))`}
>{text}</span>

<style>
  .pill { display: inline-block; border: 1px solid; border-radius: 10px; padding: 0 9px; font-size: 12px; font-weight: 600; line-height: 19px; white-space: nowrap; }
</style>
