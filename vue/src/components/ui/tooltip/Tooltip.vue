<script setup lang="ts">
import { TooltipProvider, TooltipRoot } from "reka-ui";

const props = withDefaults(
  defineProps<{
    open?: boolean;
    defaultOpen?: boolean;
    delayDuration?: number;
  }>(),
  { open: undefined, defaultOpen: undefined },
);

const emit = defineEmits<{
  "update:open": [value: boolean];
}>();
</script>

<template>
  <TooltipProvider :delay-duration="props.delayDuration ?? 0">
    <TooltipRoot
      data-slot="tooltip"
      :open="props.open"
      :default-open="props.defaultOpen"
      @update:open="emit('update:open', $event)"
    >
      <slot />
    </TooltipRoot>
  </TooltipProvider>
</template>
