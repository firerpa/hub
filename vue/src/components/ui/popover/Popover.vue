<script setup lang="ts">
import { PopoverRoot } from "reka-ui";

const props = withDefaults(
  defineProps<{
    open?: boolean;
    defaultOpen?: boolean;
    modal?: boolean;
  }>(),
  { open: undefined, defaultOpen: undefined, modal: undefined },
);

const emit = defineEmits<{
  "update:open": [value: boolean];
}>();
</script>

<template>
  <PopoverRoot
    data-slot="popover"
    :open="props.open"
    :default-open="props.defaultOpen"
    :modal="props.modal"
    @update:open="emit('update:open', $event)"
  >
    <slot />
  </PopoverRoot>
</template>
