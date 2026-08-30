<script setup lang="ts">
import { DialogRoot } from "reka-ui";

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
  <DialogRoot
    data-slot="dialog"
    :open="props.open"
    :default-open="props.defaultOpen"
    :modal="props.modal"
    @update:open="emit('update:open', $event)"
  >
    <slot />
  </DialogRoot>
</template>
