<script setup lang="ts">
import { AlertDialogRoot } from "reka-ui";

const props = withDefaults(
  defineProps<{
    open?: boolean;
    defaultOpen?: boolean;
  }>(),
  { open: undefined, defaultOpen: undefined },
);

const emit = defineEmits<{
  "update:open": [value: boolean];
}>();
</script>

<template>
  <AlertDialogRoot
    data-slot="alert-dialog"
    :open="props.open"
    :default-open="props.defaultOpen"
    @update:open="emit('update:open', $event)"
  >
    <slot />
  </AlertDialogRoot>
</template>
