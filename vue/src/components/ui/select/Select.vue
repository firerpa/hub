<script setup lang="ts">
import { SelectRoot } from "reka-ui";

const props = withDefaults(
  defineProps<{
    modelValue?: string;
    defaultValue?: string;
    open?: boolean;
    disabled?: boolean;
    name?: string;
  }>(),
  { open: undefined, disabled: undefined },
);

const emit = defineEmits<{
  "update:modelValue": [value: string];
  "update:open": [value: boolean];
}>();
</script>

<template>
  <SelectRoot
    data-slot="select"
    :model-value="props.modelValue"
    :default-value="props.defaultValue"
    :open="props.open"
    :disabled="props.disabled"
    :name="props.name"
    @update:model-value="emit('update:modelValue', $event as string)"
    @update:open="emit('update:open', $event)"
  >
    <slot />
  </SelectRoot>
</template>
