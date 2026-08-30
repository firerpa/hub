<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { TabsRoot } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = defineProps<{
  modelValue?: string;
  defaultValue?: string;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const attrs = useAttrs();
const classes = computed(() => cn("flex flex-col gap-2", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <TabsRoot
    data-slot="tabs"
    :class="classes"
    :model-value="props.modelValue"
    :default-value="props.defaultValue"
    v-bind="restAttrs"
    @update:model-value="emit('update:modelValue', $event as string)"
  >
    <slot />
  </TabsRoot>
</template>
