<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { Label as LabelPrimitive } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = defineProps<{
  for?: string;
}>();

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "flex items-center gap-2 text-sm leading-none font-medium select-none group-data-[disabled=true]:pointer-events-none group-data-[disabled=true]:opacity-50 peer-disabled:cursor-not-allowed peer-disabled:opacity-50",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <LabelPrimitive :for="props.for" data-slot="label" :class="classes" v-bind="restAttrs">
    <slot />
  </LabelPrimitive>
</template>
