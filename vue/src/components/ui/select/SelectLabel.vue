<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { SelectLabel } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("text-muted-foreground px-2 py-1.5 text-xs", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <SelectLabel data-slot="select-label" :class="classes" v-bind="restAttrs"><slot /></SelectLabel>
</template>
