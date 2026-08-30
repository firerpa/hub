<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() =>
  cn("col-start-2 row-span-2 row-start-1 self-start justify-self-end", attrs.class as string),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <div data-slot="card-action" :class="classes" v-bind="restAttrs"><slot /></div>
</template>
