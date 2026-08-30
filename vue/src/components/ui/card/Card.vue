<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() =>
  cn("bg-card text-card-foreground flex flex-col gap-0 rounded-md border py-5", attrs.class as string),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <div data-slot="card" :class="classes" v-bind="restAttrs"><slot /></div>
</template>
