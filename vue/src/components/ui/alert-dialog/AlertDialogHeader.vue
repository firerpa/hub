<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("flex flex-col gap-2 text-center sm:text-left", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <div data-slot="alert-dialog-header" :class="classes" v-bind="restAttrs"><slot /></div>
</template>
