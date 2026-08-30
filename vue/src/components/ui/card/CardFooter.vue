<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("flex items-center px-6 [.border-t]:pt-6", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <div data-slot="card-footer" :class="classes" v-bind="restAttrs"><slot /></div>
</template>
