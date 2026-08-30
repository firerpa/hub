<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DialogTitle } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("text-foreground font-semibold", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <DialogTitle data-slot="sheet-title" :class="classes" v-bind="restAttrs"><slot /></DialogTitle>
</template>
