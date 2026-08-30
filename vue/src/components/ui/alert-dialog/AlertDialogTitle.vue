<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { AlertDialogTitle } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("text-sm font-semibold", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <AlertDialogTitle data-slot="alert-dialog-title" :class="classes" v-bind="restAttrs"><slot /></AlertDialogTitle>
</template>
