<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { AlertDialogDescription } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("text-muted-foreground text-sm", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <AlertDialogDescription data-slot="alert-dialog-description" :class="classes" v-bind="restAttrs"><slot /></AlertDialogDescription>
</template>
