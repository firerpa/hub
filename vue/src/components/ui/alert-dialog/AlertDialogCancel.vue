<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { AlertDialogCancel } from "reka-ui";
import { cn } from "@/lib/utils";
import { buttonVariants } from "@/components/ui/button";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn(buttonVariants({ variant: "outline" }), attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <AlertDialogCancel :class="classes" v-bind="restAttrs"><slot /></AlertDialogCancel>
</template>
