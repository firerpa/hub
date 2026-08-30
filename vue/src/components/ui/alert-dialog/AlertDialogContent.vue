<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { AlertDialogContent, AlertDialogOverlay, AlertDialogPortal } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-background data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 fixed top-[50%] left-[50%] z-50 grid w-full max-w-[calc(100%-2rem)] translate-x-[-50%] translate-y-[-50%] gap-4 rounded-md border p-4 shadow-lg duration-200 sm:max-w-lg",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <AlertDialogPortal>
    <AlertDialogOverlay
      data-slot="alert-dialog-overlay"
      class="data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 fixed inset-0 z-50 bg-black/50"
    />
    <AlertDialogContent data-slot="alert-dialog-content" :class="classes" v-bind="restAttrs">
      <slot />
    </AlertDialogContent>
  </AlertDialogPortal>
</template>
