<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DialogClose, DialogContent, DialogOverlay, DialogPortal } from "reka-ui";
import { X as XIcon } from "lucide-vue-next";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

withDefaults(defineProps<{ showCloseButton?: boolean }>(), { showCloseButton: true });

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
  <DialogPortal data-slot="dialog-portal">
    <DialogOverlay
      data-slot="dialog-overlay"
      class="data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 fixed inset-0 z-50 bg-black/50"
    />
    <DialogContent data-slot="dialog-content" :class="classes" v-bind="restAttrs">
      <slot />
      <DialogClose
        v-if="showCloseButton"
        data-slot="dialog-close"
        class="ring-offset-background focus:ring-ring data-[state=open]:bg-accent data-[state=open]:text-muted-foreground absolute top-4 right-4 rounded-xs opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-hidden disabled:pointer-events-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4"
      >
        <XIcon />
        <span class="sr-only">Close</span>
      </DialogClose>
    </DialogContent>
  </DialogPortal>
</template>
