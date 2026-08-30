<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { PopoverContent, PopoverPortal } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

withDefaults(
  defineProps<{
    align?: "start" | "center" | "end";
    side?: "top" | "right" | "bottom" | "left";
    sideOffset?: number;
  }>(),
  { align: "center", sideOffset: 4 },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 w-72 origin-(--reka-popover-content-transform-origin) rounded-md border p-4 shadow-md outline-hidden",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <PopoverPortal>
    <PopoverContent
      data-slot="popover-content"
      :align="align"
      :side="side"
      :side-offset="sideOffset"
      :class="classes"
      v-bind="restAttrs"
    >
      <slot />
    </PopoverContent>
  </PopoverPortal>
</template>
