<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { TooltipArrow, TooltipContent, TooltipPortal } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

withDefaults(
  defineProps<{
    sideOffset?: number;
    side?: "top" | "right" | "bottom" | "left";
    align?: "start" | "center" | "end";
  }>(),
  { sideOffset: 0 },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-foreground text-background animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 w-fit origin-(--reka-tooltip-content-transform-origin) rounded-md px-3 py-1.5 text-xs text-balance",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <TooltipPortal>
    <TooltipContent
      data-slot="tooltip-content"
      :side-offset="sideOffset"
      :side="side"
      :align="align"
      :class="classes"
      v-bind="restAttrs"
    >
      <slot />
      <TooltipArrow class="bg-foreground fill-foreground z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px]" />
    </TooltipContent>
  </TooltipPortal>
</template>
