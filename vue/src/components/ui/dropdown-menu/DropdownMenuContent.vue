<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DropdownMenuContent, DropdownMenuPortal } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

withDefaults(
  defineProps<{
    sideOffset?: number;
    align?: "start" | "center" | "end";
    side?: "top" | "right" | "bottom" | "left";
  }>(),
  { sideOffset: 4 },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-(--reka-dropdown-menu-content-available-height) min-w-[8rem] origin-(--reka-dropdown-menu-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border p-1 shadow-md",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <DropdownMenuPortal>
    <DropdownMenuContent
      data-slot="dropdown-menu-content"
      :side-offset="sideOffset"
      :align="align"
      :side="side"
      :class="classes"
      v-bind="restAttrs"
    >
      <slot />
    </DropdownMenuContent>
  </DropdownMenuPortal>
</template>
