<script setup lang="ts">
import { computed, useAttrs } from "vue";
import {
  SelectContent,
  SelectPortal,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectViewport,
} from "reka-ui";
import { ChevronDown as ChevronDownIcon, ChevronUp as ChevronUpIcon } from "lucide-vue-next";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = withDefaults(defineProps<{ position?: "popper" | "item-aligned" }>(), {
  position: "popper",
});

const attrs = useAttrs();
const contentClasses = computed(() =>
  cn(
    "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 relative z-50 max-h-(--reka-select-content-available-height) min-w-[8rem] origin-(--reka-select-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border shadow-md",
    props.position === "popper" &&
      "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
    attrs.class as string,
  ),
);
const viewportClasses = computed(() =>
  cn(
    "p-1",
    props.position === "popper" && "w-full min-w-[var(--reka-select-trigger-width)] scroll-my-1",
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <SelectPortal>
    <SelectContent
      data-slot="select-content"
      :class="contentClasses"
      :position="props.position"
      v-bind="restAttrs"
    >
      <SelectScrollUpButton
        data-slot="select-scroll-up-button"
        class="flex cursor-default items-center justify-center py-1"
      >
        <ChevronUpIcon class="size-4" />
      </SelectScrollUpButton>
      <SelectViewport :class="viewportClasses">
        <slot />
      </SelectViewport>
      <SelectScrollDownButton
        data-slot="select-scroll-down-button"
        class="flex cursor-default items-center justify-center py-1"
      >
        <ChevronDownIcon class="size-4" />
      </SelectScrollDownButton>
    </SelectContent>
  </SelectPortal>
</template>
