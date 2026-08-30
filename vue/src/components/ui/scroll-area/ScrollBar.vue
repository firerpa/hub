<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { ScrollAreaScrollbar, ScrollAreaThumb } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

withDefaults(defineProps<{ orientation?: "vertical" | "horizontal" }>(), {
  orientation: "vertical",
});

const attrs = useAttrs();
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <ScrollAreaScrollbar
    data-slot="scroll-area-scrollbar"
    :orientation="orientation"
    :class="
      cn(
        'flex touch-none p-px transition-colors select-none',
        orientation === 'vertical' && 'h-full w-2.5 border-l border-l-transparent',
        orientation === 'horizontal' && 'h-2.5 flex-col border-t border-t-transparent',
        attrs.class as string,
      )
    "
    v-bind="restAttrs"
  >
    <ScrollAreaThumb data-slot="scroll-area-thumb" class="bg-border relative flex-1 rounded-full" />
  </ScrollAreaScrollbar>
</template>
