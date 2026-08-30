<script setup lang="ts">
import { computed, useAttrs } from "vue";
import {
  ScrollAreaCorner,
  ScrollAreaRoot,
  ScrollAreaViewport,
} from "reka-ui";
import { cn } from "@/lib/utils";
import ScrollBar from "./ScrollBar.vue";

defineOptions({ inheritAttrs: false });

const attrs = useAttrs();
const classes = computed(() => cn("relative", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <ScrollAreaRoot data-slot="scroll-area" :class="classes" v-bind="restAttrs">
    <ScrollAreaViewport
      data-slot="scroll-area-viewport"
      class="focus-visible:ring-ring/50 size-full rounded-[inherit] transition-[color,box-shadow] outline-none focus-visible:ring-[3px] focus-visible:outline-1"
    >
      <slot />
    </ScrollAreaViewport>
    <ScrollBar />
    <ScrollAreaCorner />
  </ScrollAreaRoot>
</template>
