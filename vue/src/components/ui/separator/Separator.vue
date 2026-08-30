<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { Separator as SeparatorPrimitive } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    orientation?: "horizontal" | "vertical";
    decorative?: boolean;
  }>(),
  { orientation: "horizontal", decorative: true },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-border shrink-0 data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-px",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <SeparatorPrimitive
    data-slot="separator"
    :decorative="props.decorative"
    :orientation="props.orientation"
    :class="classes"
    v-bind="restAttrs"
  />
</template>
