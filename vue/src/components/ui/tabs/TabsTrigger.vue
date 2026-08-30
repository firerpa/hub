<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { TabsTrigger } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

defineProps<{
  value: string;
  disabled?: boolean;
}>();

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "data-[state=active]:bg-background dark:data-[state=active]:text-foreground focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:outline-ring dark:data-[state=active]:border-input dark:data-[state=active]:bg-input/30 text-foreground dark:text-muted-foreground inline-flex h-[calc(100%-1px)] flex-1 items-center justify-center gap-1.5 rounded-md border border-transparent px-2 py-1 text-sm font-medium whitespace-nowrap transition-[color,box-shadow] focus-visible:ring-[3px] focus-visible:outline-1 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:shadow-sm [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <TabsTrigger data-slot="tabs-trigger" :value="value" :disabled="disabled" :class="classes" v-bind="restAttrs">
    <slot />
  </TabsTrigger>
</template>
