<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { TabsList } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "bg-muted text-muted-foreground inline-flex h-9 w-fit items-center justify-center rounded-lg p-[3px]",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <TabsList data-slot="tabs-list" :class="classes" v-bind="restAttrs"><slot /></TabsList>
</template>
