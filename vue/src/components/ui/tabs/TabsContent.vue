<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { TabsContent } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

defineProps<{ value: string }>();

const attrs = useAttrs();
const classes = computed(() => cn("flex-1 outline-none", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <TabsContent data-slot="tabs-content" :value="value" :class="classes" v-bind="restAttrs">
    <slot />
  </TabsContent>
</template>
