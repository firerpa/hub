<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DropdownMenuLabel } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

defineProps<{ inset?: boolean }>();

const attrs = useAttrs();
const classes = computed(() =>
  cn("px-2 py-1.5 text-sm font-medium data-[inset]:pl-8", attrs.class as string),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <DropdownMenuLabel
    data-slot="dropdown-menu-label"
    :data-inset="inset || undefined"
    :class="classes"
    v-bind="restAttrs"
  >
    <slot />
  </DropdownMenuLabel>
</template>
