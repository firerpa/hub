<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DropdownMenuSeparator } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() => cn("bg-border -mx-1 my-1 h-px", attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <DropdownMenuSeparator data-slot="dropdown-menu-separator" :class="classes" v-bind="restAttrs" />
</template>
