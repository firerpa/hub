<script setup lang="ts">
import { PopoverTrigger } from "reka-ui";

defineProps<{ asChild?: boolean }>();
</script>

<template>
  <PopoverTrigger data-slot="popover-trigger" :as-child="asChild">
    <slot />
  </PopoverTrigger>
</template>
