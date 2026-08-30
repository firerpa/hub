<script setup lang="ts">
import { PopoverAnchor } from "reka-ui";

defineProps<{ asChild?: boolean }>();
</script>

<template>
  <PopoverAnchor data-slot="popover-anchor" :as-child="asChild">
    <slot />
  </PopoverAnchor>
</template>
