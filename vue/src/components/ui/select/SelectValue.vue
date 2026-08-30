<script setup lang="ts">
import { SelectValue } from "reka-ui";

defineProps<{ placeholder?: string }>();
</script>

<template>
  <SelectValue data-slot="select-value" :placeholder="placeholder">
    <slot />
  </SelectValue>
</template>
