<script setup lang="ts">
import { DropdownMenuTrigger } from "reka-ui";

defineProps<{ asChild?: boolean }>();
</script>

<template>
  <DropdownMenuTrigger data-slot="dropdown-menu-trigger" :as-child="asChild">
    <slot />
  </DropdownMenuTrigger>
</template>
