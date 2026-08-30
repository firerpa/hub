<script setup lang="ts">
import { DialogTrigger } from "reka-ui";

defineProps<{ asChild?: boolean }>();
</script>

<template>
  <DialogTrigger data-slot="dialog-trigger" :as-child="asChild">
    <slot />
  </DialogTrigger>
</template>
