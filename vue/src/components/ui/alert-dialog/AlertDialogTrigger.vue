<script setup lang="ts">
import { AlertDialogTrigger } from "reka-ui";

defineProps<{ asChild?: boolean }>();
</script>

<template>
  <AlertDialogTrigger data-slot="alert-dialog-trigger" :as-child="asChild">
    <slot />
  </AlertDialogTrigger>
</template>
