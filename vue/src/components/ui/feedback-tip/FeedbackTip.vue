<script setup lang="ts">
import { onMounted, watch } from "vue";
import { showFeedbackTip, type FeedbackTipVariant } from "./toast";

const props = withDefaults(
  defineProps<{
    message: string;
    variant?: FeedbackTipVariant;
    toastId?: string | number;
    className?: string;
    compact?: boolean;
    truncate?: boolean;
  }>(),
  { variant: "info" },
);

onMounted(() => {
  showFeedbackTip(props.message, props.variant);
});

watch(
  () => [props.message, props.toastId, props.variant],
  () => {
    showFeedbackTip(props.message, props.variant);
  },
);
</script>

<template>
  <span style="display: none" aria-hidden="true" />
</template>
