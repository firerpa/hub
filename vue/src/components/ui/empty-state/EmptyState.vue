<script setup lang="ts">
import { Empty } from "ant-design-vue";
import { cn } from "@/lib/utils";

defineProps<{
  title: string;
  description?: string;
  class?: string;
}>();

const emptyImage = Empty.PRESENTED_IMAGE_SIMPLE;
</script>

<template>
  <div :class="cn('empty-state flex flex-col items-center justify-center text-center', $props.class)">
    <Empty :image="emptyImage" :image-style="{ height: '56px' }">
      <template #description>
        <h3 class="text-base font-semibold text-foreground">{{ title }}</h3>
        <p v-if="description" class="mt-1 max-w-sm text-xs text-muted-foreground">{{ description }}</p>
      </template>
      <slot />
    </Empty>
  </div>
</template>

<style scoped>
.empty-state :deep(.ant-empty-image) {
  margin-bottom: 12px;
}

.empty-state :deep(.ant-empty-description) {
  margin: 0;
}
</style>
