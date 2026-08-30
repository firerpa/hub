<script setup lang="ts">
import { ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-vue-next";
import { cn } from "@/lib/utils";

const props = defineProps<{
  active?: boolean;
  order?: "asc" | "desc";
  class?: string;
}>();
</script>

<template>
  <ChevronsUpDown
    v-if="!active"
    :class="cn('h-3.5 w-3.5 shrink-0 text-muted-foreground/50', props.class)"
  />
  <ChevronUp
    v-else-if="order === 'asc'"
    :class="cn('h-3.5 w-3.5 shrink-0 text-foreground', props.class)"
  />
  <ChevronDown
    v-else
    :class="cn('h-3.5 w-3.5 shrink-0 text-foreground', props.class)"
  />
</template>
