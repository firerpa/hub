<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cn } from "@/lib/utils";
import { Label } from "@/components/ui/label";

defineOptions({ inheritAttrs: false });
const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "group/field-label peer/field-label flex w-fit gap-2 leading-snug group-data-[disabled=true]/field:opacity-50",
    "has-[>[data-slot=field]]:w-full has-[>[data-slot=field]]:flex-col has-[>[data-slot=field]]:rounded-md has-[>[data-slot=field]]:border [&>*]:data-[slot=field]:p-4",
    "has-data-[state=checked]:bg-primary/5 has-data-[state=checked]:border-primary dark:has-data-[state=checked]:bg-primary/10",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <Label data-slot="field-label" :class="classes" v-bind="restAttrs"><slot /></Label>
</template>
