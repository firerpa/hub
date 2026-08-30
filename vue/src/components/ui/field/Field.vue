<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const fieldVariants = cva("group/field flex w-full gap-3 data-[invalid=true]:text-destructive", {
  variants: {
    orientation: {
      vertical: ["flex-col [&>*]:w-full [&>.sr-only]:w-auto"],
      horizontal: [
        "flex-row items-center",
        "[&>[data-slot=field-label]]:flex-auto",
        "has-[>[data-slot=field-content]]:items-start has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
      responsive: [
        "flex-col [&>*]:w-full [&>.sr-only]:w-auto @md/field-group:flex-row @md/field-group:items-center @md/field-group:[&>*]:w-auto",
        "@md/field-group:[&>[data-slot=field-label]]:flex-auto",
        "@md/field-group:has-[>[data-slot=field-content]]:items-start @md/field-group:has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
    },
  },
  defaultVariants: {
    orientation: "vertical",
  },
});

type FieldVariants = VariantProps<typeof fieldVariants>;

defineOptions({ inheritAttrs: false });

const props = withDefaults(defineProps<{ orientation?: FieldVariants["orientation"] }>(), {
  orientation: "vertical",
});

const attrs = useAttrs();
const classes = computed(() => cn(fieldVariants({ orientation: props.orientation }), attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <div role="group" data-slot="field" :data-orientation="props.orientation" :class="classes" v-bind="restAttrs">
    <slot />
  </div>
</template>
