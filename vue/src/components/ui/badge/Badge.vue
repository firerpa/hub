<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { Primitive } from "reka-ui";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap shrink-0 [&>svg]:size-3 gap-1 [&>svg]:pointer-events-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive transition-[color,box-shadow] overflow-hidden",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground [a&]:hover:bg-primary/90",
        secondary: "border-transparent bg-secondary text-secondary-foreground [a&]:hover:bg-secondary/90",
        destructive:
          "border-transparent bg-destructive text-white [a&]:hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60",
        outline: "text-foreground [a&]:hover:bg-accent [a&]:hover:text-accent-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

type BadgeVariants = VariantProps<typeof badgeVariants>;

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    variant?: BadgeVariants["variant"];
    asChild?: boolean;
    as?: string;
  }>(),
  { variant: "default", asChild: false, as: "span" },
);

const attrs = useAttrs();
const classes = computed(() => cn(badgeVariants({ variant: props.variant }), attrs.class as string));
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <Primitive :as="as" :as-child="asChild" data-slot="badge" :class="classes" v-bind="restAttrs">
    <slot />
  </Primitive>
</template>
