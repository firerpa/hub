<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { Primitive } from "reka-ui";
import { cn } from "@/lib/utils";
import { buttonVariants, type ButtonVariants } from "./variants";

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariants["variant"];
    size?: ButtonVariants["size"];
    asChild?: boolean;
    as?: string;
    type?: string;
  }>(),
  { variant: "default", size: "default", asChild: false, as: "button", type: "button" },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(buttonVariants({ variant: props.variant, size: props.size }), attrs.class as string),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <Primitive
    :as="as"
    :as-child="asChild"
    :type="as === 'button' && !asChild ? type : undefined"
    data-slot="button"
    :class="classes"
    v-bind="restAttrs"
  >
    <slot />
  </Primitive>
</template>
