<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { DropdownMenuItem } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    inset?: boolean;
    variant?: "default" | "destructive";
    disabled?: boolean;
    asChild?: boolean;
  }>(),
  { variant: "default" },
);

const emit = defineEmits<{
  select: [event: Event];
}>();

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "focus:bg-accent focus:text-accent-foreground data-[variant=destructive]:text-destructive data-[variant=destructive]:focus:bg-destructive/10 dark:data-[variant=destructive]:focus:bg-destructive/20 data-[variant=destructive]:focus:text-destructive data-[variant=destructive]:*:[svg]:!text-destructive [&_svg:not([class*='text-'])]:text-muted-foreground relative flex cursor-default items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[inset]:pl-8 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <DropdownMenuItem
    data-slot="dropdown-menu-item"
    :data-inset="inset || undefined"
    :data-variant="props.variant"
    :disabled="props.disabled"
    :as-child="asChild"
    :class="classes"
    v-bind="restAttrs"
    @select="emit('select', $event)"
  >
    <slot />
  </DropdownMenuItem>
</template>
