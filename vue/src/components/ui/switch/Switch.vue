<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { SwitchRoot, SwitchThumb } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    checked?: boolean;
    defaultChecked?: boolean;
    disabled?: boolean;
  }>(),
  { checked: undefined, defaultChecked: undefined, disabled: undefined },
);

const emit = defineEmits<{
  "update:checked": [value: boolean];
}>();

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "peer data-[state=checked]:bg-primary data-[state=unchecked]:bg-input focus-visible:border-ring focus-visible:ring-ring/50 dark:data-[state=unchecked]:bg-input/80 inline-flex h-[1.15rem] w-8 shrink-0 items-center rounded-full border border-transparent shadow-xs transition-all outline-none focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <SwitchRoot
    data-slot="switch"
    :model-value="props.checked"
    :default-value="props.defaultChecked"
    :disabled="props.disabled"
    :class="classes"
    v-bind="restAttrs"
    @update:model-value="emit('update:checked', $event === true)"
  >
    <SwitchThumb
      data-slot="switch-thumb"
      class="bg-background dark:data-[state=unchecked]:bg-foreground dark:data-[state=checked]:bg-primary-foreground pointer-events-none block size-4 rounded-full ring-0 transition-transform data-[state=checked]:translate-x-[calc(100%-2px)] data-[state=unchecked]:translate-x-0"
    />
  </SwitchRoot>
</template>
