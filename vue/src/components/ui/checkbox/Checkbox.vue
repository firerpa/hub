<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { CheckboxIndicator, CheckboxRoot } from "reka-ui";
import { Check as CheckIcon } from "lucide-vue-next";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

// checked 必须显式 default: undefined，否则 absent 会被 Vue cast 成 false，
// 转发给 reka 的 modelValue（default: void 0）后变成受控锁死
const props = withDefaults(
  defineProps<{
    checked?: boolean | "indeterminate";
    defaultChecked?: boolean;
    disabled?: boolean;
    value?: string;
  }>(),
  { checked: undefined, defaultChecked: undefined, disabled: undefined },
);

const emit = defineEmits<{
  "update:checked": [value: boolean];
}>();

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    "peer border-input dark:bg-input/30 data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground dark:data-[state=checked]:bg-primary data-[state=checked]:border-primary focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive size-4 shrink-0 rounded-[4px] border shadow-xs transition-shadow outline-none focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <CheckboxRoot
    data-slot="checkbox"
    :model-value="props.checked"
    :default-value="props.defaultChecked"
    :disabled="props.disabled"
    :value="props.value"
    :class="classes"
    v-bind="restAttrs"
    @update:model-value="emit('update:checked', $event === true)"
  >
    <CheckboxIndicator
      data-slot="checkbox-indicator"
      class="flex items-center justify-center text-current transition-none"
    >
      <CheckIcon class="size-3.5" />
    </CheckboxIndicator>
  </CheckboxRoot>
</template>
