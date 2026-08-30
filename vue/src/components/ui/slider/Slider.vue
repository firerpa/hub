<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { SliderRange, SliderRoot, SliderThumb, SliderTrack } from "reka-ui";
import { cn } from "@/lib/utils";

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    modelValue?: number[];
    defaultValue?: number[];
    min?: number;
    max?: number;
    step?: number;
    disabled?: boolean;
  }>(),
  { min: 0, max: 100 },
);

const emit = defineEmits<{
  "update:modelValue": [value: number[]];
}>();

const attrs = useAttrs();

const thumbsCount = computed(() => {
  const v = Array.isArray(props.modelValue)
    ? props.modelValue
    : Array.isArray(props.defaultValue)
      ? props.defaultValue
      : [props.min, props.max];
  return v.length;
});

const classes = computed(() =>
  cn(
    "relative flex w-full touch-none items-center select-none data-[disabled]:opacity-50 data-[orientation=vertical]:h-full data-[orientation=vertical]:min-h-44 data-[orientation=vertical]:w-auto data-[orientation=vertical]:flex-col",
    attrs.class as string,
  ),
);
const restAttrs = computed(() => {
  const { class: _class, ...rest } = attrs;
  return rest;
});
</script>

<template>
  <SliderRoot
    data-slot="slider"
    :model-value="props.modelValue"
    :default-value="props.defaultValue"
    :min="props.min"
    :max="props.max"
    :step="props.step"
    :disabled="props.disabled"
    :class="classes"
    v-bind="restAttrs"
    @update:model-value="emit('update:modelValue', $event as number[])"
  >
    <SliderTrack
      data-slot="slider-track"
      class="bg-muted relative grow overflow-hidden rounded-full data-[orientation=horizontal]:h-1.5 data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-1.5"
    >
      <SliderRange
        data-slot="slider-range"
        class="bg-primary absolute data-[orientation=horizontal]:h-full data-[orientation=vertical]:w-full"
      />
    </SliderTrack>
    <SliderThumb
      v-for="i in thumbsCount"
      :key="i - 1"
      data-slot="slider-thumb"
      class="border-primary ring-ring/50 block size-4 shrink-0 rounded-full border bg-white shadow-sm transition-[color,box-shadow] hover:ring-4 focus-visible:ring-4 focus-visible:outline-hidden disabled:pointer-events-none disabled:opacity-50"
    />
  </SliderRoot>
</template>
