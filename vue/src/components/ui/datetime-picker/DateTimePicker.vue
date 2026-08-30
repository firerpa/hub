<script setup lang="ts">
import { computed } from "vue";
import {
  Calendar as CalendarIcon,
  ChevronLeft as ChevronLeftIcon,
  ChevronRight as ChevronRightIcon,
} from "lucide-vue-next";
import {
  DatePickerCell,
  DatePickerCellTrigger,
  DatePickerContent,
  DatePickerGrid,
  DatePickerGridBody,
  DatePickerGridHead,
  DatePickerGridRow,
  DatePickerHeadCell,
  DatePickerHeader,
  DatePickerHeading,
  DatePickerNext,
  DatePickerPrev,
  DatePickerRoot,
  DatePickerTrigger,
  DatePickerCalendar,
} from "reka-ui";
import { getLocalTimeZone, parseDateTime, today, type DateValue } from "@internationalized/date";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    modelValue?: string;
    className?: string;
    placeholder?: string;
  }>(),
  { placeholder: "选择时间" },
);

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function timePartsOf(v: DateValue | undefined): { hour: number; minute: number } {
  if (v && "hour" in v) return { hour: Number(v.hour) || 0, minute: Number(v.minute) || 0 };
  return { hour: 0, minute: 0 };
}

const selected = computed<DateValue | undefined>(() => {
  if (!props.modelValue) return undefined;
  try {
    return parseDateTime(props.modelValue);
  } catch {
    return undefined;
  }
});

const calendarPlaceholder = computed(() => today(getLocalTimeZone()));

const text = computed(() => {
  const v = selected.value;
  if (!v) return "";
  const { hour, minute } = timePartsOf(v);
  return `${v.year}-${pad2(v.month)}-${pad2(v.day)} ${pad2(hour)}:${pad2(minute)}`;
});

const timeText = computed(() => {
  const { hour, minute } = timePartsOf(selected.value);
  return selected.value ? `${pad2(hour)}:${pad2(minute)}` : "00:00";
});

function onDateChange(v: DateValue | DateValue[] | undefined) {
  if (!v || Array.isArray(v)) return;
  const { hour, minute } = timePartsOf(selected.value);
  emit("update:modelValue", `${v.year}-${pad2(v.month)}-${pad2(v.day)}T${pad2(hour)}:${pad2(minute)}`);
}

function onTimeInput(e: Event) {
  const [h, m] = String((e.target as HTMLInputElement).value || "00:00").split(":");
  const base = selected.value ?? today(getLocalTimeZone());
  emit(
    "update:modelValue",
    `${base.year}-${pad2(base.month)}-${pad2(base.day)}T${pad2(Number(h) || 0)}:${pad2(Number(m) || 0)}`,
  );
}

const navBtnClass = cn(
  buttonVariants({ variant: "ghost" }),
  "size-(--cell-size) aria-disabled:opacity-50 p-0 select-none",
);

const cellTriggerClass = cn(
  buttonVariants({ variant: "ghost" }),
  "flex aspect-square size-auto w-full min-w-(--cell-size) flex-col gap-1 leading-none font-normal",
  "data-[today]:bg-accent data-[today]:text-accent-foreground data-[today]:rounded-md",
  "data-[selected]:bg-primary data-[selected]:text-primary-foreground data-[selected]:rounded-md",
  "data-[selected]:hover:bg-primary data-[selected]:hover:text-primary-foreground",
  "data-[outside-view]:text-muted-foreground data-[outside-view]:opacity-70",
);
</script>

<template>
  <DatePickerRoot
    :model-value="selected"
    :placeholder="calendarPlaceholder"
    weekday-format="short"
    @update:model-value="onDateChange"
  >
    <DatePickerTrigger as-child>
      <Button
        type="button"
        variant="outline"
        :class="
          cn(
            'h-8 justify-start gap-2 border-gray-200 px-2 text-xs font-normal text-gray-700',
            !text && 'text-gray-400',
            className,
          )
        "
      >
        <CalendarIcon class="h-3.5 w-3.5 shrink-0 text-gray-400" />
        <span class="truncate">{{ text || placeholder }}</span>
      </Button>
    </DatePickerTrigger>
    <DatePickerContent
      align="start"
      :class="
        cn(
          'bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 w-auto origin-(--reka-popover-content-transform-origin) rounded-md border p-1.5 shadow-md outline-hidden',
        )
      "
    >
      <DatePickerCalendar
        v-slot="{ grid, weekDays }"
        class="bg-background group/calendar p-3 [--cell-size:--spacing(8)] w-fit text-xs"
      >
        <DatePickerHeader class="flex items-center gap-1 w-full justify-between">
          <DatePickerPrev :class="navBtnClass" aria-label="Previous month">
            <ChevronLeftIcon class="size-4" />
          </DatePickerPrev>
          <DatePickerHeading class="flex select-none items-center justify-center font-medium text-sm" />
          <DatePickerNext :class="navBtnClass" aria-label="Next month">
            <ChevronRightIcon class="size-4" />
          </DatePickerNext>
        </DatePickerHeader>
        <DatePickerGrid
          v-for="month in grid"
          :key="month.value.toString()"
          class="w-full border-collapse"
        >
          <DatePickerGridHead>
            <DatePickerGridRow class="flex">
              <DatePickerHeadCell
                v-for="day in weekDays"
                :key="day"
                class="text-muted-foreground rounded-md flex-1 font-normal text-[0.8rem] select-none"
              >
                {{ day }}
              </DatePickerHeadCell>
            </DatePickerGridRow>
          </DatePickerGridHead>
          <DatePickerGridBody>
            <DatePickerGridRow v-for="(weekDates, wi) in month.rows" :key="wi" class="flex w-full mt-2">
              <DatePickerCell
                v-for="weekDate in weekDates"
                :key="weekDate.toString()"
                :date="month.value"
                class="relative w-full h-full p-0 text-center group/day aspect-square select-none"
              >
                <DatePickerCellTrigger :day="weekDate" :month="month.value" :class="cellTriggerClass" />
              </DatePickerCell>
            </DatePickerGridRow>
          </DatePickerGridBody>
        </DatePickerGrid>
      </DatePickerCalendar>
      <div class="mt-1.5 border-t border-border pt-1.5">
        <Input
          type="time"
          :step="60"
          :model-value="timeText"
          class="h-7 text-[11px]"
          @input="onTimeInput"
        />
      </div>
    </DatePickerContent>
  </DatePickerRoot>
</template>
