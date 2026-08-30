<script setup lang="ts">
import { computed, ref, watch } from "vue";
import {
  Calendar as CalendarIcon,
  ChevronLeft as ChevronLeftIcon,
  ChevronRight as ChevronRightIcon,
} from "lucide-vue-next";
import {
  DateRangeFieldInput,
  DateRangeFieldRoot,
  RangeCalendarCell,
  RangeCalendarCellTrigger,
  RangeCalendarGrid,
  RangeCalendarGridBody,
  RangeCalendarGridHead,
  RangeCalendarGridRow,
  RangeCalendarHeadCell,
  RangeCalendarNext,
  RangeCalendarPrev,
  RangeCalendarRoot,
  useDateFormatter,
  type DateValue,
} from "reka-ui";
import { getLocalTimeZone, parseDateTime, today, type CalendarDate } from "@internationalized/date";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const props = defineProps<{
  start?: string;
  end?: string;
  className?: string;
  placeholder?: string;
}>();

const emit = defineEmits<{
  "update:start": [value: string];
  "update:end": [value: string];
}>();

const { t, locale } = useTranslation();
const formatter = useDateFormatter(locale.value);

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function parse(value: string | undefined): DateValue | undefined {
  if (!value) return undefined;
  try {
    return parseDateTime(value) as unknown as DateValue;
  } catch {
    return undefined;
  }
}

type AnyDate = { year: number; month: number; day: number; hour?: number; minute?: number };

function timePartsOf(v: AnyDate | undefined | null): { hour: number; minute: number } {
  if (v && "hour" in v) return { hour: Number(v.hour) || 0, minute: Number(v.minute) || 0 };
  return { hour: 0, minute: 0 };
}

function toDateTimeStr(v: AnyDate): string {
  const { hour, minute } = timePartsOf(v);
  return `${v.year}-${pad2(v.month)}-${pad2(v.day)}T${pad2(hour)}:${pad2(minute)}`;
}

function formatDisplay(v: AnyDate | undefined | null): string {
  if (!v) return "";
  const { hour, minute } = timePartsOf(v);
  return `${v.year}-${pad2(v.month)}-${pad2(v.day)} ${pad2(hour)}:${pad2(minute)}`;
}

const internal = ref<any>({ start: parse(props.start), end: parse(props.end) });

// 日历范围选择的中间态（已选起点、未选终点）不应被 props 回填打断
let selecting = false;

function onCalendarUpdate(v: any) {
  selecting = Boolean(v?.start && !v?.end);
  internal.value = v;
}

watch(
  () => [props.start, props.end],
  () => {
    if (selecting) return;
    const curS = internal.value?.start ? toDateTimeStr(internal.value.start) : undefined;
    const curE = internal.value?.end ? toDateTimeStr(internal.value.end) : undefined;
    if (curS === props.start && curE === props.end) return;
    internal.value = { start: parse(props.start), end: parse(props.end) };
  },
);

watch(
  internal,
  (v) => {
    if (v.start) {
      const s = toDateTimeStr(v.start);
      if (s !== props.start) emit("update:start", s);
    }
    if (v.end) {
      const e = toDateTimeStr(v.end);
      if (e !== props.end) emit("update:end", e);
    }
  },
  { deep: true },
);

const text = computed(() => {
  const s = formatDisplay(internal.value.start);
  const e = formatDisplay(internal.value.end);
  if (s && e) return `${s} - ${e}`;
  return s || e;
});

const calendarPlaceholder = computed(() => today(getLocalTimeZone()) as unknown as DateValue);

function applyRange(startDay: CalendarDate, endDay: CalendarDate) {
  internal.value = {
    start: parseDateTime(`${toDateStr(startDay)}T00:00`) as unknown as DateValue,
    end: parseDateTime(`${toDateStr(endDay)}T23:59`) as unknown as DateValue,
  };
}

function toDateStr(d: CalendarDate): string {
  return `${d.year}-${pad2(d.month)}-${pad2(d.day)}`;
}

const quickOptions = computed(() => {
  const now = today(getLocalTimeZone());
  const quarterStartMonth = Math.floor((now.month - 1) / 3) * 3 + 1;
  const startOfQuarter = now.set({ month: quarterStartMonth, day: 1 });
  const startOfLastQuarter = startOfQuarter.subtract({ months: 3 });
  const endOfLastQuarter = startOfQuarter.subtract({ days: 1 });
  const startOfMonth = now.set({ day: 1 });
  const startOfLastMonth = startOfMonth.subtract({ months: 1 });
  const endOfLastMonth = startOfMonth.subtract({ days: 1 });
  const startOfYear = now.set({ month: 1, day: 1 });
  const startOfLastYear = startOfYear.subtract({ years: 1 });
  const endOfLastYear = startOfYear.subtract({ days: 1 });
  const c = t.value.common;
  return [
    { label: c.rangeToday, action: () => applyRange(now, now) },
    { label: c.rangeYesterday, action: () => { const y = now.subtract({ days: 1 }); applyRange(y, y); } },
    { label: c.rangeLast7Days, action: () => applyRange(now.subtract({ days: 6 }), now) },
    { label: c.rangeLast30Days, action: () => applyRange(now.subtract({ days: 29 }), now) },
    { label: c.rangeThisMonth, action: () => applyRange(startOfMonth, now) },
    { label: c.rangeLastMonth, action: () => applyRange(startOfLastMonth, endOfLastMonth) },
    { label: c.rangeThisQuarter, action: () => applyRange(startOfQuarter, now) },
    { label: c.rangeLastQuarter, action: () => applyRange(startOfLastQuarter, endOfLastQuarter) },
    { label: c.rangeThisYear, action: () => applyRange(startOfYear, now) },
    { label: c.rangeLastYear, action: () => applyRange(startOfLastYear, endOfLastYear) },
  ];
});

const navBtnClass = cn(
  "inline-flex items-center justify-center rounded-md w-7 h-7 bg-transparent text-foreground",
  "hover:bg-accent hover:text-accent-foreground transition-colors cursor-pointer",
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring aria-disabled:opacity-50",
);

const cellClass = cn(
  "relative aspect-square w-[34px] my-0.5 p-0 text-center select-none",
  "[&:has([data-selected])]:bg-accent [&:has([data-highlighted])]:bg-accent",
  "first:[&:has([data-selected])]:rounded-l-md last:[&:has([data-selected])]:rounded-r-md",
  "[&:has([data-selected][data-selection-end])]:rounded-r-md",
  "[&:not(:has([data-highlighted])):has([data-selected][data-selection-start])]:rounded-l-md",
  "first:[&:has([data-highlighted])]:rounded-l-md last:[&:has([data-highlighted])]:rounded-r-md",
  "[&:has([data-highlighted-start])]:rounded-l-md [&:has([data-highlighted-end])]:rounded-r-md",
);

const cellTriggerClass = cn(
  "relative flex h-full w-full items-center justify-center rounded-md whitespace-nowrap text-xs font-normal text-foreground outline-none transition-colors",
  "hover:bg-accent hover:text-accent-foreground",
  "focus-visible:ring-2 focus-visible:ring-ring",
  "data-[selection-start]:bg-primary data-[selection-start]:text-primary-foreground data-[selection-start]:hover:bg-primary",
  "data-[selection-end]:bg-primary data-[selection-end]:text-primary-foreground data-[selection-end]:hover:bg-primary",
  "data-[highlighted-start]:bg-primary data-[highlighted-start]:text-primary-foreground",
  "data-[highlighted-end]:bg-primary data-[highlighted-end]:text-primary-foreground",
  "data-[outside-view]:text-muted-foreground data-[outside-view]:opacity-50",
  "data-[disabled]:text-muted-foreground data-[disabled]:opacity-50 data-[disabled]:pointer-events-none",
  "data-[unavailable]:pointer-events-none data-[unavailable]:text-muted-foreground data-[unavailable]:line-through",
  "before:absolute before:bottom-1 before:hidden before:h-1 before:w-1 before:rounded-full before:bg-primary-foreground",
  "data-[today]:before:block data-[today]:before:bg-primary",
  "data-[selection-start]:before:bg-primary-foreground data-[selection-end]:before:bg-primary-foreground",
);

const fieldSegmentClass = cn(
  "rounded px-0.5 text-center focus:outline-none focus:bg-accent data-[placeholder]:text-muted-foreground",
);
</script>

<template>
  <Popover>
    <PopoverTrigger as-child>
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
        <span class="truncate">{{ text || placeholder || t.common.selectTimeRange }}</span>
      </Button>
    </PopoverTrigger>
    <PopoverContent align="start" class="w-auto p-0">
      <div class="flex">
        <div class="flex w-36 shrink-0 flex-col gap-0.5 border-r border-border p-2">
          <button
            v-for="option in quickOptions"
            :key="option.label"
            type="button"
            class="flex w-full rounded-md bg-transparent px-2.5 py-1.5 text-left text-xs transition-colors hover:bg-accent hover:text-accent-foreground"
            @click="option.action"
          >
            {{ option.label }}
          </button>
        </div>
        <div>
          <RangeCalendarRoot
            v-slot="{ weekDays, grid }"
            :model-value="internal"
            class="flex flex-col gap-4 p-3 sm:flex-row"
            @update:model-value="onCalendarUpdate"
            fixed-weeks
            :number-of-months="2"
            :locale="locale"
            weekday-format="short"
            :placeholder="calendarPlaceholder"
          >
            <div v-for="(month, index) in grid" :key="month.value.toString()">
              <div v-if="index === 0" class="flex items-center">
                <RangeCalendarPrev :class="navBtnClass" aria-label="Previous month">
                  <ChevronLeftIcon class="size-4" />
                </RangeCalendarPrev>
                <span class="flex-1 text-center text-sm font-medium select-none">
                  {{ formatter.custom(month.value.toDate(getLocalTimeZone()), { month: "long", year: "numeric" }) }}
                </span>
                <span class="w-7" />
              </div>
              <div v-if="index === grid.length - 1" class="flex items-center">
                <span class="w-7" />
                <span class="flex-1 text-center text-sm font-medium select-none">
                  {{ formatter.custom(month.value.toDate(getLocalTimeZone()), { month: "long", year: "numeric" }) }}
                </span>
                <RangeCalendarNext :class="navBtnClass" aria-label="Next month">
                  <ChevronRightIcon class="size-4" />
                </RangeCalendarNext>
              </div>
              <RangeCalendarGrid class="mt-2 w-full border-collapse select-none">
                <RangeCalendarGridHead>
                  <RangeCalendarGridRow class="mb-1 grid w-full grid-cols-7">
                    <RangeCalendarHeadCell
                      v-for="day in weekDays"
                      :key="day"
                      class="rounded-md text-center text-xs font-normal text-muted-foreground"
                    >
                      {{ day }}
                    </RangeCalendarHeadCell>
                  </RangeCalendarGridRow>
                </RangeCalendarGridHead>
                <RangeCalendarGridBody class="grid">
                  <RangeCalendarGridRow
                    v-for="(weekDates, rowIndex) in month.rows"
                    :key="`weekDate-${rowIndex}`"
                    class="grid grid-cols-7"
                  >
                    <RangeCalendarCell
                      v-for="weekDate in weekDates"
                      :key="weekDate.toString()"
                      :date="weekDate"
                      :class="cellClass"
                    >
                      <RangeCalendarCellTrigger :day="weekDate" :month="month.value" :class="cellTriggerClass" />
                    </RangeCalendarCell>
                  </RangeCalendarGridRow>
                </RangeCalendarGridBody>
              </RangeCalendarGrid>
            </div>
          </RangeCalendarRoot>

          <DateRangeFieldRoot
            v-slot="{ segments }"
            v-model="internal"
            :locale="locale"
            granularity="minute"
            :hour-cycle="24"
            class="flex select-none items-center border-t border-border p-2"
          >
            <div class="flex items-center rounded-md border border-input bg-background px-2 py-1 text-xs shadow-xs">
              <template v-for="item in segments.start" :key="item.part">
                <DateRangeFieldInput
                  v-if="item.part === 'literal'"
                  :part="item.part"
                  type="start"
                  class="text-muted-foreground"
                >
                  {{ item.value }}
                </DateRangeFieldInput>
                <DateRangeFieldInput
                  v-else
                  :part="item.part"
                  type="start"
                  :class="cn(fieldSegmentClass, item.part === 'year' ? 'w-10' : 'w-7')"
                >
                  {{ item.value }}
                </DateRangeFieldInput>
              </template>
            </div>

            <span class="mx-2 text-muted-foreground">-</span>

            <div class="flex items-center rounded-md border border-input bg-background px-2 py-1 text-xs shadow-xs">
              <template v-for="item in segments.end" :key="item.part">
                <DateRangeFieldInput
                  v-if="item.part === 'literal'"
                  :part="item.part"
                  type="end"
                  class="text-muted-foreground"
                >
                  {{ item.value }}
                </DateRangeFieldInput>
                <DateRangeFieldInput
                  v-else
                  :part="item.part"
                  type="end"
                  :class="cn(fieldSegmentClass, item.part === 'year' ? 'w-10' : 'w-7')"
                >
                  {{ item.value }}
                </DateRangeFieldInput>
              </template>
            </div>
          </DateRangeFieldRoot>
        </div>
      </div>
    </PopoverContent>
  </Popover>
</template>
