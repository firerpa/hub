<script setup lang="ts">
import { computed, ref, watch, type Component } from "vue";
import { useHashRouter } from "@/lib/hash-router";
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clock,
  Loader2,
  Pause,
  RefreshCw,
  Search,
  X,
  XCircle,
  Trash2,
  Play,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { ExecuteJobPanel } from "@/components/jobs/execute-job-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DateTimeRangePicker } from "@/components/ui/date-range-picker";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SortIcon } from "@/components/ui/sort-icon";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type JobStatus = "running" | "paused" | "stopped";
type JobMode = "loop" | "count" | "per-device-count" | "deadline" | "crontab";
type JobSortField = "name" | "mode" | "priority" | "issued" | "success" | "failed" | "timeout" | "state" | "started" | "stopped";
type SortOrder = "asc" | "desc";
type StatusFilter = "all" | "running" | "paused" | "finished";

interface Job {
  id: number;
  name: string;
  description: string;
  owner: { id: number; name: string };
  script: { id: number; version: string; parent: { id: number; name: string; type: number } };
  config: { retries: number; time_limit: number; soft_time_limit: number; ignore_result: boolean };
  priority: number;
  mode: JobMode;
  interval: number;
  count: number;
  crontab?: string;
  issued: number;
  success: number;
  failed: number;
  timeout: number;
  revoked: number;
  created: number;
  started: number;
  stopped: number | null;
  state: JobStatus;
}

type JobApiListResponse = {
  data?: unknown[];
  total?: number;
};

type JobStatusResponse = {
  running?: number;
  paused?: number;
  success?: number;
  failed?: number;
  timeout?: number;
  trend?: Array<{
    success?: number;
    failed?: number;
    timeout?: number;
    timestamp?: number;
  }>;
};

const PAGE_SIZE = 15;

function normalizeTs(raw: unknown): number {
  const n = Number(raw || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e12 ? Math.floor(n / 1000) : Math.floor(n);
}

function formatTs(ts: number): string {
  const sec = normalizeTs(ts);
  if (!sec) return "-";
  const d = new Date(sec * 1000);
  return d.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDuration(started: number, stopped: number | null): string {
  const s = normalizeTs(started);
  if (!s) return "-";
  const e = stopped ? normalizeTs(stopped) : Math.floor(Date.now() / 1000);
  const end = e > 0 ? e : Math.floor(Date.now() / 1000);
  const sec = Math.max(0, end - s);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

function formatDeadlineFromCount(count: number): string {
  const ts = Number(count || 0);
  if (!Number.isFinite(ts) || ts <= 0) return "-";
  return formatTs(ts);
}

function toApiSortField(field: JobSortField): string {
  if (field === "started") return "start_time";
  if (field === "stopped") return "stop_time";
  return field;
}

function buildSparklinePoints(values: number[]): string {
  if (!values.length) return "";
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;
  if (values.length === 1 || range === 0) {
    return values.map((_, i) => `${values.length === 1 ? 50 : (i / (values.length - 1)) * 100},50`).join(" ");
  }
  return values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * 100;
      const y = 100 - ((v - min) / range) * 100;
      return `${x},${y}`;
    })
    .join(" ");
}

function buildSparklineArea(points: string): string {
  if (!points) return "";
  return `${points} 100,100 0,100`;
}

const statColorMap = {
  blue: { accent: "border-l-blue-500", iconBg: "bg-blue-50", line: "rgba(59,130,246,0.2)", fill: "rgba(59,130,246,0.06)" },
  green: { accent: "border-l-green-500", iconBg: "bg-green-50", line: "rgba(34,197,94,0.2)", fill: "rgba(34,197,94,0.06)" },
  red: { accent: "border-l-red-500", iconBg: "bg-red-50", line: "rgba(239,68,68,0.2)", fill: "rgba(239,68,68,0.06)" },
  yellow: { accent: "border-l-amber-500", iconBg: "bg-amber-50", line: "rgba(245,158,11,0.2)", fill: "rgba(245,158,11,0.06)" },
} as const;

type StatColor = keyof typeof statColorMap;

const { t } = useTranslation();
const router = useHashRouter();
const search = ref("");
const statusFilter = ref<StatusFilter>("all");
const sortField = ref<JobSortField>("state");
const sortOrder = ref<SortOrder>("asc");
const startAfter = ref("");
const endBefore = ref("");
const currentPage = ref(1);
const selectedIds = ref<Set<number>>(new Set());
const jobs = ref<Job[]>([]);
const total = ref(0);
const loading = ref(false);
const stopConfirmOpen = ref(false);
const refreshTick = ref(0);
const executeOpen = ref(false);
const globalStats = ref({
  running: 0,
  paused: 0,
  success: 0,
  failed: 0,
  timeout: 0,
  trend: [] as Array<{ success: number; failed: number; timeout: number; timestamp: number }>,
});
const deferredSearch = search;

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / PAGE_SIZE)));
const safePage = computed(() => Math.min(currentPage.value, totalPages.value));
const paginated = computed(() => jobs.value);

const hasFilters = computed(() => !!(search.value || statusFilter.value !== "all" || startAfter.value || endBefore.value));

const buildFilter = computed(() => {
  const filter: Array<{ field: string; op: string; value: unknown }> = [];
  if (deferredSearch.value.trim()) {
    filter.push({
      field: "name",
      op: "like",
      value: deferredSearch.value.trim(),
    });
  }
  if (startAfter.value) {
    const ts = Math.floor(new Date(startAfter.value).getTime() / 1000);
    if (Number.isFinite(ts) && ts > 0) {
      filter.push({ field: "create_time", op: "ge", value: ts });
    }
  }
  if (endBefore.value) {
    const ts = Math.floor(new Date(endBefore.value).getTime() / 1000);
    if (Number.isFinite(ts) && ts > 0) {
      filter.push({ field: "create_time", op: "le", value: ts });
    }
  }
  if (statusFilter.value === "running") {
    filter.push({ field: "state", op: "eq", value: "running" });
  } else if (statusFilter.value === "paused") {
    filter.push({ field: "state", op: "eq", value: "paused" });
  } else if (statusFilter.value === "finished") {
    filter.push({ field: "state", op: "eq", value: "stopped" });
  }
  return filter.length ? JSON.stringify(filter) : undefined;
});

watch(
  refreshTick,
  (_, __, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const loadStats = async () => {
      try {
        const res = await apiRequest<JobStatusResponse>("/api/v1/job/status", {
          cache: "no-store",
        });
        if (cancelled) return;
        const data = (res.data || {}) as JobStatusResponse;
        globalStats.value = {
          running: Number(data.running || 0),
          paused: Number(data.paused || 0),
          success: Number(data.success || 0),
          failed: Number(data.failed || 0),
          timeout: Number(data.timeout || 0),
          trend: Array.isArray(data.trend)
            ? data.trend.map((item) => ({
                success: Number(item?.success || 0),
                failed: Number(item?.failed || 0),
                timeout: Number(item?.timeout || 0),
                timestamp: Number(item?.timestamp || 0),
              }))
            : [],
        };
      } catch {
        if (cancelled) return;
      }
    };
    void loadStats();
  },
  { immediate: true },
);

watch(
  [buildFilter, refreshTick, safePage, sortField, sortOrder],
  (_, __, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const loadJobs = async () => {
      loading.value = true;
      try {
        const params = new URLSearchParams({
          page: String(Math.max(1, safePage.value)),
          size: String(PAGE_SIZE),
          sort: toApiSortField(sortField.value),
          order: sortOrder.value,
        });
        if (buildFilter.value) {
          params.set("filter", buildFilter.value);
        }
        const res = await apiRequest<JobApiListResponse>(`/api/v1/job?${params.toString()}`, {
          cache: "no-store",
        });
        if (cancelled) return;
        const payload = (res.data || {}) as JobApiListResponse;
        const list = Array.isArray(payload.data) ? payload.data : [];
        const mapped = list.map((item: any): Job => {
          const created = normalizeTs(item?.create_time ?? item?.created ?? 0);
          const started = normalizeTs(item?.start_time ?? item?.started ?? 0);
          const stoppedRaw = item?.stop_time ?? item?.stopped ?? 0;
          const stoppedSec = normalizeTs(stoppedRaw);
          const stopped = stoppedSec > 0 ? stoppedSec : null;
          const rawState = String(item?.state || "");
          const state: JobStatus = rawState === "paused"
            ? "paused"
            : rawState === "stopped"
            ? "stopped"
            : "running";
          const modeRaw = String(item?.mode || "loop") as JobMode;
          const mode: JobMode =
            modeRaw === "count" || modeRaw === "per-device-count" || modeRaw === "deadline" || modeRaw === "crontab"
              ? modeRaw
              : "loop";
          return {
            id: Number(item?.id ?? 0),
            name: String(item?.name || "-"),
            description: String(item?.description || ""),
            owner: {
              id: Number(item?.owner?.id ?? 0),
              name: String(item?.owner?.name || "-"),
            },
            script: {
              id: Number(item?.script?.id ?? 0),
              version: String(item?.script?.version || "-"),
              parent: {
                id: Number(item?.script?.parent?.id ?? 0),
                name: String(item?.script?.parent?.name || "-"),
                type: Number(item?.script?.parent?.type ?? 0),
              },
            },
            config: {
              retries: Number(item?.config?.retries ?? 0),
              time_limit: Number(item?.config?.time_limit ?? 0),
              soft_time_limit: Number(item?.config?.soft_time_limit ?? 0),
              ignore_result: Boolean(item?.config?.ignore_result),
            },
            priority: Number(item?.priority ?? 0),
            mode,
            interval: Number(item?.interval ?? 0),
            count: Number(item?.count ?? 0),
            crontab: String(item?.crontab ?? ""),
            issued: Number(item?.issued ?? 0),
            success: Number(item?.success ?? 0),
            failed: Number(item?.failed ?? 0),
            timeout: Number(item?.timeout ?? 0),
            revoked: Number(item?.revoked ?? 0),
            created,
            started,
            stopped,
            state,
          };
        });
        jobs.value = mapped;
        total.value = Number(payload.total ?? mapped.length);
        const valid = new Set(mapped.map((j) => j.id));
        selectedIds.value = new Set(Array.from(selectedIds.value).filter((id) => valid.has(id)));
      } catch (error) {
        if (!cancelled) {
          console.error(formatApiError(error, "Load jobs failed"));
          jobs.value = [];
          total.value = 0;
          selectedIds.value = new Set();
        }
      } finally {
        if (!cancelled) loading.value = false;
      }
    };
    void loadJobs();
  },
  { immediate: true },
);

const clearFilters = () => {
  search.value = "";
  statusFilter.value = "all";
  startAfter.value = "";
  endBefore.value = "";
  currentPage.value = 1;
};

const toggleSort = (field: JobSortField) => {
  if (sortField.value === field) {
    sortOrder.value = sortOrder.value === "asc" ? "desc" : "asc";
  } else {
    sortField.value = field;
    sortOrder.value = "asc";
  }
  currentPage.value = 1;
};

const handleFilterChange = (cb: () => void) => {
  cb();
  currentPage.value = 1;
};

const onToggleJob = (jobId: number, checked: boolean) => {
  const newSet = new Set(selectedIds.value);
  if (checked) {
    newSet.add(jobId);
  } else {
    newSet.delete(jobId);
  }
  selectedIds.value = newSet;
};

const onToggleSelectAllFiltered = (checked: boolean | "indeterminate") => {
  if (checked === "indeterminate") return;
  if (checked) {
    selectedIds.value = new Set(paginated.value.map((j) => j.id));
  } else {
    selectedIds.value = new Set();
  }
};

const allFiltered = computed(() => paginated.value.every((j) => selectedIds.value.has(j.id)) && paginated.value.length > 0);
const partialFiltered = computed(() => paginated.value.some((j) => selectedIds.value.has(j.id)) && !allFiltered.value);

watch(
  () => selectedIds.value.size,
  (size) => {
    if (size > 0) return;
    stopConfirmOpen.value = false;
  },
);

const changeSelectedJobState = async (action: "continue" | "pause" | "stop") => {
  const ids = Array.from(selectedIds.value);
  if (!ids.length) return;
  loading.value = true;
  try {
    const results = await Promise.allSettled(
      ids.map((id) =>
        apiRequest(`/api/v1/job/${id}`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ state: action }).toString(),
        }),
      ),
    );
    const successIds = ids.filter((_, idx) => results[idx]?.status === "fulfilled");
    jobs.value = jobs.value.map((job) =>
      successIds.includes(job.id)
        ? {
            ...job,
            state: action === "continue" ? "running" : action === "pause" ? "paused" : "stopped",
            stopped: action === "stop" ? Math.floor(Date.now() / 1000) : null,
          }
        : job,
    );
    selectedIds.value = new Set();
  } catch (error) {
    console.error(formatApiError(error, "Update job state failed"));
  } finally {
    refreshTick.value += 1;
    loading.value = false;
  }
};

const onExecuteSuccess = () => {
  executeOpen.value = false;
  refreshTick.value += 1;
};

const sortColumns = computed(() => [
  { field: "name" as JobSortField, label: t.value.jobsPage.colName, className: "" },
  { field: "mode" as JobSortField, label: t.value.jobsPage.colMode, className: "" },
  { field: "priority" as JobSortField, label: t.value.jobsPage.colPriority, className: "" },
  { field: "issued" as JobSortField, label: t.value.jobsPage.colIssued, className: "text-right" },
  { field: "success" as JobSortField, label: t.value.jobsPage.colSuccess, className: "text-right" },
  { field: "failed" as JobSortField, label: t.value.jobsPage.colFailed, className: "text-right" },
  { field: "timeout" as JobSortField, label: t.value.jobsPage.colTimeout, className: "text-right" },
  { field: "state" as JobSortField, label: t.value.jobsPage.colStatus, className: "" },
  { field: "started" as JobSortField, label: t.value.jobsPage.colStarted, className: "" },
  { field: "stopped" as JobSortField, label: t.value.jobsPage.colStopped, className: "" },
]);

const statChips = computed(() => {
  const defs: Array<{
    icon: Component;
    iconClass: string;
    label: string;
    note: string;
    value: number;
    color: StatColor;
    trend?: number[];
  }> = [
    {
      icon: Loader2,
      iconClass: "h-[18px] w-[18px] animate-spin text-blue-500",
      label: t.value.jobsPage.statRunning,
      note: t.value.jobsPage.statRunningNote,
      value: globalStats.value.running,
      color: "blue",
    },
    {
      icon: Pause,
      iconClass: "h-[18px] w-[18px] text-amber-500",
      label: t.value.jobsPage.statPaused,
      note: t.value.jobsPage.statPausedNote,
      value: globalStats.value.paused,
      color: "yellow",
    },
    {
      icon: CheckCircle2,
      iconClass: "h-[18px] w-[18px] text-green-500",
      label: t.value.jobsPage.statSuccess,
      note: t.value.jobsPage.statSuccessNote,
      value: globalStats.value.success,
      color: "green",
      trend: globalStats.value.trend.map((x) => x.success),
    },
    {
      icon: XCircle,
      iconClass: "h-[18px] w-[18px] text-red-500",
      label: t.value.jobsPage.statFailed,
      note: t.value.jobsPage.statFailedNote,
      value: globalStats.value.failed,
      color: "red",
      trend: globalStats.value.trend.map((x) => x.failed),
    },
    {
      icon: Clock,
      iconClass: "h-[18px] w-[18px] text-amber-500",
      label: t.value.jobsPage.statTimeout,
      note: t.value.jobsPage.statTimeoutNote,
      value: globalStats.value.timeout,
      color: "yellow",
      trend: globalStats.value.trend.map((x) => x.timeout),
    },
  ];
  return defs.map((def) => {
    const tone = statColorMap[def.color];
    const hasNonZeroTrend = (def.trend || []).some((v) => Number(v) > 0);
    const points = hasNonZeroTrend ? buildSparklinePoints(def.trend || []) : "";
    const area = buildSparklineArea(points);
    return { ...def, tone, points, area };
  });
});

const modeText = (mode: JobMode): string =>
  mode === "loop"
    ? t.value.jobsPage.executeModeLoop
    : mode === "count"
    ? t.value.jobsPage.executeModeCount
    : mode === "per-device-count"
    ? t.value.jobsPage.executeModePerDeviceCount
    : mode === "deadline"
    ? t.value.jobsPage.executeModeTime
    : t.value.jobsPage.executeModeCrontab;

const modeToneCls = (mode: JobMode): string =>
  mode === "loop"
    ? "bg-purple-500/10 text-purple-600 dark:text-purple-400"
    : mode === "count" || mode === "per-device-count"
    ? "bg-sky-500/10 text-sky-600 dark:text-sky-400"
    : mode === "deadline"
    ? "bg-amber-500/10 text-amber-600 dark:text-amber-400"
    : "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400";

const priorityColor = (value: number): string =>
  value >= 70 ? "bg-red-500" : value >= 40 ? "bg-yellow-500" : "bg-green-500";

const pageNumbers = computed(() =>
  Array.from({ length: Math.min(5, totalPages.value) }, (_, i) => {
    if (totalPages.value <= 5) return i + 1;
    if (safePage.value <= 3) return i + 1;
    if (safePage.value >= totalPages.value - 2) return totalPages.value - 4 + i;
    return safePage.value - 2 + i;
  }),
);
</script>

<template>
  <div class="flex h-screen bg-[#f5f5f7]">
    <Sidebar />

    <div class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <!-- Header -->
      <div class="flex h-14 shrink-0 items-center border-b border-gray-100 bg-white px-5">
        <div class="flex w-full items-center justify-between">
          <div>
            <h1 class="text-base font-semibold text-gray-900">{{ t.jobsPage.title }}</h1>
          </div>
          <div class="flex items-center gap-2">
            <Button
              size="sm"
              class="h-8 gap-1.5 rounded-lg bg-gray-900 px-3.5 text-xs font-medium text-white hover:bg-gray-800"
              @click="executeOpen = true"
            >
              <Play class="h-3.5 w-3.5" />
              {{ t.jobsPage.executeJob }}
            </Button>
            <Button
              variant="outline"
              size="sm"
              class="h-8 gap-1.5 rounded-lg border-gray-200 bg-white px-3.5 text-xs text-gray-700 hover:bg-gray-50"
              @click="refreshTick += 1"
              :disabled="loading"
            >
              <RefreshCw :class="cn('h-3.5 w-3.5', loading && 'animate-spin')" />
              {{ t.jobsPage.refresh }}
            </Button>
          </div>
        </div>
      </div>

      <div class="flex min-h-0 flex-1 flex-col gap-2 overflow-hidden p-3">
      <!-- Global Stats -->
      <div class="grid shrink-0 grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        <div
          v-for="stat in statChips"
          :key="stat.label"
          :class="cn('relative flex items-center gap-3 overflow-hidden rounded-lg border border-gray-100 border-l-2 bg-white px-4 py-3 shadow-sm', stat.tone.accent)"
        >
          <svg
            v-if="stat.points"
            class="pointer-events-none absolute inset-0 h-full w-full"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            aria-hidden="true"
          >
            <polygon v-if="stat.area" :points="stat.area" :fill="stat.tone.fill" />
            <polyline
              fill="none"
              :stroke="stat.tone.line"
              stroke-width="0.1"
              stroke-linejoin="round"
              stroke-linecap="round"
              :points="stat.points"
            />
          </svg>
          <div :class="cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg', stat.tone.iconBg)">
            <component :is="stat.icon" :class="stat.iconClass" />
          </div>
          <div class="min-w-0 flex-1">
            <div class="text-2xl font-bold leading-none text-gray-900">{{ stat.value.toLocaleString() }}</div>
            <div class="mt-1">
              <div class="truncate text-xs font-medium leading-none text-gray-700">{{ stat.label }}</div>
              <div class="mt-0.5 truncate text-[11px] leading-none text-gray-400">{{ stat.note }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Table -->
      <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
        <div class="shrink-0 border-b border-gray-100 px-4 py-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-semibold text-gray-800">{{ t.jobsPage.allJobs }}</h2>
              <Badge variant="secondary" class="h-5 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 tabular-nums">
                {{ total.toLocaleString() }}
              </Badge>
            </div>

            <div class="flex flex-wrap items-center gap-2">
              <div class="relative">
                <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  :model-value="search"
                  @update:model-value="handleFilterChange(() => (search = $event))"
                  :placeholder="t.jobsPage.searchPlaceholder"
                  class="h-8 w-[200px] border-gray-200 pl-8 text-xs text-gray-600 placeholder:text-gray-400"
                />
                <button
                  v-if="search"
                  type="button"
                  @click="handleFilterChange(() => (search = ''))"
                  class="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X class="h-3 w-3" />
                </button>
              </div>

              <Select
                :model-value="statusFilter"
                @update:model-value="handleFilterChange(() => (statusFilter = $event as StatusFilter))"
              >
                <SelectTrigger size="sm" class="h-8 w-32 border-gray-200 text-xs text-gray-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{{ t.jobsPage.filterStatusAll }}</SelectItem>
                  <SelectItem value="running">{{ t.jobsPage.filterStatusRunning }}</SelectItem>
                  <SelectItem value="paused">{{ t.jobsPage.filterStatusPaused }}</SelectItem>
                  <SelectItem value="finished">{{ t.jobsPage.filterStatusFinished }}</SelectItem>
                </SelectContent>
              </Select>

              <DateTimeRangePicker
                :start="startAfter"
                :end="endBefore"
                @update:start="handleFilterChange(() => (startAfter = $event))"
                @update:end="handleFilterChange(() => (endBefore = $event))"
              />

              <Button
                v-if="hasFilters"
                variant="ghost"
                size="sm"
                class="h-8 gap-1 text-xs text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                @click="clearFilters"
              >
                <X class="h-3.5 w-3.5" />
                {{ t.jobsPage.clearFilters }}
              </Button>
            </div>
          </div>
        </div>

        <div class="min-h-0 flex-1 overflow-auto">
          <table class="w-full text-xs border-collapse">
            <thead class="sticky top-0 z-10 border-b border-gray-100 bg-white">
              <tr class="border-b border-gray-100">
                <th class="px-3 py-2 w-10">
                  <Checkbox
                    :checked="allFiltered ? true : partialFiltered ? 'indeterminate' : false"
                    @update:checked="onToggleSelectAllFiltered"
                    aria-label="Select all jobs"
                  />
                </th>
                <th
                  v-for="col in sortColumns"
                  :key="col.field"
                  :class="cn('whitespace-nowrap px-3 py-2 text-left font-medium text-gray-500', col.className)"
                >
                  <button class="inline-flex items-center gap-1" @click="toggleSort(col.field)">
                    <span>{{ col.label }}</span>
                    <SortIcon :active="sortField === col.field" :order="sortOrder" />
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="loading">
                <td colspan="11" class="py-16 text-center text-gray-500">
                  <Loader2 class="mx-auto mb-3 h-6 w-6 animate-spin text-gray-400" />
                </td>
              </tr>
              <tr v-else-if="paginated.length === 0">
                <td colspan="11" class="py-20 text-center text-muted-foreground">
                  <EmptyState
                    :title="t.jobsPage.noData"
                    :description="hasFilters ? t.jobsPage.noDataDescFiltered : t.jobsPage.noDataDescDefault"
                  />
                </td>
              </tr>
              <template v-else>
                <tr
                  v-for="(job, idx) in paginated"
                  :key="job.id"
                  :class="cn(
                    'cursor-pointer border-b border-gray-100 transition-colors hover:bg-gray-50',
                    idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/30',
                    selectedIds.has(job.id) && 'bg-gray-100/70'
                  )"
                  @click="router.push(`/jobs/${job.id}`)"
                >
                  <td class="px-3 py-2 w-10" @click.stop>
                    <Checkbox
                      :checked="selectedIds.has(job.id)"
                      @update:checked="onToggleJob(job.id, $event === true)"
                      :aria-label="`Select job: ${job.name}`"
                    />
                  </td>

                  <!-- Name + Script -->
                  <td class="px-3 py-2">
                    <Tooltip>
                      <TooltipTrigger as-child>
                        <p class="font-medium text-foreground cursor-default truncate">{{ job.name }}</p>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" class="text-xs max-w-xs break-all">
                        {{ job.name }}
                      </TooltipContent>
                    </Tooltip>
                  </td>

                  <!-- Mode -->
                  <td class="px-3 py-2">
                    <span :class="cn('inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium', modeToneCls(job.mode))">
                      {{ modeText(job.mode) }}
                    </span>
                  </td>

                  <!-- Priority -->
                  <td class="px-3 py-2">
                    <div class="flex items-center gap-1.5">
                      <div class="h-1.5 w-16 overflow-hidden rounded-full bg-gray-200">
                        <div :class="cn('h-full rounded-full', priorityColor(job.priority))" :style="{ width: `${(job.priority / 100) * 100}%` }" />
                      </div>
                      <span class="text-[10px] text-gray-500">{{ job.priority }}</span>
                    </div>
                  </td>

                  <!-- Issued -->
                  <td class="px-3 py-2 text-right text-muted-foreground">{{ job.issued }}</td>

                  <!-- Success -->
                  <td class="px-3 py-2 text-right">
                    <span :class="job.success > 0 ? 'text-green-600 dark:text-green-400 font-medium' : 'text-muted-foreground'">
                      {{ job.success }}
                    </span>
                  </td>

                  <!-- Failed -->
                  <td class="px-3 py-2 text-right">
                    <span :class="job.failed > 0 ? 'text-red-600 dark:text-red-400 font-medium' : 'text-muted-foreground'">
                      {{ job.failed }}
                    </span>
                  </td>

                  <!-- Timeout -->
                  <td class="px-3 py-2 text-right">
                    <span :class="job.timeout > 0 ? 'text-yellow-600 dark:text-yellow-400 font-medium' : 'text-muted-foreground'">
                      {{ job.timeout }}
                    </span>
                  </td>

                  <!-- Status -->
                  <td class="px-3 py-2">
                    <span v-if="job.state === 'running'" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-500/10 text-blue-600 dark:text-blue-400">
                      <span class="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
                      {{ t.jobsPage.statusRunning }}
                    </span>
                    <span v-else-if="job.state === 'paused'" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-500/10 text-yellow-600 dark:text-yellow-400">
                      <span class="h-1.5 w-1.5 rounded-full bg-yellow-500" />
                      {{ t.jobsPage.statusPaused }}
                    </span>
                    <span v-else class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted text-muted-foreground">
                      <span class="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
                      {{ t.jobsPage.statusFinished }}
                    </span>
                  </td>

                  <!-- Started -->
                  <td class="px-3 py-2 text-muted-foreground whitespace-nowrap">
                    {{ formatTs(job.started) }}
                  </td>

                  <!-- Stopped: show stop timestamp after stop, otherwise running duration -->
                  <td class="px-3 py-2 text-muted-foreground whitespace-nowrap">
                    <Tooltip v-if="job.stopped">
                      <TooltipTrigger as-child>
                        <span class="cursor-default">{{ formatTs(job.stopped) }}</span>
                      </TooltipTrigger>
                      <TooltipContent side="left" class="text-xs">
                        {{ formatDuration(job.started, job.stopped) }}
                      </TooltipContent>
                    </Tooltip>
                    <span v-else class="text-blue-500 text-[10px]">{{ formatDuration(job.started, null) }}</span>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div class="flex shrink-0 items-center justify-between border-t border-gray-100 bg-white px-4 py-2">
          <span class="text-xs text-gray-500">
            {{ t.jobsPage.totalJobs.replace('{total}', total.toString()) }}
          </span>
          <div class="flex items-center gap-1">
            <Button variant="outline" size="icon" class="h-7 w-7" @click="currentPage = 1" :disabled="safePage === 1">
              <ChevronsLeft class="h-3.5 w-3.5" />
            </Button>
            <Button variant="outline" size="icon" class="h-7 w-7" @click="currentPage = Math.max(1, currentPage - 1)" :disabled="safePage === 1">
              <ChevronLeft class="h-3.5 w-3.5" />
            </Button>
            <div class="flex items-center gap-0.5">
              <Button
                v-for="pageNum in pageNumbers"
                :key="pageNum"
                :variant="safePage === pageNum ? 'default' : 'outline'"
                size="sm"
                class="h-7 w-7 p-0 text-xs"
                @click="currentPage = pageNum"
              >
                {{ pageNum }}
              </Button>
            </div>
            <Button variant="outline" size="icon" class="h-7 w-7" @click="currentPage = Math.min(totalPages, currentPage + 1)" :disabled="safePage === totalPages">
              <ChevronRight class="h-3.5 w-3.5" />
            </Button>
            <Button variant="outline" size="icon" class="h-7 w-7" @click="currentPage = totalPages" :disabled="safePage === totalPages">
              <ChevronsRight class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
      </div>

      <!-- Floating Action Bar -->
      <div
        v-if="selectedIds.size > 0"
        class="fixed bottom-6 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 shadow-sm"
      >
        <span class="text-xs font-medium text-gray-800">
          {{ selectedIds.size }} {{ t.jobsPage.itemsSelected }}
        </span>
        <div class="h-4 w-px bg-gray-200" />
        <Tooltip>
          <TooltipTrigger as-child>
            <Button
              variant="ghost"
              size="icon"
              class="h-7 w-7 text-yellow-600 hover:text-yellow-700 hover:bg-yellow-50 dark:hover:bg-yellow-950/20"
              @click="changeSelectedJobState('pause')"
            >
              <Pause class="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="top" class="text-xs">
            {{ t.jobsPage.pauseSelected }}
          </TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger as-child>
            <Button
              variant="ghost"
              size="icon"
              class="h-7 w-7 text-blue-600 hover:text-blue-700 hover:bg-blue-50 dark:hover:bg-blue-950/20"
              @click="changeSelectedJobState('continue')"
            >
              <Play class="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="top" class="text-xs">
            {{ t.jobsPage.resumeSelected }}
          </TooltipContent>
        </Tooltip>
        <Popover :open="stopConfirmOpen" @update:open="stopConfirmOpen = $event">
          <PopoverTrigger as-child>
            <Button
              variant="outline"
              size="sm"
              class="h-7 gap-1.5 border-red-500/30 bg-red-500/5 px-2.5 text-[11px] font-medium text-red-600 hover:bg-red-500/10 dark:text-red-400"
              :title="t.jobsPage.stopSelected"
            >
              <Trash2 class="h-3.5 w-3.5" />
              {{ t.jobsPage.stopSelected }}
            </Button>
          </PopoverTrigger>
          <PopoverContent side="top" align="end" class="w-auto max-w-none p-2.5">
            <div class="flex items-center justify-between gap-2">
              <p class="whitespace-nowrap text-xs text-foreground">
                {{ t.jobsPage.stopConfirmDesc.replace('{n}', String(selectedIds.size)) }}
              </p>
              <div class="flex shrink-0 items-center gap-1.5">
                <Button
                  variant="outline"
                  size="sm"
                  class="h-6 px-2 text-[11px]"
                  @click="stopConfirmOpen = false"
                >
                  {{ t.jobsPage.cancelExecute }}
                </Button>
                <Button
                  size="sm"
                  class="h-6 bg-red-600 px-2 text-[11px] text-white hover:bg-red-700"
                  @click="
                    stopConfirmOpen = false;
                    changeSelectedJobState('stop');
                  "
                >
                  {{ t.jobsPage.stopSelected }}
                </Button>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </div>

    <Sheet :open="executeOpen" @update:open="executeOpen = $event">
      <SheetContent side="right" class="w-full gap-0 p-0 sm:max-w-[680px]">
        <SheetHeader class="border-b border-border pr-12">
          <SheetTitle>{{ t.jobsPage.executeTitle }}</SheetTitle>
        </SheetHeader>
        <ExecuteJobPanel
          compact
          :on-cancel="() => (executeOpen = false)"
          :on-success="onExecuteSuccess"
        />
      </SheetContent>
    </Sheet>
  </div>
</template>
