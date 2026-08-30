<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { CreateModelPanel } from "@/components/models/create-model-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState } from "@/components/ui/empty-state";
import { FeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { DateTimeRangePicker } from "@/components/ui/date-range-picker";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SortIcon } from "@/components/ui/sort-icon";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { loadModelCatalog } from "@/lib/model-catalog";
import { cn } from "@/lib/utils";

type SortOrder = "asc" | "desc";
type ModelSortField = "id" | "name" | "model_name" | "api_base" | "token_count" | "create_time";
type ModelItem = {
  id: number;
  name: string;
  model_name?: string;
  api_base?: string;
  api_key?: string;
  token_count?: number;
  create_time?: number;
};

const PAGE_SIZE_OPTIONS = [100, 300, 500];

function tsText(ts?: number) {
  const n = Number(ts || 0);
  if (!Number.isFinite(n) || n <= 0) return "-";
  return new Date(n * 1000).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

const { t } = useTranslation();
const loading = ref(false);
const refreshTick = ref(0);
const createOpen = ref(false);
const tip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);

const search = ref("");
const deferredSearch = ref("");
watch(search, (v) => {
  deferredSearch.value = v;
});
const startAfter = ref("");
const endBefore = ref("");
const sortField = ref<ModelSortField>("id");
const sortOrder = ref<SortOrder>("desc");

const page = ref(1);
const size = ref(100);
const total = ref(0);
const rows = ref<ModelItem[]>([]);
const selected = ref<Set<number>>(new Set());

const hasFilters = computed(() => Boolean(search.value || startAfter.value || endBefore.value));
const pages = computed(() => Math.max(1, Math.ceil(total.value / size.value)));
const safePage = computed(() => Math.min(page.value, pages.value));

const showTip = (text: string, variant: FeedbackTipVariant = "error") => {
  tip.value = { id: Date.now() + Math.random(), text, variant };
};

const filterQuery = computed(() => {
  const filter: Array<{ field: string; op: string; value: unknown }> = [];
  if (deferredSearch.value.trim()) filter.push({ field: "name", op: "like", value: deferredSearch.value.trim() });
  if (startAfter.value) {
    const ts = Math.floor(new Date(startAfter.value).getTime() / 1000);
    if (Number.isFinite(ts) && ts > 0) filter.push({ field: "create_time", op: "ge", value: ts });
  }
  if (endBefore.value) {
    const ts = Math.floor(new Date(endBefore.value).getTime() / 1000);
    if (Number.isFinite(ts) && ts > 0) filter.push({ field: "create_time", op: "le", value: ts });
  }
  return filter.length ? JSON.stringify(filter) : undefined;
});

onMounted(() => {
  void loadModelCatalog();
});

watch(
  [safePage, size, sortField, sortOrder, filterQuery, refreshTick],
  (_value, _oldValue, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const load = async () => {
      loading.value = true;
      try {
        const qs = new URLSearchParams({
          page: String(safePage.value),
          size: String(size.value),
          sort: sortField.value,
          order: sortOrder.value,
        });
        if (filterQuery.value) qs.set("filter", filterQuery.value);
        const res = await apiRequest<any>(`/api/v1/model?${qs.toString()}`, { cache: "no-store" });
        if (cancelled) return;
        const payload = res.data || {};
        const list = Array.isArray(payload.data) ? payload.data : [];
        const mapped: ModelItem[] = list.map((it: any) => ({
          id: Number(it?.id ?? 0),
          name: String(it?.name || "-"),
          model_name: String(it?.model_name ?? it?.model ?? "-"),
          api_base: String(it?.api_base || "-"),
          api_key: String(it?.api_key || "-"),
          token_count: Number(it?.token_count ?? 0),
          create_time: Number(it?.create_time ?? 0),
        }));
        rows.value = mapped;
        total.value = Number(payload.total ?? mapped.length);
        const valid = new Set(mapped.map((x) => x.id));
        selected.value = new Set(Array.from(selected.value).filter((id) => valid.has(id)));
      } catch (error) {
        if (cancelled) return;
        rows.value = [];
        total.value = 0;
        selected.value = new Set();
        showTip(formatApiError(error, t.value.modelsPage.loadFailed));
      } finally {
        if (!cancelled) loading.value = false;
      }
    };
    void load();
  },
  { immediate: true },
);

const toggleSort = (field: ModelSortField) => {
  const next: SortOrder = sortField.value === field ? (sortOrder.value === "asc" ? "desc" : "asc") : "asc";
  sortField.value = field;
  sortOrder.value = next;
  page.value = 1;
};

const columns = computed<Array<{ field?: ModelSortField; label: string }>>(() => [
  { field: "name", label: t.value.modelsPage.colName },
  { field: "model_name", label: t.value.modelsPage.colModel },
  { field: "api_base", label: t.value.modelsPage.colEndpoint },
  { label: t.value.modelsPage.colKey },
  { field: "token_count", label: t.value.modelsPage.colTokens },
  { field: "create_time", label: t.value.modelsPage.colCreated },
]);

const allSelected = computed(() => rows.value.length > 0 && rows.value.every((r) => selected.value.has(r.id)));
const partialSelected = computed(() => rows.value.some((r) => selected.value.has(r.id)) && !allSelected.value);

const onToggleAll = (checked: boolean | "indeterminate") => {
  if (checked === "indeterminate") return;
  if (!checked) {
    selected.value = new Set();
    return;
  }
  selected.value = new Set(rows.value.map((r) => r.id));
};

const onToggleOne = (id: number, checked: boolean) => {
  const next = new Set(selected.value);
  if (checked) next.add(id);
  else next.delete(id);
  selected.value = next;
};

const handleBatchDelete = async () => {
  const ids = Array.from(selected.value);
  if (!ids.length) return;
  loading.value = true;
  try {
    const results = await Promise.allSettled(
      ids.map((id) => apiRequest(`/api/v1/model/${id}`, { method: "DELETE" })),
    );
    const ok = results.filter((r) => r.status === "fulfilled").length;
    selected.value = new Set();
    if (ok === ids.length) showTip(t.value.modelsPage.deleteSuccess.replace("{n}", String(ok)), "success");
    else showTip(t.value.modelsPage.deleteFailed);
  } catch (error) {
    showTip(formatApiError(error, t.value.modelsPage.deleteFailed));
  } finally {
    refreshTick.value += 1;
    loading.value = false;
  }
};

const onPanelCancel = () => {
  createOpen.value = false;
};

const onPanelSuccess = () => {
  createOpen.value = false;
  refreshTick.value += 1;
  showTip(t.value.modelsPage.createSuccess, "success");
};
</script>

<template>
  <div class="flex h-screen bg-[#f5f5f7]">
    <Sidebar />
    <div class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <div class="h-14 shrink-0 border-b border-gray-100 bg-white px-5 py-2.5">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-base font-semibold">{{ t.modelsPage.title }}</h1>
          </div>
          <div class="flex items-center gap-2">
            <FeedbackTip
              v-if="tip"
              :key="tip.id"
              :message="tip.text"
              :variant="tip.variant"
              truncate
              class="max-w-[360px]"
            />
            <Button size="sm" class="h-8 gap-1.5 text-xs" @click="createOpen = true">
              <Plus class="h-3.5 w-3.5" />
              {{ t.modelsPage.createModel }}
            </Button>
            <Button
              variant="outline"
              size="sm"
              class="h-8 gap-1.5 text-xs"
              :disabled="loading"
              @click="refreshTick += 1"
            >
              <RefreshCw :class="cn('h-3.5 w-3.5', loading && 'animate-spin')" />
              {{ t.modelsPage.refresh }}
            </Button>
          </div>
        </div>
      </div>

      <div class="flex min-h-0 flex-1 flex-col overflow-hidden p-3">
      <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
        <div class="shrink-0 border-b border-gray-100 px-4 py-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-semibold text-gray-800">{{ t.modelsPage.allModels }}</h2>
              <Badge variant="secondary" class="h-5 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 tabular-nums">
                {{ total.toLocaleString() }}
              </Badge>
            </div>

            <div class="flex flex-wrap items-center gap-2">
              <div class="relative">
                <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  :model-value="search"
                  :placeholder="t.modelsPage.searchPlaceholder"
                  class="h-8 w-[200px] border-gray-200 pl-8 text-xs text-gray-600 placeholder:text-gray-400"
                  @update:model-value="
                    (v) => {
                      search = v;
                      page = 1;
                    }
                  "
                />
                <button
                  v-if="search"
                  type="button"
                  class="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  @click="
                    search = '';
                    page = 1;
                  "
                >
                  <X class="h-3 w-3" />
                </button>
              </div>

              <DateTimeRangePicker
                :start="startAfter"
                :end="endBefore"
                @update:start="
                  (v) => {
                    startAfter = v;
                    page = 1;
                  }
                "
                @update:end="
                  (v) => {
                    endBefore = v;
                    page = 1;
                  }
                "
              />

              <Button
                v-if="hasFilters"
                variant="ghost"
                size="sm"
                class="h-8 gap-1 text-xs text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                @click="
                  search = '';
                  startAfter = '';
                  endBefore = '';
                  page = 1;
                "
              >
                <X class="h-3.5 w-3.5" />
                {{ t.modelsPage.clearFilters }}
              </Button>
            </div>
          </div>
        </div>

        <div class="min-h-0 flex-1 overflow-auto">
          <table class="w-full border-collapse text-xs">
            <thead class="sticky top-0 z-10 border-b border-gray-100 bg-white">
              <tr class="border-b border-gray-100">
                <th class="w-10 px-3 py-2">
                  <Checkbox
                    :checked="allSelected ? true : partialSelected ? 'indeterminate' : false"
                    @update:checked="onToggleAll"
                  />
                </th>
                <th
                  v-for="col in columns"
                  :key="col.label"
                  class="whitespace-nowrap px-3 py-2 text-left font-medium text-muted-foreground"
                >
                  <button v-if="col.field" class="inline-flex items-center gap-1" @click="toggleSort(col.field)">
                    <span>{{ col.label }}</span>
                    <SortIcon :active="sortField === col.field" :order="sortOrder" />
                  </button>
                  <template v-else>{{ col.label }}</template>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="loading">
                <td :colspan="7" class="py-16 text-center text-muted-foreground">
                  <Loader2 class="mx-auto h-6 w-6 animate-spin opacity-60" />
                </td>
              </tr>
              <tr v-else-if="rows.length === 0">
                <td :colspan="7" class="py-20 text-center text-muted-foreground">
                  <EmptyState
                    :title="t.modelsPage.noData"
                    :description="hasFilters ? t.modelsPage.noDataDescFiltered : t.modelsPage.noDataDescDefault"
                  />
                </td>
              </tr>
              <template v-else>
                <tr
                  v-for="(r, idx) in rows"
                  :key="r.id"
                  :class="
                    cn(
                      'border-b border-gray-100',
                      idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/30',
                      selected.has(r.id) && 'bg-gray-100/70',
                    )
                  "
                >
                  <td class="w-10 px-3 py-2">
                    <Checkbox :checked="selected.has(r.id)" @update:checked="(c) => onToggleOne(r.id, c === true)" />
                  </td>
                  <td class="px-3 py-2 font-medium">{{ r.name }}</td>
                  <td class="px-3 py-2">{{ r.model_name || "-" }}</td>
                  <td class="max-w-[280px] truncate px-3 py-2" :title="r.api_base || '-'">
                    {{ r.api_base || "-" }}
                  </td>
                  <td class="max-w-[180px] truncate px-3 py-2 text-muted-foreground" :title="r.api_key || '-'">
                    {{ r.api_key || "-" }}
                  </td>
                  <td class="px-3 py-2">{{ Number(r.token_count || 0).toLocaleString("en-US") }}</td>
                  <td class="whitespace-nowrap px-3 py-2 text-muted-foreground">{{ tsText(r.create_time) }}</td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <div class="shrink-0 border-t border-gray-100 bg-white px-4 py-2">
          <div class="flex items-center justify-between">
            <span class="text-xs text-muted-foreground">
              {{ t.modelsPage.total.replace("{total}", String(total)) }}
            </span>
            <div class="flex items-center gap-2">
              <Select
                :model-value="String(size)"
                @update:model-value="
                  (v) => {
                    size = Number(v);
                    page = 1;
                  }
                "
              >
                <SelectTrigger size="sm" class="h-7 w-[84px] text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="n in PAGE_SIZE_OPTIONS" :key="n" :value="String(n)">{{ n }}</SelectItem>
                </SelectContent>
              </Select>
              <div class="flex items-center gap-1">
                <Button variant="outline" size="icon" class="h-7 w-7" :disabled="safePage <= 1" @click="page = 1">
                  <ChevronsLeft class="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  class="h-7 w-7"
                  :disabled="safePage <= 1"
                  @click="page = Math.max(1, page - 1)"
                >
                  <ChevronLeft class="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  class="h-7 w-7"
                  :disabled="safePage >= pages"
                  @click="page = Math.min(pages, page + 1)"
                >
                  <ChevronRight class="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  class="h-7 w-7"
                  :disabled="safePage >= pages"
                  @click="page = pages"
                >
                  <ChevronsRight class="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
      </div>

      <div
        v-if="selected.size > 0"
        class="fixed bottom-6 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 shadow-sm"
      >
        <span class="text-xs font-medium text-foreground">{{ selected.size }} {{ t.modelsPage.itemsSelected }}</span>
        <div class="h-4 w-px bg-border" />
        <Button
          variant="ghost"
          size="icon"
          class="h-7 w-7 text-red-600 hover:bg-red-50 hover:text-red-700 dark:hover:bg-red-950/20"
          @click="handleBatchDelete()"
        >
          <Trash2 class="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>

    <Sheet :open="createOpen" @update:open="createOpen = $event">
      <SheetContent side="right" class="w-full gap-0 p-0 sm:max-w-[680px]">
        <SheetHeader class="border-b border-border pr-12">
          <SheetTitle>{{ t.modelsPage.createTitle }}</SheetTitle>
        </SheetHeader>
        <CreateModelPanel compact :on-cancel="onPanelCancel" :on-success="onPanelSuccess" />
      </SheetContent>
    </Sheet>
  </div>
</template>
