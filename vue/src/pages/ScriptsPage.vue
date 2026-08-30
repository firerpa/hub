<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useHashRouter } from "@/lib/hash-router";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Code2,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Share2,
  Trash2,
  User,
  X,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { CreateScriptPanel } from "@/components/scripts/create-script-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState } from "@/components/ui/empty-state";
import { FeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { DateTimeRangePicker } from "@/components/ui/date-range-picker";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SortIcon } from "@/components/ui/sort-icon";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type SortOrder = "asc" | "desc";
type ScriptSortField = "id" | "name" | "type" | "create_time";

type ScriptItem = {
  id: number;
  name: string;
  type?: number;
  owner?: { id?: number; name?: string; username?: string } | string;
  owner_name?: string;
  create_time?: number;
  created?: number;
};

type UserBrief = {
  id: number;
  name?: string;
  username?: string;
  contact?: string;
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

function getOwnerName(item: ScriptItem) {
  if (typeof item.owner === "string") return item.owner || "-";
  if (item.owner?.name) return item.owner.name;
  if (item.owner?.username) return item.owner.username;
  if (item.owner_name) return item.owner_name;
  return "-";
}

function scriptTypeText(v: number | undefined, tt: any) {
  return Number(v || 0) === 1 ? tt.scriptsPage.typePrompt : tt.scriptsPage.typeCode;
}

const router = useHashRouter();
const { t } = useTranslation();
const loading = ref(false);
const refreshTick = ref(0);

const search = ref("");
const deferredSearch = search;
const typeFilter = ref<"all" | "code" | "prompt">("all");
const startAfter = ref("");
const endBefore = ref("");

const sortField = ref<ScriptSortField>("id");
const sortOrder = ref<SortOrder>("desc");

const page = ref(1);
const size = ref(100);
const total = ref(0);
const rows = ref<ScriptItem[]>([]);
const selected = ref<Set<number>>(new Set());

const tip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);
const createOpen = ref(false);

const shareOpen = ref(false);
const shareLoading = ref(false);
const usersLoading = ref(false);
const users = ref<UserBrief[]>([]);
const userSearch = ref("");
const deferredUserSearch = userSearch;

const pages = computed(() => Math.max(1, Math.ceil(total.value / size.value)));
const safePage = computed(() => Math.min(page.value, pages.value));
const hasFilters = computed(() => Boolean(search.value || typeFilter.value !== "all" || startAfter.value || endBefore.value));

const showTip = (text: string, variant: FeedbackTipVariant = "error") => {
  tip.value = { id: Date.now() + Math.random(), text, variant };
};

const filterQuery = computed(() => {
  const filter: Array<{ field: string; op: string; value: unknown }> = [];
  if (deferredSearch.value.trim()) {
    filter.push({ field: "name", op: "like", value: deferredSearch.value.trim() });
  }
  if (typeFilter.value !== "all") {
    filter.push({ field: "type", op: "eq", value: typeFilter.value === "prompt" ? 1 : 0 });
  }
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

watch(
  [safePage, size, sortField, sortOrder, filterQuery, refreshTick],
  async (_vals, _prev, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    loading.value = true;
    try {
      const qs = new URLSearchParams({
        page: String(Math.max(1, safePage.value)),
        size: String(size.value),
        sort: sortField.value,
        order: sortOrder.value,
      });
      if (filterQuery.value) qs.set("filter", filterQuery.value);
      const res = await apiRequest<any>(`/api/v1/script?${qs.toString()}`, { cache: "no-store" });
      if (cancelled) return;
      const payload = res.data || {};
      const list = Array.isArray(payload.data) ? payload.data : [];
      const mapped: ScriptItem[] = list.map((item: any): ScriptItem => ({
        id: Number(item?.id ?? 0),
        name: String(item?.name || "-"),
        type: Number(item?.type ?? 0),
        owner: item?.owner,
        owner_name: item?.owner_name,
        create_time: Number(item?.create_time ?? item?.created ?? 0),
        created: Number(item?.created ?? item?.create_time ?? 0),
      }));
      rows.value = mapped;
      total.value = Number(payload.total ?? mapped.length);
      const valid = new Set(mapped.map((i) => i.id));
      selected.value = new Set(Array.from(selected.value).filter((id) => valid.has(id)));
    } catch (error) {
      if (cancelled) return;
      rows.value = [];
      total.value = 0;
      selected.value = new Set();
      showTip(formatApiError(error, t.value.scriptsPage.loadFailed));
    } finally {
      if (!cancelled) loading.value = false;
    }
  },
  { immediate: true },
);

watch([shareOpen, deferredUserSearch], async (_vals, _prev, onCleanup) => {
  if (!shareOpen.value) return;
  let cancelled = false;
  onCleanup(() => {
    cancelled = true;
  });
  usersLoading.value = true;
  try {
    const qs = new URLSearchParams({
      page: "1",
      size: "20",
      sort: "id",
      order: "desc",
    });
    if (deferredUserSearch.value.trim()) {
      qs.set("filter", JSON.stringify([{ field: "name", op: "like", value: deferredUserSearch.value.trim() }]));
    }
    const res = await apiRequest<any>(`/api/v1/user?${qs.toString()}`, { cache: "no-store" });
    if (cancelled) return;
    const payload = res.data || {};
    const list = Array.isArray(payload.data) ? payload.data : [];
    users.value = list.map((u: any) => ({
      id: Number(u?.id ?? 0),
      name: String(u?.name || ""),
      username: String(u?.username || ""),
      contact: String(u?.contact || ""),
    }));
  } catch (error) {
    if (cancelled) return;
    users.value = [];
    showTip(formatApiError(error, t.value.scriptsPage.loadUsersFailed));
  } finally {
    if (!cancelled) usersLoading.value = false;
  }
});

const onToggleAll = (checked: boolean) => {
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

const selectedCount = computed(() => selected.value.size);
const allSelected = computed(() => rows.value.length > 0 && rows.value.every((r) => selected.value.has(r.id)));
const partialSelected = computed(() => rows.value.some((r) => selected.value.has(r.id)) && !allSelected.value);

const clearFilters = () => {
  search.value = "";
  typeFilter.value = "all";
  startAfter.value = "";
  endBefore.value = "";
  page.value = 1;
};

const toggleSort = (field: ScriptSortField) => {
  const nextOrder: SortOrder = sortField.value === field ? (sortOrder.value === "asc" ? "desc" : "asc") : "asc";
  sortField.value = field;
  sortOrder.value = nextOrder;
  page.value = 1;
};

const onSearchInput = (v: string) => {
  search.value = v;
  page.value = 1;
};

const onTypeFilterChange = (v: string) => {
  typeFilter.value = v as "all" | "code" | "prompt";
  page.value = 1;
};

const onStartAfterChange = (v: string) => {
  startAfter.value = v;
  page.value = 1;
};

const onEndBeforeChange = (v: string) => {
  endBefore.value = v;
  page.value = 1;
};

const onSizeChange = (v: string) => {
  size.value = Number(v);
  page.value = 1;
};

const onShareOpenChange = (open: boolean) => {
  shareOpen.value = open;
  if (!open) userSearch.value = "";
};

const pageNumbers = computed(() => {
  const result: number[] = [];
  const len = Math.min(5, pages.value);
  for (let i = 0; i < len; i++) {
    let n = 1;
    if (pages.value <= 5) n = i + 1;
    else if (safePage.value <= 3) n = i + 1;
    else if (safePage.value >= pages.value - 2) n = pages.value - 4 + i;
    else n = safePage.value - 2 + i;
    result.push(n);
  }
  return result;
});

const handleBatchDelete = async () => {
  const ids = Array.from(selected.value);
  if (!ids.length) return;
  loading.value = true;
  try {
    const results = await Promise.allSettled(ids.map((id) => apiRequest(`/api/v1/script/${id}`, { method: "DELETE" })));
    const ok = results.filter((r) => r.status === "fulfilled").length;
    selected.value = new Set();
    if (ok === ids.length) showTip(t.value.scriptsPage.deleteSuccess.replace("{n}", String(ok)), "success");
    else showTip(t.value.scriptsPage.deleteFailed);
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.deleteFailed));
  } finally {
    refreshTick.value = refreshTick.value + 1;
    loading.value = false;
  }
};

const handleShareToUser = async (uid: number) => {
  const ids = Array.from(selected.value);
  if (!uid || !ids.length) return;
  shareLoading.value = true;
  try {
    for (const id of ids) {
      await apiRequest(`/api/v1/script/${id}/alloc`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ id: String(uid) }).toString(),
      });
    }
    shareOpen.value = false;
    userSearch.value = "";
    showTip(t.value.scriptsPage.shareSuccess.replace("{n}", String(ids.length)), "success");
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.shareFailed));
  } finally {
    shareLoading.value = false;
  }
};

const onCreateCancel = () => {
  createOpen.value = false;
};

const onCreateSuccess = () => {
  createOpen.value = false;
  refreshTick.value = refreshTick.value + 1;
  showTip(t.value.scriptsPage.createSuccess, "success");
};
</script>

<template>
  <div class="flex h-screen bg-[#f5f5f7]">
    <Sidebar />
    <div class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <div class="flex h-14 shrink-0 items-center border-b border-gray-100 bg-white px-5">
        <div class="flex w-full min-w-0 items-center justify-between gap-3">
          <div class="min-w-0">
            <h1 class="text-base font-semibold leading-tight">{{ t.scriptsPage.title }}</h1>
          </div>
          <div class="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <FeedbackTip
              v-if="tip"
              :key="tip.id"
              :message="tip.text"
              :variant="tip.variant"
              compact
              truncate
              class-name="h-7 max-w-[min(100%,360px)] px-2 py-0"
            />
            <Button size="sm" class="h-8 gap-1.5 text-xs" @click="createOpen = true">
              <Plus class="h-3.5 w-3.5" />
              {{ t.scriptsPage.createScript }}
            </Button>
            <Button
              variant="outline"
              size="sm"
              class="h-8 gap-1.5 text-xs"
              :disabled="loading"
              @click="refreshTick = refreshTick + 1"
            >
              <RefreshCw :class="cn('h-3.5 w-3.5', loading && 'animate-spin')" />
              {{ t.scriptsPage.refresh }}
            </Button>
          </div>
        </div>
      </div>

      <div class="flex min-h-0 flex-1 flex-col overflow-hidden p-3">
      <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
        <div class="shrink-0 border-b border-gray-100 px-4 py-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-semibold text-gray-800">{{ t.scriptsPage.allScripts }}</h2>
              <Badge variant="secondary" class="h-5 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 tabular-nums">
                {{ total.toLocaleString() }}
              </Badge>
            </div>

            <div class="flex flex-wrap items-center gap-2">
              <div class="relative">
                <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  :model-value="search"
                  @update:model-value="onSearchInput"
                  :placeholder="t.scriptsPage.searchPlaceholder"
                  class="h-8 w-[200px] border-gray-200 pl-8 text-xs text-gray-600 placeholder:text-gray-400"
                />
                <button
                  v-if="search"
                  type="button"
                  @click="
                    search = '';
                    page = 1;
                  "
                  class="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X class="h-3 w-3" />
                </button>
              </div>

              <Select :model-value="typeFilter" @update:model-value="onTypeFilterChange">
                <SelectTrigger size="sm" class="h-8 w-32 border-gray-200 text-xs text-gray-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{{ t.scriptsPage.typeAll }}</SelectItem>
                  <SelectItem value="code">{{ t.scriptsPage.typeCode }}</SelectItem>
                  <SelectItem value="prompt">{{ t.scriptsPage.typePrompt }}</SelectItem>
                </SelectContent>
              </Select>

              <DateTimeRangePicker
                :start="startAfter"
                :end="endBefore"
                @update:start="onStartAfterChange"
                @update:end="onEndBeforeChange"
              />

              <Button
                v-if="hasFilters"
                variant="ghost"
                size="sm"
                class="h-8 gap-1 text-xs text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                @click="clearFilters"
              >
                <X class="h-3.5 w-3.5" />
                {{ t.scriptsPage.clearFilters }}
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
                    aria-label="select all scripts"
                  />
                </th>
                <th class="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  <button class="inline-flex items-center gap-1" @click="toggleSort('id')">
                    <span>ID</span>
                    <SortIcon :active="sortField === 'id'" :order="sortOrder" />
                  </button>
                </th>
                <th class="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  <button class="inline-flex items-center gap-1" @click="toggleSort('name')">
                    <span>{{ t.scriptsPage.colName }}</span>
                    <SortIcon :active="sortField === 'name'" :order="sortOrder" />
                  </button>
                </th>
                <th class="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  <button class="inline-flex items-center gap-1" @click="toggleSort('type')">
                    <span>{{ t.scriptsPage.colMeta }}</span>
                    <SortIcon :active="sortField === 'type'" :order="sortOrder" />
                  </button>
                </th>
                <th class="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  {{ t.scriptsPage.colOwner }}
                </th>
                <th class="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  <button class="inline-flex items-center gap-1" @click="toggleSort('create_time')">
                    <span>{{ t.scriptsPage.colCreated }}</span>
                    <SortIcon :active="sortField === 'create_time'" :order="sortOrder" />
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="loading">
                <td :colspan="6" class="py-16 text-center text-muted-foreground">
                  <Loader2 class="mx-auto h-6 w-6 animate-spin opacity-60" />
                </td>
              </tr>
              <tr v-else-if="rows.length === 0">
                <td :colspan="6" class="py-20 text-center text-muted-foreground">
                  <EmptyState
                    :title="t.scriptsPage.noData"
                    :description="hasFilters ? t.scriptsPage.noDataDescFiltered : t.scriptsPage.noDataDescDefault"
                  />
                </td>
              </tr>
              <template v-else>
                <tr
                  v-for="(item, idx) in rows"
                  :key="item.id"
                  :class="
                    cn(
                      'cursor-pointer border-b border-gray-100',
                      idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/30',
                      selected.has(item.id) && 'bg-gray-100/70',
                    )
                  "
                  @click="router.push(`/scripts/${item.id}`)"
                >
                <td class="w-10 px-3 py-2" @click.stop>
                  <Checkbox :checked="selected.has(item.id)" @update:checked="onToggleOne(item.id, $event)" />
                </td>
                <td class="whitespace-nowrap px-3 py-2">
                  <span class="font-semibold text-foreground">#</span>
                  <span class="ml-0.5 font-mono text-muted-foreground">{{ item.id }}</span>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center gap-2">
                    <span class="inline-flex h-5 w-5 items-center justify-center rounded bg-blue-500/10 text-blue-600 dark:text-blue-400">
                      <Code2 class="h-3.5 w-3.5" />
                    </span>
                    <div class="min-w-0">
                      <p class="truncate font-medium text-foreground">{{ item.name }}</p>
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center gap-1.5">
                    <span
                      :class="
                        cn(
                          'inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium',
                          Number(item.type || 0) === 1
                            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                            : 'bg-sky-500/10 text-sky-600 dark:text-sky-400',
                        )
                      "
                    >
                      {{ scriptTypeText(item.type, t) }}
                    </span>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center gap-1.5 text-muted-foreground">
                    <User class="h-3.5 w-3.5" />
                    <span class="truncate">{{ getOwnerName(item) }}</span>
                  </div>
                </td>
                <td class="whitespace-nowrap px-3 py-2 text-muted-foreground">{{ tsText(item.create_time ?? item.created) }}</td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <div class="shrink-0 border-t border-gray-100 bg-white px-4 py-2">
          <div class="flex items-center justify-between">
            <div class="text-xs text-muted-foreground">
              {{ t.scriptsPage.total.replace("{total}", String(total)) }}
            </div>
            <div class="flex items-center gap-2">
              <Select :model-value="String(size)" @update:model-value="onSizeChange">
                <SelectTrigger size="sm" class="h-7 w-[84px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="n in PAGE_SIZE_OPTIONS" :key="n" :value="String(n)">
                    {{ n }}
                  </SelectItem>
                </SelectContent>
              </Select>
              <div class="flex items-center gap-1">
                <Button variant="outline" size="icon" class="h-7 w-7" :disabled="safePage <= 1" @click="page = 1">
                  <ChevronsLeft class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" class="h-7 w-7" :disabled="safePage <= 1" @click="page = Math.max(1, page - 1)">
                  <ChevronLeft class="h-3.5 w-3.5" />
                </Button>
                <div class="flex items-center gap-0.5">
                  <Button
                    v-for="n in pageNumbers"
                    :key="n"
                    :variant="safePage === n ? 'default' : 'outline'"
                    size="sm"
                    class="h-7 w-7 p-0 text-xs"
                    @click="page = n"
                  >
                    {{ n }}
                  </Button>
                </div>
                <Button variant="outline" size="icon" class="h-7 w-7" :disabled="safePage >= pages" @click="page = Math.min(pages, page + 1)">
                  <ChevronRight class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" class="h-7 w-7" :disabled="safePage >= pages" @click="page = pages">
                  <ChevronsRight class="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
      </div>

      <div
        v-if="selectedCount > 0"
        class="fixed bottom-6 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 shadow-sm"
      >
        <span class="text-xs font-medium text-foreground">{{ selectedCount }} {{ t.scriptsPage.itemsSelected }}</span>
        <div class="h-4 w-px bg-border" />
        <Popover :open="shareOpen" @update:open="onShareOpenChange">
          <PopoverTrigger as-child>
            <Button
              variant="ghost"
              size="icon"
              class="h-7 w-7 text-blue-600 hover:bg-blue-50 hover:text-blue-700 dark:hover:bg-blue-950/20"
              :disabled="shareLoading"
            >
              <Loader2 v-if="shareLoading" class="h-3.5 w-3.5 animate-spin" />
              <Share2 v-else class="h-3.5 w-3.5" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="center" class="w-[260px] p-0">
            <div class="p-2">
              <div class="relative">
                <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  v-model="userSearch"
                  :placeholder="t.scriptsPage.searchUserPlaceholder"
                  class="h-8 pl-8 text-xs"
                  autofocus
                />
              </div>
            </div>
            <div class="border-t border-border" />
            <div class="max-h-[240px] overflow-y-auto py-1">
              <div v-if="usersLoading" class="flex items-center justify-center gap-2 px-4 py-8 text-xs text-muted-foreground">
                <Loader2 class="h-3.5 w-3.5 animate-spin" />
                {{ t.common.loading }}
              </div>
              <div v-else-if="users.length === 0" class="px-4 py-8 text-center text-xs text-muted-foreground">{{ t.scriptsPage.noUsers }}</div>
              <template v-else>
                <button
                  v-for="u in users"
                  :key="u.id"
                  type="button"
                  class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/60"
                  @click="void handleShareToUser(u.id)"
                  :disabled="shareLoading"
                >
                  <span class="h-2.5 w-2.5 shrink-0 rounded-sm bg-blue-500/80" />
                  <span class="flex-1 truncate">{{ u.name || u.username || "-" }}</span>
                  <span class="text-xs text-muted-foreground tabular-nums">{{ u.contact || "-" }}</span>
                </button>
              </template>
            </div>
          </PopoverContent>
        </Popover>
        <Button
          variant="ghost"
          size="icon"
          class="h-7 w-7 text-red-600 hover:bg-red-50 hover:text-red-700 dark:hover:bg-red-950/20"
          @click="void handleBatchDelete()"
        >
          <Trash2 class="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>

    <Sheet :open="createOpen" @update:open="createOpen = $event">
      <SheetContent side="right" class="w-full gap-0 p-0 sm:max-w-[680px]">
        <SheetHeader class="border-b border-border pr-12">
          <SheetTitle>{{ t.scriptsPage.createTitle }}</SheetTitle>
        </SheetHeader>
        <CreateScriptPanel
          compact
          :open="createOpen"
          :on-cancel="onCreateCancel"
          :on-success="onCreateSuccess"
        />
      </SheetContent>
    </Sheet>
  </div>
</template>
