<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ArrowUpDown, CalendarClock, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, ChevronsLeft, ChevronsRight, Download, FileCode2, FileX2, Gauge, GitBranch, History, Info, Loader2, Monitor, Pause, Play, RefreshCw, RotateCcw, SlidersHorizontal, Square, TimerReset, User, XCircle } from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { showFeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip as UITooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { apiRequest, formatApiError } from "@/lib/api";
import { matchHashPath, useHashPathname, useHashRouter } from "@/lib/hash-router";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type JobState = "running" | "paused" | "stopped";
type ExecState = "pending" | "issued" | "running" | "success" | "failed" | "timeout" | "revoked";
type SortOrder = "asc" | "desc";
type DeviceSortField = "domain" | "issued" | "success" | "failed" | "rate" | "state" | "version";
type ExecSortField = "execution" | "device" | "state" | "started" | "duration" | "reason";

type JobDetail = {
  id: number;
  name: string;
  state: JobState;
  description?: string;
  config?: {
    retries?: number;
    time_limit?: number;
    soft_time_limit?: number;
    ignore_result?: boolean;
    mutex?: string | null;
  };
  owner?: { id: number; name: string };
  group?: { id?: number; name?: string; color?: string | null } | null;
  script?: {
    id: number;
    version: string;
    parent?: { id: number; name: string; params?: unknown };
    params?: unknown;
  };
  mode?: string;
  param_source?: string;
  params?: unknown;
  interval?: number;
  crontab?: string;
  count?: number;
  priority?: number;
  create_time?: number;
  start_time?: number;
  stop_time?: number;
  created?: number;
  started?: number;
  stopped?: number;
  issued?: number;
  success?: number;
  failed?: number;
  timeout?: number;
  revoked?: number;
};

type JobDeviceRow = {
  state?: string;
  error?: string;
  binding_state?: string;
  create_time?: number;
  leave_time?: number;
  device?: {
    domain?: string;
    state?: string | number;
    disk_percent?: number;
    mem_percent?: number;
    version?: string;
    brand?: string;
    model?: string;
  };
  domain?: string;
  issued?: number;
  success?: number;
  failed?: number;
  timeout?: number;
};

type JobExecRow = {
  id?: number | string;
  task_id?: string;
  state?: ExecState | string;
  reason?: string;
  elapsed_time?: number;
  start_time?: number;
  finish_time?: number;
  create_time?: number;
  started?: number;
  finished?: number;
  device?: { domain?: string; state?: string | number };
  params?: unknown;
  result?: unknown;
  exception?: unknown;
  traceback?: string;
  resources?: Array<{
    id?: number;
    type?: string;
    name?: string;
    data?: any;
    create_time?: number;
  }>;
  job?: { name?: string; id?: number };
  script?: { version?: string; parent?: { name?: string } };
};

type ScriptVersionOption = {
  id: number;
  version: string;
  create_time?: number;
};

function toTsText(ts?: number) {
  const n = Number(ts || 0);
  if (!Number.isFinite(n) || n <= 0) return "-";
  return new Date(n * 1000).toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function toTsTextFlexible(ts?: number | string | null) {
  const n = Number(ts || 0);
  if (!Number.isFinite(n) || n <= 0) return "-";
  const sec = n > 1e12 ? Math.floor(n / 1000) : n > 1e10 ? Math.floor(n / 1000) : Math.floor(n);
  return toTsText(sec);
}

function toDuration(started?: number, finished?: number) {
  const s = Number(started || 0);
  const f = Number(finished || 0);
  if (!s) return "-";
  const end = f > s ? f : Math.floor(Date.now() / 1000);
  const sec = Math.max(0, end - s);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

function toElapsedDuration(elapsed?: number) {
  const sec = Number(elapsed || 0);
  if (!Number.isFinite(sec) || sec <= 0) return "-";
  return `${sec.toFixed(2)}s`;
}

function num(v: unknown) {
  const n = Number(v || 0);
  return Number.isFinite(n) ? n : 0;
}

function percent(a: number, b: number) {
  if (b <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((a / b) * 100)));
}

function fmtInt(n: number) {
  return Number(n || 0).toLocaleString("en-US");
}

function jobTs(detail: JobDetail | null, key: "create" | "start" | "stop") {
  if (!detail) return 0;
  if (key === "create") return num(detail.create_time ?? detail.created);
  if (key === "start") return num(detail.start_time ?? detail.started);
  return num(detail.stop_time ?? detail.stopped);
}

function execStartTs(row: JobExecRow) {
  return num(row.start_time ?? row.started);
}

function execFinishTs(row: JobExecRow) {
  return num(row.finish_time ?? row.finished);
}

function stateBadge(state: string | number | undefined) {
  if (state === 1 || state === "online") return "online";
  if (state === 0 || state === "offline") return "offline";
  if (state === "pending") return "pending";
  return "pending";
}

function executionStateTone(state: string | undefined) {
  const s = String(state || "").toLowerCase();
  if (s === "success") return "green";
  if (s === "running" || s === "issued") return "blue";
  if (s === "lost") return "orange";
  if (s === "failed" || s === "timeout") return "red";
  if (s === "revoked") return "slate";
  return "slate";
}

function isRemovedDevice(row: JobDeviceRow) {
  return String(row.binding_state || "").toLowerCase() === "removed";
}

function deviceJobStateTone(state: string | undefined) {
  const s = String(state || "").toLowerCase();
  if (s === "prepared") return "border-emerald-500/30 bg-emerald-500/15";
  if (s === "initial") return "border-sky-500/30 bg-sky-500/15";
  if (s === "script/load_failed") return "border-red-500/30 bg-red-500/15";
  return "border-amber-500/30 bg-amber-500/15";
}

function deviceSortToApi(sortField: DeviceSortField) {
  if (sortField === "domain") return "domain";
  if (sortField === "issued") return "issued";
  if (sortField === "success") return "success";
  if (sortField === "failed") return "failed";
  if (sortField === "rate") return "success";
  if (sortField === "state") return "state";
  return "version";
}

function execSortToApi(sortField: ExecSortField) {
  if (sortField === "execution") return "task_id";
  if (sortField === "device") return "device";
  if (sortField === "state") return "state";
  if (sortField === "started") return "start_time";
  if (sortField === "duration") return "elapsed_time";
  return "reason";
}

type ParamType = "boolean" | "integer" | "float" | "list" | "object" | "string";

function normalizeParamType(raw: unknown): ParamType {
  const key = String(raw || "").trim().toLowerCase();
  if (key === "bool" || key === "boolean") return "boolean";
  if (key === "int" || key === "integer") return "integer";
  if (key === "float" || key === "double" || key === "number") return "float";
  if (key === "array" || key === "list") return "list";
  if (key === "object" || key === "dict" || key === "map" || key === "json") return "object";
  return "string";
}

function inferParamType(value: unknown): ParamType {
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "float";
  if (Array.isArray(value)) return "list";
  if (value && typeof value === "object") return "object";
  return "string";
}

function parseMaybeJson(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const text = raw.trim();
  if (!text) return raw;
  if ((text.startsWith("{") && text.endsWith("}")) || (text.startsWith("[") && text.endsWith("]"))) {
    try {
      return JSON.parse(text);
    } catch {
      return raw;
    }
  }
  return raw;
}

function parseScriptParamSchema(raw: unknown): Array<{ name: string; type?: string; description?: string }> {
  const parsed = parseMaybeJson(raw);
  if (!parsed) return [];
  if (Array.isArray(parsed)) {
    return parsed
      .map((it) => ({
        name: String((it as any)?.name || ""),
        type: (it as any)?.type ? String((it as any).type) : undefined,
        description: (it as any)?.description ? String((it as any).description) : undefined,
      }))
      .filter((it) => it.name);
  }
  if (parsed && typeof parsed === "object") {
    return Object.keys(parsed as Record<string, unknown>).map((name) => ({ name }));
  }
  return [];
}

function normalizeJobState(raw: unknown): JobState {
  const value = String(raw || "").toLowerCase();
  if (value === "paused") return "paused";
  if (value === "stopped" || value === "stop") return "stopped";
  return "running";
}

function stateToneClass(tone: string) {
  return tone === "green"
    ? "bg-emerald-500/8 text-emerald-700 dark:text-emerald-300"
    : tone === "red"
      ? "bg-red-500/8 text-red-700 dark:text-red-300"
      : tone === "yellow"
        ? "bg-yellow-500/10 text-yellow-700 dark:text-yellow-300"
        : tone === "purple"
          ? "bg-violet-500/10 text-violet-700 dark:text-violet-300"
          : "bg-muted/50 text-foreground";
}

function execRowStateTone(state: string | undefined) {
  const s = String(state || "").toLowerCase();
  if (s === "success") return "text-emerald-600 bg-emerald-500/10";
  if (s === "running" || s === "issued") return "text-blue-600 bg-blue-500/10";
  if (s === "pending") return "text-slate-600 bg-slate-500/10";
  if (s === "lost") return "text-amber-700 bg-amber-500/10";
  if (s === "failed" || s === "timeout") return "text-red-600 bg-red-500/10";
  if (s === "revoked") return "text-violet-600 bg-violet-500/10";
  return "text-muted-foreground bg-muted";
}

function execRowStateLabel(tr: any, state: string | undefined) {
  const s = String(state || "").toLowerCase();
  if (s === "pending") return tr.jobDetailPage.execStatePending;
  if (s === "issued") return tr.jobDetailPage.execStateIssued;
  if (s === "running") return tr.jobDetailPage.execStateRunning;
  if (s === "success") return tr.jobDetailPage.execStateSuccess;
  if (s === "failed") return tr.jobDetailPage.execStateFailed;
  if (s === "timeout") return tr.jobDetailPage.execStateTimeout;
  if (s === "lost") return tr.jobDetailPage.execStateLost;
  if (s === "revoked") return tr.jobDetailPage.execStateRevoked;
  return String(state || "-");
}

function jsonBlockText(value: unknown) {
  const parsed = parseMaybeJson(value);
  return parsed == null || parsed === "" ? "" : typeof parsed === "string" ? parsed : JSON.stringify(parsed, null, 2);
}

function logsBlockText(detail: JobExecRow) {
  const logs = Array.isArray(detail.resources)
    ? detail.resources.filter((r) => String(r.type || "").toLowerCase() === "log")
    : [];
  if (!logs.length) return "";
  return logs
    .map((r) => {
      const rawTs = r?.create_time ?? r?.data?.timestamp ?? r?.data?.ts ?? r?.data?.time;
      const tsText = toTsTextFlexible(rawTs);
      const msg = r?.data?.message ?? r?.data;
      const msgText = typeof msg === "string"
        ? msg
        : msg == null
          ? ""
          : JSON.stringify(msg, null, 2);
      if (!msgText) return "";
      return tsText !== "-" ? `[${tsText}] ${msgText}` : msgText;
    })
    .filter(Boolean)
    .join("\n");
}

function fileResources(detail: JobExecRow | null) {
  if (!detail || !Array.isArray(detail.resources)) return [] as NonNullable<JobExecRow["resources"]>;
  return detail.resources.filter((r) => {
    const t = String(r.type || "").toLowerCase();
    return t === "file" || t === "image";
  });
}

function fileHref(domain: string, r: NonNullable<JobExecRow["resources"]>[number]) {
  const rawPath = String(r?.data?.path || r?.data?.url || "");
  const path = rawPath.replace(/^\/+/, "");
  return domain && path ? `/d/${encodeURIComponent(domain)}/fs/${path}` : "";
}

function filePathText(r: NonNullable<JobExecRow["resources"]>[number]) {
  const rawPath = String(r?.data?.path || r?.data?.url || "");
  return rawPath.replace(/^\/+/, "");
}

function dataResources(detail: JobExecRow | null) {
  if (!detail || !Array.isArray(detail.resources)) return [] as unknown[];
  return detail.resources.filter((r) => String(r.type || "").toLowerCase() === "data").map((r) => r.data);
}

function pagerVisiblePages(page: number, size: number, total: number) {
  const pages = Math.max(1, Math.ceil(total / size));
  return Array.from({ length: Math.min(5, pages) }, (_, i) => {
    if (pages <= 5) return i + 1;
    if (page <= 3) return i + 1;
    if (page >= pages - 2) return pages - 4 + i;
    return page - 2 + i;
  });
}

const { t } = useTranslation();
const router = useHashRouter();
const hashPathname = useHashPathname();
const hashId = computed(() => matchHashPath(hashPathname.value, /^\/jobs\/([^/]+)$/));
const jobId = computed(() => Number(hashId.value || 0));

const tab = ref("devices");
const loading = ref(true);
const refreshTick = ref(0);

const detail = ref<JobDetail | null>(null);

const devices = ref<JobDeviceRow[]>([]);
const deviceTotal = ref(0);
const devicePage = ref(1);
const deviceSize = ref(100);
const deviceLoading = ref(false);
const overviewAll = ref<JobDeviceRow[]>([]);
const overviewLoading = ref(false);
const overviewPage = ref(1);
const overviewPageSize = ref(30);

const execRows = ref<JobExecRow[]>([]);
const execTotal = ref(0);
const execPage = ref(1);
const execSize = ref(100);
const execLoading = ref(false);
const execKeyword = ref("");
const execState = ref("all");
const stopConfirmOpen = ref(false);
const stopping = ref(false);
const stateUpdating = ref<"continue" | "pause" | null>(null);
const switchVersionOpen = ref(false);
const scriptVersions = ref<ScriptVersionOption[]>([]);
const scriptVersionsLoading = ref(false);
const switchingVersion = ref(false);
const selectedScriptVersionId = ref<string>("");
const switchVersionTip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);
const deviceSortField = ref<DeviceSortField>("domain");
const deviceSortOrder = ref<SortOrder>("asc");
const execSortField = ref<ExecSortField>("started");
const execSortOrder = ref<SortOrder>("desc");
const execDetailOpen = ref(false);
const execDetailLoading = ref(false);
const execDetail = ref<JobExecRow | null>(null);
const execDetailTab = ref("overview");

const showTip = (text: string, variant: FeedbackTipVariant = "error") => {
  showFeedbackTip(text, variant);
};

const loadDetail = async () => {
  if (!jobId.value) {
    loading.value = false;
    return;
  }
  const initial = !detail.value;
  if (initial) loading.value = true;
  try {
    const res = await apiRequest<any>(`/api/v1/job/${jobId.value}`, { cache: "no-store" });
    const raw = (res.data || {}) as JobDetail;
    detail.value = {
      ...raw,
      state: normalizeJobState(raw.state),
    };
  } catch (error) {
    showTip(formatApiError(error, t.value.jobDetailPage.loadDetailFailed));
  } finally {
    if (initial) loading.value = false;
  }
};

const loadDevices = async (
  page = devicePage.value,
  size = deviceSize.value,
  sortField = deviceSortField.value,
  sortOrder = deviceSortOrder.value,
) => {
  if (!jobId.value) return;
  deviceLoading.value = true;
  try {
    const qs = new URLSearchParams({
      page: String(Math.max(1, page)),
      size: String(size),
      sort: deviceSortToApi(sortField),
      order: sortOrder,
    });
    const res = await apiRequest<any>(`/api/v1/job/${jobId.value}/device?${qs.toString()}`, { cache: "no-store" });
    const payload = res.data || {};
    const list = Array.isArray(payload.data) ? payload.data : [];
    devices.value = list as JobDeviceRow[];
    deviceTotal.value = num(payload.total);
    devicePage.value = page;
    deviceSize.value = size;
  } catch (error) {
    devices.value = [];
    deviceTotal.value = 0;
    showTip(formatApiError(error, t.value.jobDetailPage.loadDevicesFailed));
  } finally {
    deviceLoading.value = false;
  }
};

const loadOverview = async () => {
  if (!jobId.value) return;
  overviewLoading.value = true;
  try {
    const qs = new URLSearchParams({
      page: "1",
      size: "9999",
    });
    const res = await apiRequest<any>(`/api/v1/job/${jobId.value}/device?${qs.toString()}`, { cache: "no-store" });
    const payload = res.data || {};
    const list = Array.isArray(payload.data) ? payload.data : [];
    overviewAll.value = list as JobDeviceRow[];
  } catch (error) {
    overviewAll.value = [];
    showTip(formatApiError(error, t.value.jobDetailPage.loadOverviewFailed));
  } finally {
    overviewLoading.value = false;
  }
};

const loadExecutions = async (
  page = execPage.value,
  size = execSize.value,
  sortField = execSortField.value,
  sortOrder = execSortOrder.value,
) => {
  if (!jobId.value) return;
  execLoading.value = true;
  try {
    const qs = new URLSearchParams({
      page: String(Math.max(1, page)),
      size: String(size),
      sort: execSortToApi(sortField),
      order: sortOrder,
    });
    const filters: Array<{ field: string; op: string; value: unknown }> = [];
    if (execKeyword.value.trim()) filters.push({ field: "task_id", op: "like", value: execKeyword.value.trim() });
    if (execState.value !== "all") filters.push({ field: "state", op: "eq", value: execState.value });
    if (filters.length) qs.set("filter", JSON.stringify(filters));
    const res = await apiRequest<any>(`/api/v1/job/${jobId.value}/execute?${qs.toString()}`, { cache: "no-store" });
    const payload = res.data || {};
    const list = Array.isArray(payload.data) ? payload.data : [];
    execRows.value = list as JobExecRow[];
    execTotal.value = num(payload.total);
    execPage.value = page;
    execSize.value = size;
  } catch (error) {
    execRows.value = [];
    execTotal.value = 0;
    showTip(formatApiError(error, t.value.jobDetailPage.loadExecutionsFailed));
  } finally {
    execLoading.value = false;
  }
};

const handleStop = async () => {
  if (!jobId.value) return;
  stopConfirmOpen.value = true;
};

const handleSwitchState = async (action: "continue" | "pause") => {
  if (!jobId.value) return;
  stateUpdating.value = action;
  try {
    await apiRequest(`/api/v1/job/${jobId.value}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ state: action }).toString(),
    });
    detail.value = detail.value
      ? {
          ...detail.value,
          state: action === "pause" ? "paused" : "running",
          stop_time: action === "pause" ? detail.value.stop_time : 0,
        }
      : detail.value;
    showTip(action === "pause" ? t.value.jobDetailPage.pauseSuccess : t.value.jobDetailPage.resumeSuccess, "success");
    void loadDevices(1, deviceSize.value);
    void loadExecutions(1, execSize.value);
  } catch (error) {
    showTip(formatApiError(error, action === "pause" ? t.value.jobDetailPage.pauseFailed : t.value.jobDetailPage.resumeFailed));
  } finally {
    stateUpdating.value = null;
  }
};

const handleStopConfirmed = async () => {
  if (!jobId.value) return;
  stopping.value = true;
  try {
    await apiRequest(`/api/v1/job/${jobId.value}/execute?with_running=1`, {
      method: "DELETE",
    });
    detail.value = detail.value
      ? {
          ...detail.value,
          state: "stopped",
          stop_time: Math.floor(Date.now() / 1000),
        }
      : detail.value;
    showTip(t.value.jobDetailPage.stopSuccess, "success");
    stopConfirmOpen.value = false;
    void loadDevices(1, deviceSize.value);
    void loadExecutions(1, execSize.value);
  } catch (error) {
    showTip(formatApiError(error, t.value.jobDetailPage.stopFailed));
  } finally {
    stopping.value = false;
  }
};

const openExecutionDetail = async (row: JobExecRow) => {
  const execId = num(row.id);
  if (!execId) {
    showTip(t.value.jobDetailPage.runDetailInvalidId);
    return;
  }
  execDetailOpen.value = true;
  execDetailTab.value = "overview";
  execDetailLoading.value = true;
  execDetail.value = null;
  try {
    const res = await apiRequest<any>(`/api/v1/job/${jobId.value}/execute/${execId}`, { cache: "no-store" });
    execDetail.value = (res.data || null) as JobExecRow | null;
  } catch (error) {
    showTip(formatApiError(error, t.value.jobDetailPage.runDetailLoadFailed));
    execDetailOpen.value = false;
  } finally {
    execDetailLoading.value = false;
  }
};

const loadScriptVersions = async () => {
  const scriptId = num(detail.value?.script?.parent?.id);
  if (!scriptId) {
    scriptVersions.value = [];
    scriptVersionsLoading.value = false;
    return;
  }
  scriptVersionsLoading.value = true;
  try {
    const res = await apiRequest<any>(`/api/v1/script/${scriptId}`, { cache: "no-store" });
    const versions = Array.isArray(res.data?.versions) ? res.data.versions : [];
    const list = versions
      .map((v: any) => ({
        id: Number(v?.id || 0),
        version: String(v?.version || ""),
        create_time: Number(v?.create_time || 0),
      }))
      .filter((v: ScriptVersionOption) => v.id > 0 && v.version)
      .sort((a: ScriptVersionOption, b: ScriptVersionOption) => b.id - a.id);
    scriptVersions.value = list;
  } catch (error) {
    scriptVersions.value = [];
    switchVersionTip.value = { id: Date.now() + Math.random(), text: formatApiError(error, t.value.jobDetailPage.loadScriptVersionsFailed), variant: "error" };
  } finally {
    scriptVersionsLoading.value = false;
  }
};

const handleSwitchVersionConfirm = async () => {
  if (!jobId.value) return;
  const nextId = Number(selectedScriptVersionId.value || 0);
  if (!nextId) {
    switchVersionTip.value = { id: Date.now() + Math.random(), text: t.value.jobDetailPage.selectScriptVersionFirst, variant: "error" };
    return;
  }
  switchingVersion.value = true;
  switchVersionTip.value = null;
  try {
    await apiRequest(`/api/v1/job/${jobId.value}/script-version`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ script_version_id: String(nextId) }).toString(),
    });
    switchVersionOpen.value = false;
    refreshTick.value += 1;
  } catch (error) {
    switchVersionTip.value = { id: Date.now() + Math.random(), text: formatApiError(error, t.value.jobDetailPage.switchVersionFailed), variant: "error" };
  } finally {
    switchingVersion.value = false;
  }
};

const onSwitchVersionOpenChange = (open: boolean) => {
  switchVersionOpen.value = open;
  if (open) {
    switchVersionTip.value = null;
    void loadScriptVersions();
  } else {
    scriptVersionsLoading.value = false;
    switchingVersion.value = false;
  }
};

watch([jobId, refreshTick], () => {
  void loadDetail();
  void loadDevices(1, deviceSize.value);
  void loadExecutions(1, execSize.value);
  overviewAll.value = [];
}, { immediate: true });

watch(() => detail.value?.script?.id, () => {
  const currentVersionId = num(detail.value?.script?.id);
  selectedScriptVersionId.value = currentVersionId ? String(currentVersionId) : "";
});

watch(tab, (tabValue) => {
  if ((tabValue === "overview" || tabValue === "desktop") && overviewAll.value.length === 0 && !overviewLoading.value) {
    void loadOverview();
  }
});

watch([() => overviewAll.value.length, overviewPage, overviewPageSize], () => {
  const pages = Math.max(1, Math.ceil(overviewAll.value.length / overviewPageSize.value));
  if (overviewPage.value > pages) {
    overviewPage.value = pages;
  }
});

const state = computed(() => normalizeJobState(detail.value?.state));
const isRunning = computed(() => state.value === "running");
const isPaused = computed(() => state.value === "paused");
const isStopped = computed(() => state.value === "stopped");
const successCount = computed(() => num(detail.value?.success));
const failedCount = computed(() => num(detail.value?.failed));
const timeoutCount = computed(() => num(detail.value?.timeout));
const revokedCount = computed(() => num(detail.value?.revoked));
const issuedCount = computed(() => num(detail.value?.issued));
const modeLabel = computed(() => {
  const mode = String(detail.value?.mode || "loop");
  if (mode === "count") return t.value.jobsPage.executeModeCount;
  if (mode === "per-device-count") return t.value.jobsPage.executeModePerDeviceCount;
  if (mode === "deadline") return t.value.jobsPage.executeModeTime;
  if (mode === "crontab") return t.value.jobsPage.executeModeCrontab;
  return t.value.jobsPage.executeModeLoop;
});

const toggleDeviceSort = (field: DeviceSortField) => {
  const nextOrder: SortOrder = deviceSortField.value === field
    ? (deviceSortOrder.value === "asc" ? "desc" : "asc")
    : "asc";
  deviceSortField.value = field;
  deviceSortOrder.value = nextOrder;
  void loadDevices(1, deviceSize.value, field, nextOrder);
};

const toggleExecSort = (field: ExecSortField) => {
  const defaultOrder: SortOrder = field === "started" || field === "duration" ? "desc" : "asc";
  const nextOrder: SortOrder = execSortField.value === field
    ? (execSortOrder.value === "asc" ? "desc" : "asc")
    : defaultOrder;
  execSortField.value = field;
  execSortOrder.value = nextOrder;
  void loadExecutions(1, execSize.value, field, nextOrder);
};

const paramSource = computed(() => String(detail.value?.param_source || "native").toLowerCase());
const paramSourceLabel = computed(() => paramSource.value === "callback"
  ? t.value.jobsPage.executeParamSourceHttp
  : paramSource.value === "queue"
    ? t.value.jobsPage.executeParamSourceQueue
    : t.value.jobsPage.executeParamSourceNative);
const createdAtText = computed(() => toTsText(jobTs(detail.value, "create")));
const startedAtText = computed(() => toTsText(jobTs(detail.value, "start")));
const stoppedAtText = computed(() => toTsText(jobTs(detail.value, "stop")));
const taskGroupName = computed(() => detail.value?.group?.name || t.value.jobDetailPage.noTaskGroup);
const taskGroupId = computed(() => num(detail.value?.group?.id));
const taskGroupColor = computed(() => detail.value?.group?.color || "#ef4444");
const stateText = computed(() => state.value === "running" ? t.value.jobsPage.statusRunning : state.value === "paused" ? t.value.jobsPage.statusPaused : t.value.jobsPage.statusFinished);
const stateTone = computed(() => state.value === "running"
  ? "bg-blue-500/10 text-blue-700 dark:text-blue-300"
  : state.value === "paused"
    ? "bg-yellow-500/10 text-yellow-700 dark:text-yellow-300"
    : "bg-muted text-muted-foreground");
const scriptName = computed(() => detail.value?.script?.parent?.name || "-");
const scriptVersion = computed(() => detail.value?.script?.version || "-");
const scriptParentId = computed(() => num(detail.value?.script?.parent?.id));
const scriptVersionId = computed(() => num(detail.value?.script?.id));
const detailModeText = computed(() => modeLabel.value + (detail.value?.count ? ` · ${detail.value.count}` : ""));
const executionParams = computed(() => {
  const parsedParams = parseMaybeJson(detail.value?.params);
  if (!parsedParams || typeof parsedParams !== "object" || Array.isArray(parsedParams)) {
    return [] as Array<{ name: string; type: ParamType; valueText: string; description?: string }>;
  }
  const rawObj = parsedParams as Record<string, unknown>;
  const source = String(detail.value?.param_source || "native").toLowerCase();
  if (source === "queue") {
    const items: Array<{ name: string; type: ParamType; valueText: string; description?: string }> = [
      {
        name: t.value.jobDetailPage.paramJobId,
        type: "string" as ParamType,
        valueText: String(rawObj.job_id ?? detail.value?.id ?? ""),
      },
      {
        name: t.value.jobDetailPage.paramToken,
        type: "string" as ParamType,
        valueText: String(rawObj.token ?? ""),
      },
    ];
    if (rawObj.callback) {
      items.push({
        name: t.value.jobDetailPage.paramCallback,
        type: "string" as ParamType,
        valueText: String(rawObj.callback),
      });
    }
    return items;
  }
  if (source === "callback") {
    return [
      {
        name: t.value.jobDetailPage.paramUrl,
        type: "string" as ParamType,
        valueText: String(rawObj.url ?? ""),
      },
      {
        name: t.value.jobDetailPage.paramCallback,
        type: "string" as ParamType,
        valueText: String(rawObj.callback ?? ""),
      },
    ];
  }
  const schema = parseScriptParamSchema(detail.value?.script?.parent?.params ?? detail.value?.script?.params);
  const schemaMap = new Map(schema.map((it) => [it.name, it]));
  return Object.keys(rawObj).map((name) => {
    const value = rawObj[name];
    const schemaItem = schemaMap.get(name);
    const type = schemaItem?.type ? normalizeParamType(schemaItem.type) : inferParamType(value);
    const valueText = type === "object" || type === "list"
      ? JSON.stringify(value)
      : String(value ?? "");
    return {
      name,
      type,
      valueText,
      description: schemaItem?.description,
    };
  });
});
const overviewTotalPages = computed(() => Math.max(1, Math.ceil(overviewAll.value.length / overviewPageSize.value)));
const overviewPageSafe = computed(() => Math.min(overviewPage.value, overviewTotalPages.value));
const overviewDevices = computed(() => {
  const start = (overviewPageSafe.value - 1) * overviewPageSize.value;
  return overviewAll.value.slice(start, start + overviewPageSize.value);
});
const execDetailState = computed(() => String(execDetail.value?.state || "").toLowerCase());
const execDetailStateTone = computed(() => executionStateTone(execDetailState.value));
const execDetailStateLabel = computed(() => {
  if (execDetailState.value === "pending") return t.value.jobDetailPage.execStatePending;
  if (execDetailState.value === "issued") return t.value.jobDetailPage.execStateIssued;
  if (execDetailState.value === "running") return t.value.jobDetailPage.execStateRunning;
  if (execDetailState.value === "success") return t.value.jobDetailPage.execStateSuccess;
  if (execDetailState.value === "failed") return t.value.jobDetailPage.execStateFailed;
  if (execDetailState.value === "timeout") return t.value.jobDetailPage.execStateTimeout;
  if (execDetailState.value === "lost") return t.value.jobDetailPage.execStateLost;
  if (execDetailState.value === "revoked") return t.value.jobDetailPage.execStateRevoked;
  return String(execDetail.value?.state || "-");
});
const detailLogsCount = computed(() => Array.isArray(execDetail.value?.resources)
  ? execDetail.value!.resources!.filter((r) => String(r.type || "").toLowerCase() === "log").length
  : 0);
const detailParamsCount = computed(() => {
  const p = parseMaybeJson(execDetail.value?.params);
  return p && typeof p === "object" && !Array.isArray(p) ? Object.keys(p as Record<string, unknown>).length : 0;
});
const execDetailDurationText = computed(() => {
  if (!execDetail.value) return "-";
  const elapsed = toElapsedDuration(execDetail.value.elapsed_time);
  return elapsed !== "-" ? elapsed : toDuration(execStartTs(execDetail.value), execFinishTs(execDetail.value));
});
const detailFiles = computed(() => fileResources(execDetail.value));
const detailFilesDomain = computed(() => execDetail.value?.device?.domain || "");
const detailDataEntries = computed(() => dataResources(execDetail.value));
const detailExceptionParsed = computed(() => parseMaybeJson(execDetail.value?.exception));
const detailTraceback = computed(() => String(execDetail.value?.traceback || ""));
const detailLogsText = computed(() => (execDetail.value ? logsBlockText(execDetail.value) : ""));
const detailParamsText = computed(() => jsonBlockText(execDetail.value?.params));
const detailResultText = computed(() => jsonBlockText(execDetail.value?.result));
const detailDataText = computed(() => jsonBlockText(detailDataEntries.value.length ? detailDataEntries.value : null));
const devicePageCount = computed(() => Math.max(1, Math.ceil(deviceTotal.value / deviceSize.value)));
const deviceVisiblePages = computed(() => pagerVisiblePages(devicePage.value, deviceSize.value, deviceTotal.value));
const execPageCount = computed(() => Math.max(1, Math.ceil(execTotal.value / execSize.value)));
const execVisiblePages = computed(() => pagerVisiblePages(execPage.value, execSize.value, execTotal.value));

// DesktopPreview (one MJPEG-over-WebSocket canvas per visible online device card)
const openDeviceDesktop = (domain: string, active: boolean) => {
  if (active && domain) window.open(`/d/${encodeURIComponent(domain)}/`, "_blank");
};

const previewCanvases = new Set<HTMLCanvasElement>();

const bindPreviewCanvas = (canvas: HTMLCanvasElement, deviceId: string) => {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/d/${encodeURIComponent(deviceId)}/ws/screen/10@25/live?scale=0.4&type=mjpeg&backend=0`;
  const ws = new WebSocket(wsUrl);
  ws.binaryType = "blob";

  const img = new Image();
  ws.onmessage = (evt) => {
    if (!previewCanvases.has(canvas)) return;
    const blob = evt.data instanceof Blob ? evt.data : new Blob([evt.data], { type: "image/jpeg" });
    const url = URL.createObjectURL(blob);
    img.onload = () => {
      if (previewCanvases.has(canvas)) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      }
      URL.revokeObjectURL(url);
    };
    img.onerror = () => URL.revokeObjectURL(url);
    img.src = url;
  };

  return () => {
    ws.close();
  };
};

const setPreviewCanvas = (el: Element | any, deviceId: string) => {
  const canvas = (el || null) as HTMLCanvasElement | null;
  if (!canvas) return;
  const prevCleanup = (canvas as any).__previewCleanup as (() => void) | undefined;
  if (prevCleanup) {
    prevCleanup();
    previewCanvases.delete(canvas);
    (canvas as any).__previewCleanup = undefined;
  }
  if (!deviceId) return;
  previewCanvases.add(canvas);
  (canvas as any).__previewCleanup = bindPreviewCanvas(canvas, deviceId);
};

onBeforeUnmount(() => {
  previewCanvases.forEach((canvas) => {
    const cleanup = (canvas as any).__previewCleanup as (() => void) | undefined;
    if (cleanup) cleanup();
  });
  previewCanvases.clear();
});
</script>

<template>
  <div class="flex h-screen bg-[#f5f5f7]">
    <Sidebar />
    <main class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <div class="flex h-14 shrink-0 items-center border-b border-gray-100 bg-white px-5">
        <div class="flex w-full min-w-0 items-center gap-2">
          <Button variant="ghost" size="icon" class="h-7 w-7 shrink-0" @click="router.push('/jobs')">
            <ChevronLeft class="h-3.5 w-3.5" />
          </Button>
          <div class="flex min-h-0 min-w-0 flex-1 flex-col items-stretch gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
            <div class="flex min-h-0 min-w-0 flex-1 flex-col gap-3 sm:flex-row sm:items-center sm:gap-5">
              <div class="shrink-0">
                <h1 class="text-base font-semibold leading-tight">{{ t.jobDetailPage.title }}</h1>
              </div>

              <div v-if="!loading && detail" class="min-w-0 flex-1 border-t border-border pt-3 sm:border-l sm:border-t-0 sm:pl-5 sm:pt-0">
                <p class="truncate text-xl font-semibold leading-tight">{{ detail?.name || "-" }}</p>
              </div>
            </div>

            <div class="flex shrink-0 flex-wrap items-center justify-end gap-2 sm:max-w-[min(100%,28rem)]">
              <template v-if="detail">
                <span
                  v-if="isRunning || isPaused || isStopped"
                  :class="cn('inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium', stateTone)"
                >
                  {{ isStopped ? t.jobDetailPage.ended : stateText }}
                </span>
                <template v-if="isRunning">
                  <Button
                    variant="outline"
                    size="sm"
                    class="h-7 gap-1.5 text-[11px]"
                    :disabled="stateUpdating !== null || stopping"
                    @click="void handleSwitchState('pause')"
                  >
                    <Loader2 v-if="stateUpdating === 'pause'" class="h-3.5 w-3.5 animate-spin" />
                    <Pause v-else class="h-3.5 w-3.5" />
                    {{ t.jobDetailPage.pause }}
                  </Button>
                  <Button
                    size="sm"
                    class="h-7 gap-1.5 text-[11px] bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    :disabled="stateUpdating !== null || stopping"
                    @click="handleStop"
                  >
                    <Square class="h-3.5 w-3.5 fill-current" />
                    {{ t.jobDetailPage.end }}
                  </Button>
                </template>
                <template v-if="isPaused">
                  <Button
                    variant="outline"
                    size="sm"
                    class="h-7 gap-1.5 text-[11px]"
                    :disabled="stateUpdating !== null || stopping"
                    @click="void handleSwitchState('continue')"
                  >
                    <Loader2 v-if="stateUpdating === 'continue'" class="h-3.5 w-3.5 animate-spin" />
                    <Play v-else class="h-3.5 w-3.5" />
                    {{ t.jobDetailPage.resume }}
                  </Button>
                  <Button
                    size="sm"
                    class="h-7 gap-1.5 text-[11px] bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    :disabled="stateUpdating !== null || stopping"
                    @click="handleStop"
                  >
                    <Square class="h-3.5 w-3.5 fill-current" />
                    {{ t.jobDetailPage.end }}
                  </Button>
                </template>
              </template>
              <Button variant="outline" size="sm" class="h-7 gap-1.5 text-[11px]" @click="refreshTick += 1">
                <RefreshCw :class="cn('h-3.5 w-3.5', loading && 'animate-spin')" />
                {{ t.jobsPage.refresh }}
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div class="flex-1 overflow-y-auto p-3">
        <div v-if="loading" class="flex h-64 items-center justify-center text-muted-foreground">
          <Loader2 class="h-5 w-5 animate-spin" />
        </div>
        <div v-else class="flex min-h-full flex-col gap-3">
          <div class="grid min-h-[640px] flex-1 grid-cols-1 items-stretch gap-3 xl:grid-cols-[320px_minmax(0,1fr)]">
            <div class="grid h-full min-h-0 grid-rows-[auto_auto_auto_minmax(0,1fr)] gap-3">
              <div class="rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <div class="mb-2 flex items-center justify-between">
                  <p class="inline-flex items-center gap-1 text-xs font-semibold">
                    <Info class="h-3.5 w-3.5 text-muted-foreground" />
                    {{ t.jobDetailPage.jobInfo }}
                  </p>
                  <span class="text-[11px] text-muted-foreground">#{{ detail?.id || "-" }}</span>
                </div>
                <div class="space-y-1.5 text-[11px]">
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Info class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.statusCard }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ stateText || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground">
                        <span class="inline-block h-3 w-3 shrink-0 rounded-sm translate-y-px" :style="{ backgroundColor: taskGroupColor }" />
                      </span>
                      {{ t.jobDetailPage.taskGroup }}
                    </p>
                    <div class="truncate text-[11px] font-medium">
                      <button
                        v-if="taskGroupId > 0"
                        type="button"
                        class="cursor-pointer text-left text-blue-600 underline-offset-2 hover:underline dark:text-blue-300"
                        @click="router.push(`/devices/group/${encodeURIComponent(String(taskGroupId))}`)"
                      >
                        {{ taskGroupName }}
                      </button>
                      <template v-else>{{ taskGroupName || "-" }}</template>
                    </div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><User class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.owner }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ detail?.owner?.name || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Info class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.paramSource }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ paramSourceLabel || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><RotateCcw class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.mode }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ detailModeText || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><CalendarClock class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.createdAt }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ createdAtText || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Play class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.startedAt }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ startedAtText || "-" }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Square class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.stoppedAt }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ stoppedAtText || "-" }}</div>
                  </div>
                </div>
              </div>

              <div class="rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <div class="mb-2 flex items-center justify-between">
                  <p class="inline-flex items-center gap-1 text-xs font-semibold">
                    <FileCode2 class="h-3.5 w-3.5 text-muted-foreground" />
                    {{ t.jobDetailPage.scriptInfo }}
                  </p>
                  <Popover :open="switchVersionOpen" @update:open="onSwitchVersionOpenChange">
                    <PopoverTrigger as-child>
                      <Button variant="outline" size="sm" class="h-6 gap-1 px-2 text-[10px]">
                        <GitBranch class="h-3 w-3" />
                        {{ t.jobDetailPage.switchVersion }}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent align="end" class="w-64 p-3">
                      <div class="space-y-3">
                        <div v-if="scriptVersionsLoading" class="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                          <Loader2 class="h-3 w-3 animate-spin" />
                          {{ t.jobDetailPage.loadingScriptVersions }}
                        </div>
                        <div v-else class="max-h-52 overflow-y-auto rounded-md border border-border p-1">
                          <div v-if="scriptVersions.length === 0" class="px-2 py-6 text-center text-[11px] text-muted-foreground">
                            {{ t.jobDetailPage.noScriptVersions }}
                          </div>
                          <template v-else>
                            <button
                              v-for="version in scriptVersions"
                              :key="version.id"
                              type="button"
                              :class="cn(
                                'flex w-full items-center justify-between rounded px-2 py-1.5 text-[11px] transition-colors',
                                selectedScriptVersionId === String(version.id) ? 'bg-accent text-accent-foreground' : 'hover:bg-muted/60',
                              )"
                              @click="selectedScriptVersionId = String(version.id)"
                              :disabled="switchingVersion"
                            >
                              <span class="truncate font-medium">{{ version.version }}</span>
                              <span class="shrink-0 text-[10px] text-muted-foreground">#{{ version.id }}</span>
                            </button>
                          </template>
                        </div>
                        <div class="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 border-t border-border pt-2">
                          <div class="min-w-0 min-h-5 overflow-hidden">
                            <FeedbackTip
                              v-if="switchVersionTip"
                              :key="switchVersionTip.id"
                              :toastId="switchVersionTip.id"
                              :message="switchVersionTip.text"
                              :variant="switchVersionTip.variant"
                              compact
                              class="max-w-full"
                              truncate
                            />
                          </div>
                          <div class="flex shrink-0 items-center gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              class="h-7 px-2.5 text-[11px]"
                              :disabled="switchingVersion"
                              @click="switchVersionOpen = false"
                            >
                              {{ t.jobsPage.cancelExecute }}
                            </Button>
                            <Button
                              size="sm"
                              class="h-7 px-2.5 text-[11px]"
                              :disabled="
                                switchingVersion ||
                                scriptVersionsLoading ||
                                !selectedScriptVersionId ||
                                Number(selectedScriptVersionId) === num(detail?.script?.id)
                              "
                              @click="void handleSwitchVersionConfirm()"
                            >
                              <Loader2 v-if="switchingVersion" class="mr-1 h-3.5 w-3.5 animate-spin" />
                              {{ t.jobDetailPage.switchVersionConfirm }}
                            </Button>
                          </div>
                        </div>
                      </div>
                    </PopoverContent>
                  </Popover>
                </div>
                <div class="space-y-1.5 text-[11px]">
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><FileCode2 class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.scriptName }}
                    </p>
                    <div class="truncate text-[11px] font-medium">
                      <button
                        v-if="scriptParentId > 0"
                        type="button"
                        class="cursor-pointer text-left text-blue-600 underline-offset-2 hover:underline dark:text-blue-300"
                        @click="
                          router.push(
                            scriptVersionId > 0
                              ? `/scripts/${encodeURIComponent(String(scriptParentId))}?versionId=${encodeURIComponent(String(scriptVersionId))}`
                              : `/scripts/${encodeURIComponent(String(scriptParentId))}`,
                          )
                        "
                      >
                        {{ `${scriptName} / ${scriptVersion}` }}
                      </button>
                      <template v-else>{{ `${scriptName} / ${scriptVersion}` || "-" }}</template>
                    </div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Info class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.description }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ String((detail?.script?.parent as any)?.description || "-") }}</div>
                  </div>
                </div>
              </div>

              <div class="rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <p class="mb-2 inline-flex items-center gap-1 text-xs font-semibold">
                  <SlidersHorizontal class="h-3.5 w-3.5 text-muted-foreground" />
                  {{ t.jobDetailPage.executionConfig }}
                </p>
                <div class="space-y-1.5 text-[11px]">
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><RotateCcw class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.retryCount }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ String(num(detail?.config?.retries)) }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><TimerReset class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.softTimeout }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ `${num(detail?.config?.soft_time_limit)}s` }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><TimerReset class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.hardTimeout }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ `${num(detail?.config?.time_limit)}s` }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><CalendarClock class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.interval }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ `${num(detail?.interval)}s` }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Gauge class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.weight }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ String(num(detail?.priority)) }}</div>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Info class="h-3 w-3" /></span>
                      {{ t.jobDetailPage.ignoreResult }}
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ detail?.config?.ignore_result ? t.jobDetailPage.yes : t.jobDetailPage.no }}</div>
                  </div>
                  <div v-if="detail?.mode === 'crontab'" class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><CalendarClock class="h-3 w-3" /></span>
                      Crontab
                    </p>
                    <div class="truncate text-[11px] font-medium">{{ String(detail?.crontab || "-") }}</div>
                  </div>
                </div>
              </div>

              <div class="flex min-h-0 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <p class="mb-2 inline-flex items-center gap-1 text-xs font-semibold">
                  <FileCode2 class="h-3.5 w-3.5 text-muted-foreground" />
                  {{ t.jobDetailPage.executionParams }}
                </p>
                <div class="min-h-0 flex-1 overflow-y-auto pr-1">
                  <div v-if="executionParams.length === 0" class="flex h-full min-h-[120px] flex-col items-center justify-center gap-2 text-muted-foreground">
                    <FileCode2 class="h-5 w-5 opacity-50" />
                    <p class="text-[11px]">{{ t.jobDetailPage.noExecutionParams }}</p>
                  </div>
                  <div v-else class="space-y-1.5">
                    <div v-for="param in executionParams" :key="param.name" class="rounded-md border border-border/70 bg-background px-2 py-1.5">
                      <div class="flex items-center justify-between gap-2">
                        <span class="truncate text-[11px] font-medium">{{ param.name }}</span>
                        <span class="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{{ param.type }}</span>
                      </div>
                      <p v-if="param.description" class="mt-1 text-[10px] text-muted-foreground">{{ param.description }}</p>
                      <p class="mt-1 break-all font-mono text-[11px] text-foreground">{{ param.valueText || "-" }}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="flex h-full min-h-0 flex-col gap-3">
              <div class="rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <div class="grid grid-cols-2 gap-2 text-[11px] md:grid-cols-5">
                  <div :class="cn('rounded-md border border-border px-2.5 py-2', stateToneClass('neutral'))">
                    <p class="text-[10px]">{{ t.jobDetailPage.issued }}</p>
                    <p class="mt-1 text-sm font-semibold">{{ fmtInt(issuedCount) }}</p>
                  </div>
                  <div :class="cn('rounded-md border border-border px-2.5 py-2', stateToneClass('green'))">
                    <p class="text-[10px]">{{ t.jobDetailPage.success }}</p>
                    <p class="mt-1 text-sm font-semibold">{{ fmtInt(successCount) }}</p>
                  </div>
                  <div :class="cn('rounded-md border border-border px-2.5 py-2', stateToneClass('red'))">
                    <p class="text-[10px]">{{ t.jobDetailPage.failed }}</p>
                    <p class="mt-1 text-sm font-semibold">{{ fmtInt(failedCount) }}</p>
                  </div>
                  <div :class="cn('rounded-md border border-border px-2.5 py-2', stateToneClass('yellow'))">
                    <p class="text-[10px]">{{ t.jobDetailPage.timeout }}</p>
                    <p class="mt-1 text-sm font-semibold">{{ fmtInt(timeoutCount) }}</p>
                  </div>
                  <div :class="cn('rounded-md border border-border px-2.5 py-2', stateToneClass('purple'))">
                    <p class="text-[10px]">{{ t.jobDetailPage.revoked }}</p>
                    <p class="mt-1 text-sm font-semibold">{{ fmtInt(revokedCount) }}</p>
                  </div>
                </div>
              </div>

              <div class="flex min-h-0 flex-1 flex-col rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
                <Tabs v-model="tab" class="flex min-h-0 flex-1 flex-col">
                  <div class="mb-3 flex items-center justify-between gap-2">
                    <TabsList class="h-8">
                      <TabsTrigger value="devices" class="text-[11px]">{{ t.jobDetailPage.tabDevices }}</TabsTrigger>
                      <TabsTrigger value="executions" class="text-[11px]">{{ t.jobDetailPage.tabExecutions }}</TabsTrigger>
                      <TabsTrigger value="overview" class="text-[11px]">{{ t.jobDetailPage.tabOverview }}</TabsTrigger>
                    </TabsList>
                    <div v-if="tab === 'executions'" class="flex items-center gap-2">
                      <Input
                        class="h-7 w-40 text-[11px]"
                        :placeholder="t.jobDetailPage.execSearchPlaceholder"
                        v-model="execKeyword"
                        @keydown="(e: KeyboardEvent) => { if (e.key === 'Enter') void loadExecutions(1, execSize); }"
                      />
                      <Select v-model="execState">
                        <SelectTrigger size="sm" class="h-7 w-32 text-[11px]"><SelectValue /></SelectTrigger>
                        <SelectContent class="max-h-64">
                          <SelectItem value="all">{{ t.jobDetailPage.stateAll }}</SelectItem>
                          <SelectItem value="pending">{{ t.jobDetailPage.execStatePending }}</SelectItem>
                          <SelectItem value="issued">{{ t.jobDetailPage.execStateIssued }}</SelectItem>
                          <SelectItem value="running">{{ t.jobDetailPage.execStateRunning }}</SelectItem>
                          <SelectItem value="success">{{ t.jobDetailPage.execStateSuccess }}</SelectItem>
                          <SelectItem value="failed">{{ t.jobDetailPage.execStateFailed }}</SelectItem>
                          <SelectItem value="timeout">{{ t.jobDetailPage.execStateTimeout }}</SelectItem>
                          <SelectItem value="lost">{{ t.jobDetailPage.execStateLost }}</SelectItem>
                          <SelectItem value="revoked">{{ t.jobDetailPage.execStateRevoked }}</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="void loadExecutions(1, execSize)">
                        {{ t.jobDetailPage.filter }}
                      </Button>
                    </div>
                  </div>

                  <TabsContent value="devices" class="mt-0 flex min-h-[360px] flex-1 flex-col">
                    <div class="overflow-hidden rounded-lg border border-border">
                      <table class="w-full text-[11px]">
                        <thead class="bg-muted/30">
                          <tr class="border-b border-border">
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('domain')">{{ t.jobDetailPage.colDomain }}<ArrowUpDown v-if="deviceSortField !== 'domain'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('issued')">{{ t.jobDetailPage.colIssued }}<ArrowUpDown v-if="deviceSortField !== 'issued'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('success')">{{ t.jobDetailPage.colResult }}<ArrowUpDown v-if="deviceSortField !== 'success'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('rate')">{{ t.jobDetailPage.colRate }}<ArrowUpDown v-if="deviceSortField !== 'rate'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('state')">{{ t.jobDetailPage.colState }}<ArrowUpDown v-if="deviceSortField !== 'state'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleDeviceSort('version')">{{ t.jobDetailPage.colVersion }}<ArrowUpDown v-if="deviceSortField !== 'version'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="deviceSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr v-if="deviceLoading"><td :colspan="6" class="py-8 text-center text-muted-foreground"><Loader2 class="mx-auto h-4 w-4 animate-spin" /></td></tr>
                          <tr v-else-if="devices.length === 0">
                            <td :colspan="6" class="py-0">
                              <div class="flex h-40 flex-col items-center justify-center gap-2 text-muted-foreground">
                                <Monitor class="h-5 w-5 opacity-50" />
                                <span class="text-[11px]">{{ t.jobDetailPage.noDevices }}</span>
                              </div>
                            </td>
                          </tr>
                          <template v-else>
                          <tr
                            v-for="(row, idx) in devices"
                            :key="`${row.device?.domain || row.domain || '-'}-${idx}`"
                            :class="cn('border-b border-border/50 last:border-0', isRemovedDevice(row) && 'bg-muted/35 text-muted-foreground')"
                          >
                            <td class="px-3 py-2">
                              <div class="flex items-center gap-2">
                                <span :class="cn('h-2 w-2 rounded-full', isRemovedDevice(row) ? 'bg-slate-400' : stateBadge(row.device?.state) === 'online' ? 'bg-emerald-500' : stateBadge(row.device?.state) === 'offline' ? 'bg-slate-400' : 'bg-yellow-500')" />
                                <span class="font-medium">{{ row.device?.domain || row.domain || "-" }}</span>
                                <span v-if="isRemovedDevice(row)" class="inline-flex rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{{ t.jobDetailPage.deviceRemoved }}</span>
                              </div>
                            </td>
                            <td class="px-3 py-2 font-medium">{{ fmtInt(num(row.issued)) }}</td>
                            <td class="px-3 py-2">
                              <span class="text-emerald-600">{{ fmtInt(num(row.success)) }}</span>
                              <span class="mx-1 text-muted-foreground">/</span>
                              <span class="text-red-600">{{ fmtInt(num(row.failed)) }}</span>
                              <span class="mx-1 text-muted-foreground">/</span>
                              <span class="text-amber-600">{{ fmtInt(num(row.timeout)) }}</span>
                            </td>
                            <td class="px-3 py-2">{{ percent(num(row.success), Math.max(1, num(row.success) + num(row.failed) + num(row.timeout))) }}%</td>
                            <td class="px-3 py-2">
                              <UITooltip v-if="String(row.state || '').toLowerCase() === 'script/load_failed' && String(row.error || '').trim()">
                                <TooltipTrigger as-child>
                                  <span
                                    :class="cn(
                                      'inline-flex rounded-full border px-1.5 py-0.5 text-[11px] font-medium text-foreground',
                                      String(row.state || '').trim() ? deviceJobStateTone(String(row.state || '')) : 'border-border bg-muted text-muted-foreground',
                                      'cursor-help',
                                    )"
                                  >
                                    {{ String(row.state || (isRemovedDevice(row) ? t.jobDetailPage.deviceRemoved : "-")) }}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent side="top" class="max-w-[520px] whitespace-pre-wrap break-words text-xs">
                                  <code class="block whitespace-pre-wrap break-words font-mono text-[11px] leading-4">
                                    {{ String(row.error || '').trim() }}
                                  </code>
                                </TooltipContent>
                              </UITooltip>
                              <span
                                v-else
                                :class="cn(
                                  'inline-flex rounded-full border px-1.5 py-0.5 text-[11px] font-medium text-foreground',
                                  String(row.state || '').trim() ? deviceJobStateTone(String(row.state || '')) : 'border-border bg-muted text-muted-foreground',
                                )"
                              >
                                {{ String(row.state || (isRemovedDevice(row) ? t.jobDetailPage.deviceRemoved : "-")) }}
                              </span>
                            </td>
                            <td class="px-3 py-2">{{ row.device?.version || "-" }}</td>
                          </tr>
                          </template>
                        </tbody>
                      </table>
                    </div>
                    <div class="mt-auto flex items-center justify-between border-t border-border/60 pt-3">
                      <span class="text-xs text-muted-foreground">{{ t.jobDetailPage.total.replace("{total}", String(deviceTotal)) }}</span>
                      <div class="flex items-center gap-1">
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="devicePage <= 1" @click="void loadDevices(1, deviceSize)">
                          <ChevronsLeft class="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="devicePage <= 1" @click="void loadDevices(Math.max(1, devicePage - 1), deviceSize)">
                          <ChevronLeft class="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          v-for="n in deviceVisiblePages"
                          :key="n"
                          :variant="n === devicePage ? 'default' : 'outline'"
                          size="sm"
                          class="h-7 w-7 p-0 text-[11px]"
                          @click="void loadDevices(n, deviceSize)"
                        >
                          {{ n }}
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="devicePage >= devicePageCount" @click="void loadDevices(Math.min(devicePageCount, devicePage + 1), deviceSize)">
                          <ChevronRight class="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="devicePage >= devicePageCount" @click="void loadDevices(devicePageCount, deviceSize)">
                          <ChevronsRight class="h-3.5 w-3.5" />
                        </Button>
                        <Select :model-value="String(deviceSize)" @update:model-value="(v: string) => void loadDevices(1, Number(v))">
                          <SelectTrigger size="sm" class="h-7 w-24 text-xs"><SelectValue /></SelectTrigger>
                          <SelectContent class="max-h-64">
                            <SelectItem value="100">{{ t.jobDetailPage.perPage.replace("{size}", "100") }}</SelectItem>
                            <SelectItem value="300">{{ t.jobDetailPage.perPage.replace("{size}", "300") }}</SelectItem>
                            <SelectItem value="500">{{ t.jobDetailPage.perPage.replace("{size}", "500") }}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="executions" class="mt-0 flex min-h-[360px] flex-1 flex-col">
                    <div class="overflow-hidden rounded-lg border border-border">
                      <table class="w-full text-[11px]">
                        <thead class="bg-muted/30">
                          <tr class="border-b border-border">
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('execution')">{{ t.jobDetailPage.colExecution }}<ArrowUpDown v-if="execSortField !== 'execution'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('device')">{{ t.jobDetailPage.colDevice }}<ArrowUpDown v-if="execSortField !== 'device'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('state')">{{ t.jobDetailPage.colState }}<ArrowUpDown v-if="execSortField !== 'state'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('started')">{{ t.jobDetailPage.colStarted }}<ArrowUpDown v-if="execSortField !== 'started'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('duration')">{{ t.jobDetailPage.colDuration }}<ArrowUpDown v-if="execSortField !== 'duration'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                            <th class="px-3 py-2 text-left"><button class="inline-flex items-center gap-1" @click="toggleExecSort('reason')">{{ t.jobDetailPage.colReason }}<ArrowUpDown v-if="execSortField !== 'reason'" class="h-3 w-3 opacity-50" /><ChevronUp v-else-if="execSortOrder === 'asc'" class="h-3 w-3" /><ChevronDown v-else class="h-3 w-3" /></button></th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr v-if="execLoading"><td :colspan="6" class="py-8 text-center text-muted-foreground"><Loader2 class="mx-auto h-4 w-4 animate-spin" /></td></tr>
                          <tr v-else-if="execRows.length === 0">
                            <td :colspan="6" class="py-0">
                              <div class="flex h-40 flex-col items-center justify-center gap-2 text-muted-foreground">
                                <History class="h-5 w-5 opacity-50" />
                                <span class="text-[11px]">{{ t.jobDetailPage.noExecutions }}</span>
                              </div>
                            </td>
                          </tr>
                          <template v-else>
                          <tr
                            v-for="(row, idx) in execRows"
                            :key="`${row.task_id || row.id || idx}`"
                            class="cursor-pointer border-b border-border/50 transition-colors hover:bg-muted/30 last:border-0"
                            @click="void openExecutionDetail(row)"
                          >
                            <td class="px-3 py-2 font-medium">{{ row.task_id || row.id || "-" }}</td>
                            <td class="px-3 py-2">{{ row.device?.domain || "-" }}</td>
                            <td class="px-3 py-2">
                              <span :class="cn('inline-flex rounded px-1.5 py-0.5', execRowStateTone(String(row.state || '')))">{{ execRowStateLabel(t, String(row.state || '')) }}</span>
                            </td>
                            <td class="px-3 py-2">{{ toTsText(execStartTs(row)) }}</td>
                            <td class="px-3 py-2">{{ toElapsedDuration(row.elapsed_time) }}</td>
                            <td class="px-3 py-2">{{ row.reason || "-" }}</td>
                          </tr>
                          </template>
                        </tbody>
                      </table>
                    </div>
                    <div class="mt-auto flex items-center justify-between border-t border-border/60 pt-3">
                      <span class="text-xs text-muted-foreground">{{ t.jobDetailPage.total.replace("{total}", String(execTotal)) }}</span>
                      <div class="flex items-center gap-1">
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="execPage <= 1" @click="void loadExecutions(1, execSize)">
                          <ChevronsLeft class="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="execPage <= 1" @click="void loadExecutions(Math.max(1, execPage - 1), execSize)">
                          <ChevronLeft class="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          v-for="n in execVisiblePages"
                          :key="n"
                          :variant="n === execPage ? 'default' : 'outline'"
                          size="sm"
                          class="h-7 w-7 p-0 text-[11px]"
                          @click="void loadExecutions(n, execSize)"
                        >
                          {{ n }}
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="execPage >= execPageCount" @click="void loadExecutions(Math.min(execPageCount, execPage + 1), execSize)">
                          <ChevronRight class="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="outline" size="icon" class="h-7 w-7" :disabled="execPage >= execPageCount" @click="void loadExecutions(execPageCount, execSize)">
                          <ChevronsRight class="h-3.5 w-3.5" />
                        </Button>
                        <Select :model-value="String(execSize)" @update:model-value="(v: string) => void loadExecutions(1, Number(v))">
                          <SelectTrigger size="sm" class="h-7 w-24 text-xs"><SelectValue /></SelectTrigger>
                          <SelectContent class="max-h-64">
                            <SelectItem value="100">{{ t.jobDetailPage.perPage.replace("{size}", "100") }}</SelectItem>
                            <SelectItem value="300">{{ t.jobDetailPage.perPage.replace("{size}", "300") }}</SelectItem>
                            <SelectItem value="500">{{ t.jobDetailPage.perPage.replace("{size}", "500") }}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="overview" class="mt-0 flex-1">
                    <div v-if="overviewLoading" class="flex h-40 items-center justify-center text-muted-foreground"><Loader2 class="h-4 w-4 animate-spin" /></div>
                    <div v-else-if="overviewAll.length === 0" class="flex h-40 flex-col items-center justify-center gap-2 text-muted-foreground">
                      <Monitor class="h-5 w-5 opacity-50" />
                      <span class="text-[11px]">{{ t.jobDetailPage.noOverview }}</span>
                    </div>
                    <div v-else class="flex h-full min-h-0 flex-col">
                      <div class="grid flex-1 auto-rows-max content-start items-start grid-cols-3 gap-2 overflow-y-auto pr-1 md:grid-cols-5 lg:grid-cols-7 xl:grid-cols-9">
                        <div
                          v-for="(it, idx) in overviewDevices"
                          :key="`${it.device?.domain || it.domain || `#${idx + 1}`}-${idx}`"
                          :class="cn(
                            'self-start overflow-hidden rounded-md border border-border bg-card transition-all',
                            stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it) ? 'cursor-pointer hover:border-accent hover:bg-accent/5' : 'opacity-55',
                          )"
                          @click="openDeviceDesktop(it.device?.domain || it.domain || '', stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it))"
                        >
                          <div
                            :class="cn(
                              'relative aspect-[9/16] overflow-hidden border-b border-border/50',
                              stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it) ? 'bg-muted/30' : 'bg-muted/50',
                            )"
                          >
                            <canvas
                              v-if="stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it)"
                              :ref="(el) => setPreviewCanvas(el, it.device?.domain || it.domain || '')"
                              width="540"
                              height="960"
                              class="h-full w-full"
                            />
                            <div v-else class="flex h-full flex-col items-center justify-center gap-1">
                              <div class="flex h-6 w-6 items-center justify-center rounded-full border-2 border-dashed border-muted-foreground/30">
                                <XCircle class="h-3 w-3 text-muted-foreground/50" />
                              </div>
                              <span class="text-[10px] font-medium text-muted-foreground/70">
                                {{ isRemovedDevice(it) ? t.jobDetailPage.deviceRemoved : stateBadge(it.device?.state) === "pending" ? t.overviewPage.statusPending : t.overviewPage.statusOffline }}
                              </span>
                            </div>
                            <span :class="cn('absolute left-1 top-1 h-2 w-2 rounded-full', stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it) ? 'bg-green-500' : isRemovedDevice(it) ? 'bg-slate-400' : stateBadge(it.device?.state) === 'pending' ? 'bg-yellow-500' : 'bg-gray-500')" />
                          </div>
                          <div class="p-1.5">
                            <div class="flex items-center gap-1.5">
                              <p class="min-w-0 flex-1 truncate text-[11px] font-medium">{{ it.device?.domain || it.domain || `#${idx + 1}` }}</p>
                              <span :class="cn('h-1.5 w-1.5 shrink-0 rounded-full', stateBadge(it.device?.state) === 'online' && !isRemovedDevice(it) ? 'bg-green-500' : isRemovedDevice(it) ? 'bg-slate-400' : stateBadge(it.device?.state) === 'pending' ? 'bg-yellow-500' : 'bg-gray-500')" />
                            </div>
                          </div>
                        </div>
                      </div>
                      <div class="mt-3 flex items-center justify-between border-t border-border/60 pt-3">
                        <span class="text-xs text-muted-foreground">{{ t.jobDetailPage.total.replace("{total}", String(overviewAll.length)) }}</span>
                        <div class="flex items-center gap-1">
                          <Select
                            :model-value="String(overviewPageSize)"
                            @update:model-value="(value: string) => {
                              overviewPageSize = Number(value);
                              overviewPage = 1;
                            }"
                          >
                            <SelectTrigger size="sm" class="h-7 w-[68px] text-xs">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent class="max-h-64">
                              <SelectItem v-for="size in [30, 50, 70, 90]" :key="size" :value="String(size)" class="text-xs">
                                {{ size }}
                              </SelectItem>
                            </SelectContent>
                          </Select>
                          <span class="mx-1 text-xs text-muted-foreground">
                            {{ t.overviewPage.page.replace("{page}", overviewPageSafe.toString()) }} / {{ overviewTotalPages }}
                          </span>
                          <Button
                            variant="outline"
                            size="icon"
                            class="h-7 w-7"
                            @click="overviewPage = 1"
                            :disabled="overviewPageSafe === 1"
                          >
                            <ChevronsLeft class="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="outline"
                            size="icon"
                            class="h-7 w-7"
                            @click="overviewPage = Math.max(1, overviewPageSafe - 1)"
                            :disabled="overviewPageSafe === 1"
                          >
                            <ChevronLeft class="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="outline"
                            size="icon"
                            class="h-7 w-7"
                            @click="overviewPage = Math.min(overviewTotalPages, overviewPageSafe + 1)"
                            :disabled="overviewPageSafe === overviewTotalPages"
                          >
                            <ChevronRight class="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="outline"
                            size="icon"
                            class="h-7 w-7"
                            @click="overviewPage = overviewTotalPages"
                            :disabled="overviewPageSafe === overviewTotalPages"
                          >
                            <ChevronsRight class="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
    <AlertDialog :open="stopConfirmOpen" @update:open="(v: boolean) => (stopConfirmOpen = v)">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{{ t.jobDetailPage.stop }}</AlertDialogTitle>
          <AlertDialogDescription>{{ t.jobDetailPage.stopConfirm }}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel :disabled="stopping">{{ t.jobsPage.cancelExecute }}</AlertDialogCancel>
          <AlertDialogAction
            :disabled="stopping"
            @click="(e: Event) => {
              e.preventDefault();
              void handleStopConfirmed();
            }"
          >
            <Loader2 v-if="stopping" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            {{ t.jobDetailPage.stop }}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    <Dialog :open="execDetailOpen" @update:open="(v: boolean) => (execDetailOpen = v)">
      <DialogContent class="max-h-[80vh] w-[50vw] max-w-[calc(100vw-1rem)] overflow-hidden p-0 sm:max-w-[50vw]">
        <DialogHeader class="border-b border-border px-4 pb-3 pt-4 sm:px-5">
          <div class="flex items-start justify-between gap-3 pr-8">
            <div class="min-w-0">
              <DialogTitle class="truncate text-base font-semibold leading-tight sm:text-lg">
                {{ execDetail?.job?.name || detail?.name || t.jobDetailPage.runDetailTitle }}
              </DialogTitle>
              <p class="mt-1 truncate font-mono text-[11px] text-muted-foreground sm:text-xs">
                {{ execDetail?.task_id || "-" }}
              </p>
            </div>
            <span
              v-if="execDetail"
              :class="cn(
                'inline-flex shrink-0 items-center gap-1 rounded-lg border px-2 py-0.5 text-[11px] font-medium',
                execDetailStateTone === 'green' && 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
                execDetailStateTone === 'blue' && 'border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300',
                execDetailStateTone === 'orange' && 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
                execDetailStateTone === 'red' && 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300',
                execDetailStateTone === 'slate' && 'border-border bg-muted text-muted-foreground',
              )"
            >
              <CheckCircle2 class="h-3 w-3" />
              {{ execDetailStateLabel }}
            </span>
          </div>
        </DialogHeader>
        <div v-if="execDetailLoading" class="flex h-40 items-center justify-center text-muted-foreground">
          <Loader2 class="h-5 w-5 animate-spin" />
        </div>
        <div v-else-if="!execDetail" class="flex h-40 items-center justify-center text-sm text-muted-foreground">
          {{ t.jobDetailPage.runDetailNoData }}
        </div>
        <Tabs v-else v-model="execDetailTab" class="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <div class="border-b border-border px-4 py-2 sm:px-5">
            <TabsList class="h-8 w-full justify-start gap-1 overflow-x-auto">
              <TabsTrigger value="overview" class="h-7 px-2 text-[11px]">
                {{ t.jobDetailPage.runDetailOverview }}
              </TabsTrigger>
              <TabsTrigger value="params" class="h-7 px-2 text-[11px]">
                {{ `${t.jobDetailPage.runDetailParams} (${detailParamsCount})` }}
              </TabsTrigger>
              <TabsTrigger value="result" class="h-7 px-2 text-[11px]">
                {{ t.jobDetailPage.runDetailResult }}
              </TabsTrigger>
              <TabsTrigger value="logs" class="h-7 px-2 text-[11px]">
                {{ `${t.jobDetailPage.runDetailLogs} (${detailLogsCount})` }}
              </TabsTrigger>
              <TabsTrigger value="files" class="h-7 px-2 text-[11px]">
                {{ t.jobDetailPage.runDetailFiles }}
              </TabsTrigger>
              <TabsTrigger value="data" class="h-7 px-2 text-[11px]">
                {{ t.jobDetailPage.runDetailData }}
              </TabsTrigger>
              <TabsTrigger value="exception" class="h-7 px-2 text-[11px]">
                {{ t.jobDetailPage.runDetailException }}
              </TabsTrigger>
            </TabsList>
          </div>

          <div class="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-3 sm:px-5">
            <TabsContent value="overview" class="mt-0 min-w-0 overflow-hidden">
              <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
                <Card class="min-w-0  pt-0">
                  <CardContent class="space-y-2 p-3">
                    <p class="text-[11px] font-medium text-muted-foreground">{{ t.jobDetailPage.runDetailDeviceInfo }}</p>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.runDetailDevice }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ execDetail.device?.domain || "-" }}</span>
                    </div>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.colState }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ String(execDetail.device?.state || "-") }}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card class="min-w-0 pt-0">
                  <CardContent class="space-y-2 p-3">
                    <p class="text-[11px] font-medium text-muted-foreground">{{ t.jobDetailPage.runDetailScriptInfo }}</p>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.runDetailScript }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ `${(execDetail.script as any)?.parent?.name || "-"} / ${(execDetail.script as any)?.version || "-"}` }}</span>
                    </div>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.colExecution }}</span>
                      <span class="min-w-0 truncate font-mono text-[11px] font-medium text-foreground">{{ String(execDetail.task_id || "-") }}</span>
                    </div>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.colReason }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ String(execDetail.reason || "-") }}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card class="min-w-0 md:col-span-2 pt-0 pb-0">
                  <CardContent class="grid grid-cols-1 gap-2 p-3 sm:grid-cols-3">
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.runDetailStartedAt }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ toTsText(execStartTs(execDetail)) }}</span>
                    </div>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.runDetailFinishedAt }}</span>
                      <span class="min-w-0 truncate text-[11px] font-medium text-foreground">{{ toTsText(execFinishTs(execDetail)) }}</span>
                    </div>
                    <div class="grid grid-cols-[84px_minmax(0,1fr)] items-start gap-2">
                      <span class="text-[11px] text-muted-foreground">{{ t.jobDetailPage.colDuration }}</span>
                      <span class="min-w-0 truncate font-mono text-[11px] font-medium text-foreground">{{ execDetailDurationText }}</span>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="params" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="!detailParamsText" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoParams }}</p>
              </div>
              <div v-else class="h-[300px] min-w-0 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
                <pre class="inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ detailParamsText }}</pre>
              </div>
            </TabsContent>
            <TabsContent value="result" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="!detailResultText" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoResult }}</p>
              </div>
              <div v-else class="h-[300px] min-w-0 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
                <pre class="inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ detailResultText }}</pre>
              </div>
            </TabsContent>
            <TabsContent value="logs" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="!detailLogsText" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoLogs }}</p>
              </div>
              <div v-else class="h-[300px] min-w-0 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
                <pre class="inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ detailLogsText }}</pre>
              </div>
            </TabsContent>
            <TabsContent value="files" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="detailFiles.length === 0" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoFiles }}</p>
              </div>
              <ScrollArea v-else class="h-[300px] rounded-md border border-border">
                <div class="divide-y divide-border/60">
                  <div v-for="(r, idx) in detailFiles" :key="`${r.id || idx}`" class="flex items-center justify-between gap-3 px-3 py-2 text-[11px]">
                    <div class="min-w-0">
                      <p class="truncate font-medium">{{ r.name || filePathText(r) || "-" }}</p>
                      <p class="truncate text-muted-foreground">{{ filePathText(r) || "-" }}</p>
                    </div>
                    <a
                      v-if="fileHref(detailFilesDomain, r)"
                      :href="fileHref(detailFilesDomain, r)"
                      target="_blank"
                      rel="noreferrer"
                      class="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      <Download class="h-3.5 w-3.5" />
                      <span>{{ t.jobDetailPage.runDetailDownload }}</span>
                    </a>
                  </div>
                </div>
              </ScrollArea>
            </TabsContent>
            <TabsContent value="data" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="!detailDataText" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoDataEntries }}</p>
              </div>
              <div v-else class="h-[300px] min-w-0 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
                <pre class="inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ detailDataText }}</pre>
              </div>
            </TabsContent>
            <TabsContent value="exception" class="mt-0 min-w-0 overflow-hidden">
              <div v-if="!detailExceptionParsed && !detailTraceback" class="flex h-[220px] flex-col items-center justify-center gap-2 text-muted-foreground">
                <div class="rounded-xl bg-muted/50 p-3">
                  <FileX2 class="h-6 w-6 opacity-60" />
                </div>
                <p class="text-xs">{{ t.jobDetailPage.runDetailNoException }}</p>
              </div>
              <div v-else class="h-[300px] min-w-0 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
                <pre v-if="detailExceptionParsed" class="mb-3 inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ typeof detailExceptionParsed === "string" ? detailExceptionParsed : JSON.stringify(detailExceptionParsed, null, 2) }}</pre>
                <pre v-if="detailTraceback" class="inline-block min-w-full whitespace-pre font-mono text-[11px] leading-5 text-zinc-100">{{ detailTraceback }}</pre>
              </div>
            </TabsContent>
          </div>
        </Tabs>
      </DialogContent>
    </Dialog>
  </div>
</template>
