<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { matchHashPath, useHashPathname, useHashRouter } from "@/lib/hash-router";
import {
  ArrowRightLeft,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronUp,
  Download,
  Folder,
  FolderOpen,
  FolderPlus,
  FolderUp,
  ListFilter,
  Plus,
  Power,
  RotateCw,
  Search,
  Settings2,
  Link2,
  MoreVertical,
  Trash2,
  Upload,
  Terminal,
  Wifi,
  X,
} from "lucide-vue-next";
import { DropdownMenuCheckboxItem, DropdownMenuItemIndicator } from "reka-ui";
import { Sidebar } from "@/components/dashboard/sidebar";
import { HexColorPicker } from "@/components/ui/color-picker";
import { AddDeviceDialog } from "@/components/devices/add-device-dialog";
import { DeviceStats } from "@/components/devices/device-stats";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverAnchor, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { interpolate, useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { apiRequest, formatApiError } from "@/lib/api";
import { androidVersionFromSdk } from "@/lib/android-version";

type DeviceStatus = "pending" | "online" | "offline";

type DeviceRecord = {
  id: string;
  status: DeviceStatus;
  mode: string;
  tokenId: string;
  authToken: string;
  cert: string;
  remark: string;
  brand: string;
  model: string;
  architecture: string;
  serviceVersion: string;
  registerTime: number;
  lastHeartbeatMin: number;
  groupId: string | null;
  sdk: string;
  batt_percent: number;
};

type DeviceGroup = {
  id: string;
  name: string;
  color: string;
  builtinName?: "gemini" | "test";
  total?: number;
};

type GroupFilterId = "all" | "ungrouped" | string;

type GroupApiItem = {
  id: number;
  name: string;
  color?: string;
  total?: number;
};

type ListEnvelope<T> = {
  page?: number;
  size?: number;
  total?: number;
  data?: T[];
};

type DeviceApiItem = {
  domain: string;
  state: string;
  mode?: string;
  token_id?: string;
  auth_token?: string;
  cert?: string;
  comment?: string;
  remark?: string;
  locked?: boolean;
  brand?: string;
  model?: string;
  abi?: string;
  version?: string;
  register_time?: number;
  last_heartbeat_time?: number;
  sdk?: string | number;
  batt_percent?: string | number;
};

type PlatformConfig = {
  top_endpoint: string;
  top_ckey: string;
  sapi_ckey: string;
  public_ip: string;
  web_port: string;
  top_server: string;
};

type ForwardConfigDevice = {
  domain: string;
  token_id: string;
  cert: string;
  auth_token: string;
};
const GROUP_COLOR_POOL = ["#22c55e", "#3b82f6", "#a855f7", "#f59e0b", "#14b8a6", "#ef4444"];

function randomHexColor() {
  const n = Math.floor(Math.random() * 0xffffff);
  return `#${n.toString(16).padStart(6, "0")}`;
}

function normalizeStatus(state: string, _locked: boolean): DeviceStatus {
  if (state === "pending") return "pending";
  if (state === "online") return "online";
  return "offline";
}

function mapDeviceFromApi(device: DeviceApiItem, groupId: string | null): DeviceRecord {
  const now = Math.floor(Date.now() / 1000);
  const status = normalizeStatus(String(device.state || ""), Boolean(device.locked));
  const rawHeartbeat = Number(device.last_heartbeat_time || 0);
  const heartbeat = status === "pending" || rawHeartbeat <= 0
    ? -1
    : Math.max(0, Math.floor((now - rawHeartbeat) / 60));
  const sdk = String(device.sdk || "-");
  const batt_percent = normalizeBatteryPercent(device.batt_percent);
  return {
    id: String(device.domain || ""),
    status,
    mode: String(device.mode || ""),
    tokenId: String(device.token_id || ""),
    authToken: String(device.auth_token || ""),
    cert: String(device.cert || ""),
    remark: String(device.comment ?? device.remark ?? ""),
    brand: String(device.brand || "-"),
    model: String(device.model || "-"),
    architecture: String(device.abi || "-"),
    serviceVersion: String(device.version || "-"),
    registerTime: Number(device.register_time || 0),
    lastHeartbeatMin: heartbeat,
    groupId,
    sdk,
    batt_percent,
  };
}

function normalizeBatteryPercent(value: number | string | undefined) {
  const raw = Number(value || 0);
  if (!Number.isFinite(raw)) return 100;
  const clamped = Math.min(100, Math.max(0, raw));
  return clamped === 0 ? 100 : clamped;
}

function batteryColor(percent: number) {
  const p = Math.min(100, Math.max(0, percent));
  const hue = Math.round((p / 100) * 120);
  return `hsl(${hue} 85% 45%)`;
}

function statusTextColor(status: DeviceStatus) {
  if (status === "online") return "text-[var(--status-online)]";
  if (status === "offline") return "text-[var(--status-offline)]";
  return "text-[var(--status-busy)]";
}

function statusBadgeClass(status: DeviceStatus) {
  if (status === "online") {
    return "border-transparent bg-[var(--status-online)]/12 text-[var(--status-online)]";
  }
  if (status === "offline") {
    return "border-transparent bg-[var(--status-offline)]/12 text-[var(--status-offline)]";
  }
  return "border-transparent bg-[var(--status-busy)]/12 text-[var(--status-busy)]";
}

function formatHeartbeat(template: string, min: number) {
  if (min < 0) return "-";
  return interpolate(template, { min });
}

function formatTimestamp(timestamp: number) {
  if (!timestamp) return "-";
  const d = new Date(timestamp * 1000);
  if (Number.isNaN(d.getTime())) return "-";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function runWithConcurrency<T>(
  list: T[],
  limit: number,
  task: (item: T) => Promise<void>,
) {
  if (!list.length) return;
  let cursor = 0;
  const workerCount = Math.min(Math.max(1, limit), list.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const idx = cursor++;
      if (idx >= list.length) return;
      await task(list[idx]);
    }
  });
  await Promise.all(workers);
}

const router = useHashRouter();
const hashPathname = useHashPathname();
const { t } = useTranslation();
const targetGroupId = computed(() => {
  const matched = matchHashPath(hashPathname.value, /^\/devices\/group\/([^/]+)$/);
  return (matched || "").trim();
});

const groups = ref<DeviceGroup[]>([]);
const devices = ref<DeviceRecord[]>([]);
const loadError = ref<string | null>(null);
const loading = ref(false);
const summary = ref({ total: 0, usable: 0, working: 0, offline: 0, ungrouped: 0 });
const selectedGroupId = ref<GroupFilterId>("all");
const groupKeyword = ref("");

const deviceKeyword = ref("");
const deferredDeviceKeyword = computed(() => deviceKeyword.value);

const statusFilter = ref<Set<DeviceStatus>>(new Set());

type ColumnKey = "deviceId" | "status" | "brand" | "model" | "architecture" | "serviceVersion" | "registerTime" | "heartbeat" | "sdk" | "batt_percent" | "remark";
const ALL_COLUMNS: ColumnKey[] = ["deviceId", "status", "brand", "model", "architecture", "serviceVersion", "registerTime", "heartbeat", "sdk", "batt_percent", "remark"];
const DEFAULT_VISIBLE_COLUMNS: ColumnKey[] = ["deviceId", "status", "brand", "serviceVersion", "heartbeat", "sdk", "batt_percent"];
const STATUS_OPTIONS: DeviceStatus[] = ["online", "pending", "offline"];
const DROPDOWN_CHECKBOX_ITEM_CLASS =
  "focus:bg-accent focus:text-accent-foreground relative flex cursor-default items-center gap-2 rounded-sm py-1.5 pr-2 pl-8 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4";
const visibleColumns = ref<Set<ColumnKey>>(new Set(DEFAULT_VISIBLE_COLUMNS));
const editingRemarkId = ref<string | null>(null);
const remarkDraft = ref("");
const savingRemarkId = ref<string | null>(null);

const toggleColumn = (col: ColumnKey) => {
  const next = new Set(visibleColumns.value);
  if (next.has(col)) next.delete(col);
  else next.add(col);
  visibleColumns.value = next;
};

const toggleStatusFilter = (s: DeviceStatus, checked: boolean) => {
  const next = new Set(statusFilter.value);
  if (checked) next.add(s);
  else next.delete(s);
  statusFilter.value = next;
};

const selectedIds = ref<Set<string>>(new Set());
const moveGroupOpen = ref(false);
const groupMenuOpenId = ref<string | null>(null);
const groupDeleteConfirmId = ref<string | null>(null);
const moveGroupSearch = ref("");
const moveGroupItems = ref<DeviceGroup[]>([]);
const moveGroupsLoading = ref(false);
const movingGroup = ref(false);
const restarting = ref(false);
const deleting = ref(false);
const restartConfirmOpen = ref(false);
const deleteConfirmOpen = ref(false);
const restartDone = ref(0);
const restartTotal = ref(0);
const actionError = ref<{ id: number; text: string } | null>(null);
const actionMessage = ref<{ id: number; text: string } | null>(null);

const createGroupOpen = ref(false);
const createGroupName = ref("");
const createGroupError = ref<string | null>(null);
const createGroupColor = ref<string>(randomHexColor());
const createGroupColorOpen = ref(false);

const addDeviceOpen = ref(false);
const tokenConfigOpen = ref(false);
const tokenConfigLoading = ref(false);
const tokenConfigError = ref("");
const tokenConfigTip = ref<{ id: number; text: string; variant: "success" | "error" } | null>(null);
const tokenConfigToken = ref("");
const tokenConfigMode = ref<"p2p" | "forward">("p2p");
const platformConfig = ref<PlatformConfig | null>(null);
const forwardConfigDevice = ref<ForwardConfigDevice | null>(null);
const page = ref(1);
const pageSize = ref(100);
const sortConfig = ref<{ key: string; order: "asc" | "desc" } | null>(null);
const pageTotal = ref(0);
const requestRef = { current: 0 };
const moveGroupRequestRef = { current: 0 };

const bytesToBase64 = (bytes: Uint8Array) => {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
};

const toBase64 = (input: string) => {
  try {
    const encoded = new TextEncoder().encode(input);
    return bytesToBase64(encoded);
  } catch {
    return btoa(input);
  }
};

const ensurePlatformConfig = async () => {
  if (platformConfig.value) return platformConfig.value;
  const res = await apiRequest<{
    top_endpoint?: string;
    top_ckey?: string;
    public_ip?: string;
    sapi_ckey?: string;
    web_port?: string | number;
    top_server?: string;
  }>(`/api/v1/platform/config`, {
    method: "GET",
    errorMessage: "Failed to load platform config",
  });
  const next: PlatformConfig = {
    top_endpoint: String(res.data?.top_endpoint || ""),
    top_ckey: String(res.data?.top_ckey || ""),
    public_ip: String(res.data?.public_ip || ""),
    web_port: String(res.data?.web_port || ""),
    top_server: String(res.data?.top_server || ""),
    sapi_ckey: String(res.data?.sapi_ckey || ""),
  };
  platformConfig.value = next;
  return next;
};

const buildForwardConfigText = (cfg: PlatformConfig, device: ForwardConfigDevice) => {
  return [
    "[pigeon]",
    `properties.remote=http://${cfg.public_ip}:${cfg.web_port}/properties/${device.domain}`,
    `properties.ckey=${cfg.sapi_ckey}`,
    `properties.tries=64`,
  ].join("\n");
};

const tokenConfigText = computed(() => {
  if (!platformConfig.value) return "";
  if (tokenConfigMode.value === "p2p") {
    if (!tokenConfigToken.value) return "";
    return toBase64(`${platformConfig.value.top_endpoint}|${platformConfig.value.top_ckey}|${tokenConfigToken.value}`);
  }
  if (!forwardConfigDevice.value) return "";
  return buildForwardConfigText(platformConfig.value, forwardConfigDevice.value);
});

const openTokenConfig = async (
  token: string,
  mode: "p2p" | "forward" = "p2p",
  forwardDevice?: ForwardConfigDevice,
) => {
  const nextToken = String(token || "");
  tokenConfigMode.value = mode;
  tokenConfigToken.value = nextToken;
  forwardConfigDevice.value = mode === "forward" ? (forwardDevice || null) : null;
  tokenConfigError.value = "";
  tokenConfigOpen.value = true;
  if (!nextToken && mode === "p2p") {
    tokenConfigError.value = t.value.devices.p2pConfigNoToken;
    return;
  }
  tokenConfigLoading.value = true;
  try {
    await ensurePlatformConfig();
  } catch (error: any) {
    tokenConfigError.value = interpolate(t.value.devices.p2pConfigLoadFailed, { message: String(error?.message || "unknown") });
  } finally {
    tokenConfigLoading.value = false;
  }
};

const closeTokenConfig = () => {
  tokenConfigOpen.value = false;
  tokenConfigLoading.value = false;
  tokenConfigError.value = "";
  tokenConfigTip.value = null;
  tokenConfigToken.value = "";
  forwardConfigDevice.value = null;
};

const copyTokenConfig = async () => {
  if (!tokenConfigText.value) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(tokenConfigText.value);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = tokenConfigText.value;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    tokenConfigTip.value = { id: Date.now() + Math.random(), text: t.value.devices.p2pConfigCopied, variant: "success" };
  } catch {
    tokenConfigTip.value = { id: Date.now() + Math.random(), text: t.value.devices.p2pConfigCopyFailed, variant: "error" };
  }
};

const loadGroupsAndSummary = async () => {
  const [groupsResp, infoResp, ungroupedResp] = await Promise.all([
    apiRequest<ListEnvelope<GroupApiItem>>(`/api/v1/group?page=1&size=1000`, {
      method: "GET",
      errorMessage: "Failed to load groups",
    }),
    apiRequest<{ total?: number; usable?: number; working?: number; offline?: number }>(`/api/v1/summary`, {
      method: "GET",
      errorMessage: "Failed to load summary",
    }),
    apiRequest<ListEnvelope<DeviceApiItem>>(`/api/v1/ungrouped/devices?page=1&size=1`, {
      method: "GET",
      errorMessage: "Failed to load ungrouped count",
    }),
  ]);

  const groupItems = Array.isArray(groupsResp.data?.data) ? groupsResp.data.data : [];
  const mappedGroups: DeviceGroup[] = groupItems.map((g, idx) => ({
    id: String(g.id),
    name: String(g.name || ""),
    color: g.color || GROUP_COLOR_POOL[idx % GROUP_COLOR_POOL.length],
    total: Number(g.total || 0),
  }));
  groups.value = mappedGroups;
  summary.value = {
    total: Number(infoResp.data?.total || 0),
    usable: Number(infoResp.data?.usable || 0),
    working: Number(infoResp.data?.working || 0),
    offline: Number(infoResp.data?.offline || 0),
    ungrouped: Number(ungroupedResp.data?.total || 0),
  };
};

const loadMoveGroups = async (keyword: string) => {
  const currentReq = ++moveGroupRequestRef.current;
  moveGroupsLoading.value = true;
  try {
    const params = new URLSearchParams();
    params.set("page", "1");
    params.set("size", "20");
    params.set("sort", "order");
    params.set("order", "asc");
    const q = keyword.trim();
    if (q) {
      params.set("filter", JSON.stringify([{ field: "name", op: "like", value: q }]));
    }
    const resp = await apiRequest<ListEnvelope<GroupApiItem>>(`/api/v1/group?${params.toString()}`, {
      method: "GET",
      errorMessage: t.value.devices.moveGroupFailed,
    });
    if (currentReq !== moveGroupRequestRef.current) return;
    const list = Array.isArray(resp.data?.data) ? resp.data.data : [];
    moveGroupItems.value = list.map((g, idx) => ({
      id: String(g.id),
      name: String(g.name || ""),
      color: g.color || GROUP_COLOR_POOL[idx % GROUP_COLOR_POOL.length],
      total: Number(g.total || 0),
    }));
  } catch {
    if (currentReq !== moveGroupRequestRef.current) return;
    moveGroupItems.value = [];
  } finally {
    if (currentReq === moveGroupRequestRef.current) {
      moveGroupsLoading.value = false;
    }
  }
};

const buildDeviceApiQuery = () => {
  const sortMap: Record<string, string> = {
    deviceId: "domain",
    status: "state",
    brand: "brand",
    model: "model",
    architecture: "abi",
    serviceVersion: "version",
    registerTime: "register_time",
    heartbeat: "last_heartbeat_time",
  };
  const sortField = sortConfig.value?.key ? sortMap[sortConfig.value.key] || "id" : "id";
  const order = sortConfig.value?.order || "asc";
  const filterItems: Array<{ field: string; op: string; value: unknown }> = [];

  const raw = deferredDeviceKeyword.value.trim().toLowerCase();
  if (raw) {
    const tokens = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (tokens.length > 1 || raw.includes(",")) {
      filterItems.push({ field: "domain", op: "in", value: tokens });
    } else if (tokens.length === 1) {
      filterItems.push({ field: "domain", op: "like", value: tokens[0] });
    }
  }

  if (statusFilter.value.size > 0) {
    const states = Array.from(new Set(Array.from(statusFilter.value)));
    filterItems.push({ field: "state", op: "in", value: states });
  }

  const params = new URLSearchParams();
  params.set("page", String(page.value));
  params.set("size", String(pageSize.value));
  params.set("sort", sortField);
  params.set("order", order);
  if (filterItems.length > 0) {
    params.set("filter", JSON.stringify(filterItems));
  }
  return params;
};

const loadDeviceList = async () => {
  const currentReq = ++requestRef.current;
  loading.value = true;
  loadError.value = null;
  try {
    const params = buildDeviceApiQuery();
    let baseUrl = `/api/v1/device?${params.toString()}`;
    if (selectedGroupId.value === "ungrouped") {
      baseUrl = `/api/v1/ungrouped/devices?${params.toString()}`;
    } else if (selectedGroupId.value !== "all") {
      baseUrl = `/api/v1/group/${selectedGroupId.value}/devices?${params.toString()}`;
    }
    const listResp = await apiRequest<ListEnvelope<DeviceApiItem>>(baseUrl, {
      method: "GET",
      errorMessage: "Failed to load devices",
    });
    if (currentReq !== requestRef.current) return;

    const listItems = Array.isArray(listResp.data?.data) ? listResp.data.data : [];
    const total = Number(listResp.data?.total || 0);
    const remoteTotalPages = Math.max(1, Math.ceil(total / pageSize.value));
    if (page.value > remoteTotalPages) {
      page.value = remoteTotalPages;
      return;
    }
    const mapped = listItems
      .map((d) => mapDeviceFromApi(d, selectedGroupId.value === "all" || selectedGroupId.value === "ungrouped" ? null : String(selectedGroupId.value)))
      .filter((d) => d.id);
    devices.value = mapped;
    pageTotal.value = total;
    selectedIds.value = new Set();
  } catch (err) {
    if (currentReq !== requestRef.current) return;
    loadError.value = formatApiError(err, "Failed to load devices");
    devices.value = [];
    pageTotal.value = 0;
  } finally {
    if (currentReq === requestRef.current) loading.value = false;
  }
};

onMounted(() => {
  loadGroupsAndSummary().catch((err) => {
    loadError.value = formatApiError(err, "Failed to load groups");
  });
});

watch([hashPathname, targetGroupId], () => {
  if (targetGroupId.value) {
    if (selectedGroupId.value !== targetGroupId.value) selectedGroupId.value = targetGroupId.value;
    page.value = 1;
    return;
  }
  if (hashPathname.value === "/devices") {
    if (selectedGroupId.value !== "all") selectedGroupId.value = "all";
  }
}, { immediate: true });

watch([selectedGroupId, deferredDeviceKeyword, statusFilter, sortConfig, page, pageSize], () => {
  void loadDeviceList();
}, { immediate: true });

watch([moveGroupOpen, moveGroupSearch], (_, __, onCleanup) => {
  if (!moveGroupOpen.value) return;
  const timer = window.setTimeout(() => {
    void loadMoveGroups(moveGroupSearch.value);
  }, 180);
  onCleanup(() => window.clearTimeout(timer));
});

const showActionError = (text: string) => {
  actionError.value = { id: Date.now() + Math.random(), text };
};
const showActionMessage = (text: string) => {
  actionMessage.value = { id: Date.now() + Math.random(), text };
};

const handleSort = (key: string) => {
  const prev = sortConfig.value;
  if (prev?.key === key) {
    sortConfig.value = prev.order === "asc" ? { key, order: "desc" } : null;
  } else {
    sortConfig.value = { key, order: "asc" };
  }
  page.value = 1;
};

const headerColumns: Array<{ col: ColumnKey; sortKey?: string }> = [
  { col: "deviceId", sortKey: "deviceId" },
  { col: "status", sortKey: "status" },
  { col: "brand", sortKey: "brand" },
  { col: "model", sortKey: "model" },
  { col: "architecture", sortKey: "architecture" },
  { col: "sdk", sortKey: "sdk" },
  { col: "batt_percent", sortKey: "batt_percent" },
  { col: "remark" },
  { col: "serviceVersion", sortKey: "serviceVersion" },
  { col: "registerTime", sortKey: "registerTime" },
  { col: "heartbeat", sortKey: "heartbeat" },
];

const counts = computed(() => {
  const groupMap = new Map<string, number>();
  const onlineMap = new Map<string, number>();
  for (const group of groups.value) {
    groupMap.set(group.id, Number(group.total || 0));
    onlineMap.set(group.id, 0);
  }
  return {
    all: summary.value.total,
    ungrouped: summary.value.ungrouped,
    groupMap,
    onlineMap,
    totalOnline: summary.value.usable,
    totalPending: summary.value.working,
    totalOffline: summary.value.offline,
  };
});

const getGroupName = (group: DeviceGroup) => {
  if (!group.builtinName) return group.name;
  return t.value.devices.defaultGroupNames[group.builtinName];
};

const getStatusLabel = (status: DeviceStatus) => {
  if (status === "online") return t.value.devices.statusText.online;
  if (status === "offline") return t.value.devices.statusText.offline;
  return t.value.devices.statusText.pending;
};

const modeIconComponent = (mode: string) => {
  if (mode === "p2p") return Link2;
  if (mode === "forward") return ArrowRightLeft;
  return Wifi;
};

const visibleGroups = computed(() => {
  const keyword = groupKeyword.value.trim().toLowerCase();
  if (!keyword) return groups.value;
  return groups.value.filter((group) => getGroupName(group).toLowerCase().includes(keyword));
});

// Reset page when filters change
watch([selectedGroupId, deferredDeviceKeyword, statusFilter], () => {
  page.value = 1;
});

const totalPages = computed(() => Math.max(1, Math.ceil(pageTotal.value / pageSize.value)));
const safePage = computed(() => Math.min(page.value, totalPages.value));
const pagedRows = devices;

const selectedInFiltered = computed(() => {
  let count = 0;
  for (const d of pagedRows.value) {
    if (selectedIds.value.has(d.id)) count += 1;
  }
  return count;
});

const allFilteredSelected = computed(() => pagedRows.value.length > 0 && selectedInFiltered.value === pagedRows.value.length);
const partialFilteredSelected = computed(() => selectedInFiltered.value > 0 && !allFilteredSelected.value);

const onToggleSelectAllFiltered = () => {
  const next = new Set(selectedIds.value);
  if (allFilteredSelected.value) {
    for (const d of pagedRows.value) next.delete(d.id);
  } else {
    for (const d of pagedRows.value) next.add(d.id);
  }
  selectedIds.value = next;
};

const onToggleDevice = (deviceId: string, checked: boolean) => {
  const next = new Set(selectedIds.value);
  if (checked) next.add(deviceId);
  else next.delete(deviceId);
  selectedIds.value = next;
};

const selectedDevices = computed(() => {
  const selectedSet = selectedIds.value;
  return devices.value.filter((d) => selectedSet.has(d.id));
});

watch(() => selectedIds.value.size, (size) => {
  if (size > 0) return;
  restartConfirmOpen.value = false;
  deleteConfirmOpen.value = false;
});

const onMoveToGroup = async (targetGroupId: string) => {
  if (movingGroup.value || restarting.value || deleting.value) return;
  if (!selectedIds.value.size) {
    showActionError(t.value.devices.selectDevicesFirst);
    return;
  }
  if (!targetGroupId) return;
  actionError.value = null;
  actionMessage.value = null;
  movingGroup.value = true;
  try {
    await apiRequest(`/api/v1/group/${targetGroupId}/devices`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        devices: JSON.stringify(Array.from(selectedIds.value)),
      }).toString(),
      errorMessage: t.value.devices.moveGroupFailed,
    });
    moveGroupOpen.value = false;
    moveGroupSearch.value = "";
    showActionMessage(interpolate(t.value.devices.moveGroupSuccess, { n: selectedIds.value.size }));
    selectedIds.value = new Set();
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
  } catch (err) {
    showActionError(formatApiError(err, t.value.devices.moveGroupFailed));
  } finally {
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
    movingGroup.value = false;
  }
};

const rebootDevice = async (deviceId: string) => {
  const response = await fetch(`/d/${encodeURIComponent(deviceId)}/reboot`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
};

const onRestartSelected = async () => {
  if (restarting.value || movingGroup.value || deleting.value) return;
  if (!selectedIds.value.size) {
    showActionError(t.value.devices.selectDevicesFirst);
    return;
  }
  const onlineIds = Array.from(new Set(
    selectedDevices.value
      .filter((d) => d.status === "online")
      .map((d) => d.id),
  ));
  if (!onlineIds.length) {
    showActionError(t.value.devices.noOnlineDevices);
    return;
  }
  actionError.value = null;
  actionMessage.value = null;
  restarting.value = true;
  restartDone.value = 0;
  restartTotal.value = onlineIds.length;
  let successCount = 0;
  let failedCount = 0;
  try {
    await runWithConcurrency(onlineIds, 16, async (deviceId) => {
      try {
        await rebootDevice(deviceId);
        successCount += 1;
      } catch {
        failedCount += 1;
      } finally {
        restartDone.value += 1;
      }
    });
    if (failedCount > 0) {
      showActionError(interpolate(t.value.devices.restartPartial, { ok: successCount, failed: failedCount }));
    } else {
      showActionMessage(interpolate(t.value.devices.restartSuccess, { ok: successCount }));
    }
  } catch {
    showActionError(t.value.devices.restartFailed);
  } finally {
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
    restarting.value = false;
  }
};

const onDeleteSelected = async () => {
  if (deleting.value || movingGroup.value || restarting.value) return;
  if (!selectedIds.value.size) {
    showActionError(t.value.devices.selectDevicesFirst);
    return;
  }
  actionError.value = null;
  actionMessage.value = null;
  deleting.value = true;
  const ids = Array.from(selectedIds.value);
  let successCount = 0;
  let failedCount = 0;
  try {
    await runWithConcurrency(ids, 16, async (deviceId) => {
      try {
        await apiRequest(`/api/v1/device/${encodeURIComponent(deviceId)}`, {
          method: "DELETE",
          errorMessage: t.value.devices.deleteFailed,
        });
        successCount += 1;
      } catch {
        failedCount += 1;
      }
    });
    if (failedCount > 0) {
      showActionError(interpolate(t.value.devices.deletePartial, { ok: successCount, failed: failedCount }));
    } else {
      showActionMessage(interpolate(t.value.devices.deleteSuccess, { ok: successCount }));
    }
    selectedIds.value = new Set();
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
  } catch (err) {
    showActionError(formatApiError(err, t.value.devices.deleteFailed));
  } finally {
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
    deleting.value = false;
  }
};

const onCreateGroup = async () => {
  const name = createGroupName.value.trim();
  if (!name) {
    createGroupError.value = t.value.devices.errors.emptyGroupName;
    return;
  }
  const normalizedName = name.toLowerCase();
  const exists = groups.value.some((group) => {
    if (group.name.toLowerCase() === normalizedName) return true;
    if (group.builtinName) {
      return t.value.devices.defaultGroupNames[group.builtinName].toLowerCase() === normalizedName;
    }
    return false;
  });
  if (exists) {
    createGroupError.value = t.value.devices.errors.duplicateGroupName;
    return;
  }
  try {
    const color = createGroupColor.value || GROUP_COLOR_POOL[groups.value.length % GROUP_COLOR_POOL.length];
    const created = await apiRequest<{ id?: number }>(`/api/v1/group`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        name,
        description: "",
        color,
      }).toString(),
      errorMessage: "Failed to create group",
    });
    const createdId = created.data?.id ? String(created.data.id) : "all";
    createGroupName.value = "";
    createGroupError.value = null;
    createGroupColorOpen.value = false;
    createGroupOpen.value = false;
    await loadGroupsAndSummary();
    if (createdId !== "all") selectedGroupId.value = createdId;
  } catch (err) {
    createGroupError.value = formatApiError(err, "Failed to create group");
  }
};

const onDeleteGroup = async (groupId: string) => {
  if (!groupId) return;
  try {
    await apiRequest(`/api/v1/group/${groupId}`, {
      method: "DELETE",
      errorMessage: t.value.devices.deleteGroupFailed,
    });
    if (selectedGroupId.value === groupId) {
      selectedGroupId.value = "all";
    }
    groupMenuOpenId.value = null;
    groupDeleteConfirmId.value = null;
    showActionMessage(t.value.devices.deleteGroupSuccess);
    await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
  } catch (err) {
    showActionError(formatApiError(err, t.value.devices.deleteGroupFailed));
  }
};

const onAddDevice = async (data: any) => {
  try {
    if (data.mode === "p2p") {
      const created = await apiRequest<any>(`/api/v1/device`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          mode: "p2p",
          comment: String(data.remark || ""),
        }).toString(),
        errorMessage: "Failed to add device",
      });
      const token = String(created?.data?.token_id || created?.data?.token || "");
      if (token) {
        await openTokenConfig(token, "p2p");
      }
      await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
      return created;
    } else if (data.mode === "forward") {
      const params = new URLSearchParams({ mode: "forward" });
      const remark = String(data.remark || "").trim();
      if (remark) params.set("comment", remark);
      const created = await apiRequest<any>(`/api/v1/device`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
        errorMessage: "Failed to add device",
      });
      const token = String(created?.data?.token_id || created?.data?.token || "");
      if (token) {
        await openTokenConfig(token, "forward", {
          domain: String(created?.data?.domain || ""),
          token_id: token,
          cert: String(created?.data?.cert || ""),
          auth_token: String(created?.data?.auth_token || ""),
        });
      }
      await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
      return created;
    } else if (data.mode === "direct" && data.addressMode === "segment") {
      const scanned = await apiRequest<any>(`/api/v1/device`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          mode: "scan",
          ip_start: String(data.rangeStart || ""),
          ip_end: String(data.rangeEnd || ""),
          port: String(data.port || ""),
        }).toString(),
        errorMessage: "Failed to scan devices",
      });
      return scanned;
    } else {
      const created = await apiRequest(`/api/v1/device`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          mode: "direct",
          ip: String(data.ip || ""),
          port: String(data.port || ""),
          comment: String(data.remark || ""),
        }).toString(),
        errorMessage: "Failed to add device",
      });
      await Promise.all([loadGroupsAndSummary(), loadDeviceList()]);
      return created;
    }
  } catch (err) {
    throw err;
  }
};

const onOpenDevice = async (device: DeviceRecord) => {
  if (device.status === "pending") {
    if (device.mode === "p2p" && device.tokenId) {
      await openTokenConfig(device.tokenId, "p2p");
      return;
    }
    if (device.mode === "forward") {
      await openTokenConfig(device.tokenId || "", "forward", {
        domain: device.id,
        token_id: device.tokenId,
        cert: device.cert,
        auth_token: device.authToken,
      });
      return;
    }
    if (!device.tokenId) {
      showActionError(t.value.devices.pendingDeviceWaiting);
      return;
    }
    showActionError(t.value.devices.pendingDeviceWaiting);
    return;
  }
  router.push(`/devices/${encodeURIComponent(device.id)}`);
};

const startRemarkEdit = (device: DeviceRecord) => {
  if (savingRemarkId.value === device.id) return;
  editingRemarkId.value = device.id;
  remarkDraft.value = device.remark || "";
};

const cancelRemarkEdit = () => {
  editingRemarkId.value = null;
  remarkDraft.value = "";
};

const saveRemark = async (device: DeviceRecord) => {
  const next = remarkDraft.value.trim();
  if (next === (device.remark || "").trim()) {
    cancelRemarkEdit();
    return;
  }
  savingRemarkId.value = device.id;
  try {
    await apiRequest(`/api/v1/device/${encodeURIComponent(device.id)}/comment`, {
      method: "PUT",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ comment: next }).toString(),
      errorMessage: t.value.devices.remarkUpdateFailed,
    });
    devices.value = devices.value.map((item) => (item.id === device.id ? { ...item, remark: next } : item));
    showActionMessage(t.value.devices.remarkUpdated);
    cancelRemarkEdit();
  } catch (err) {
    showActionError(formatApiError(err, t.value.devices.remarkUpdateFailed));
  } finally {
    if (savingRemarkId.value === device.id) savingRemarkId.value = null;
  }
};

const activeGroupLabel = computed(() => {
  if (selectedGroupId.value === "all") return t.value.devices.allDevices;
  if (selectedGroupId.value === "ungrouped") return t.value.devices.ungrouped;
  const g = groups.value.find((g) => g.id === selectedGroupId.value);
  return g ? getGroupName(g) : "";
});

const pageItems = computed(() =>
  Array.from({ length: totalPages.value }, (_, i) => i + 1)
    .filter((n) => n === 1 || n === totalPages.value || Math.abs(n - safePage.value) <= 1)
    .reduce<(number | "ellipsis")[]>((acc, n, i, arr) => {
      if (i > 0 && n - (arr[i - 1] as number) > 1) acc.push("ellipsis");
      acc.push(n);
      return acc;
    }, []),
);

const onCreateGroupDialogOpenChange = (open: boolean) => {
  createGroupOpen.value = open;
  if (!open) {
    createGroupError.value = null;
    createGroupColorOpen.value = false;
  } else {
    createGroupColor.value = randomHexColor();
  }
};

const onGroupItemKeydown = (e: KeyboardEvent, groupId: string) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    selectedGroupId.value = groupId;
  }
};

const onGroupMenuOpenChange = (open: boolean, groupId: string) => {
  groupMenuOpenId.value = open ? groupId : null;
  if (!open) groupDeleteConfirmId.value = null;
};

const onRemarkPopoverOpenChange = (open: boolean) => {
  if (!open) {
    cancelRemarkEdit();
  }
};

const onRemarkInputKeydown = (e: KeyboardEvent, device: DeviceRecord) => {
  if (e.key === "Enter") {
    e.preventDefault();
    void saveRemark(device);
  } else if (e.key === "Escape") {
    e.preventDefault();
    cancelRemarkEdit();
  }
};

const onPageSizeChange = (v: string) => {
  pageSize.value = Number(v);
  page.value = 1;
};

const goPushFiles = () => {
  sessionStorage.setItem("push_device_ids", JSON.stringify([...selectedIds.value]));
  router.push("/devices/push");
};

const goPullFiles = () => {
  sessionStorage.setItem("pull_device_ids", JSON.stringify([...selectedIds.value]));
  router.push("/devices/pull");
};

const goBatchCommand = () => {
  sessionStorage.setItem("push_device_ids", JSON.stringify([...selectedIds.value]));
  router.push("/devices/batch-command");
};

const onMoveGroupOpenChange = (open: boolean) => {
  moveGroupOpen.value = open;
  if (!open) {
    moveGroupSearch.value = "";
  } else {
    actionError.value = null;
    actionMessage.value = null;
  }
};

const onTokenConfigOpenChange = (open: boolean) => {
  if (!open) closeTokenConfig();
  else tokenConfigOpen.value = true;
};
</script>

<template>
  <div class="flex h-screen w-full overflow-hidden bg-[#f5f5f7]">
    <Sidebar />

    <div class="flex h-screen min-w-0 flex-1 flex-col lg:ml-[220px]">
      <!-- Header -->
      <header class="flex h-14 shrink-0 items-center justify-between border-b border-gray-100 bg-white px-5">
        <h1 class="text-base font-semibold text-gray-900">{{ t.devices.pageTitle }}</h1>

        <div class="flex items-center gap-2">
          <div class="hidden items-center gap-3 px-3 sm:flex">
            <span class="flex items-center gap-1.5 text-xs text-gray-500">
              <span class="h-1.5 w-1.5 rounded-full bg-[var(--status-online)]" />
              {{ counts.totalOnline.toLocaleString() }}
            </span>
            <span class="flex items-center gap-1.5 text-xs text-gray-500">
              <span class="h-1.5 w-1.5 rounded-full bg-[var(--status-busy)]" />
              {{ counts.totalPending.toLocaleString() }}
            </span>
            <span class="flex items-center gap-1.5 text-xs text-gray-500">
              <span class="h-1.5 w-1.5 rounded-full bg-[var(--status-offline)]" />
              {{ counts.totalOffline.toLocaleString() }}
            </span>
          </div>

          <Button
            size="sm"
            :disabled="loading"
            class="h-8 gap-1.5 rounded-lg bg-gray-900 px-3.5 text-xs font-medium text-white hover:bg-gray-800"
            @click="addDeviceOpen = true"
          >
            <Plus class="h-3.5 w-3.5" />
            {{ t.devices.addDevice }}
          </Button>
          <AddDeviceDialog
            :open="addDeviceOpen"
            @update:open="addDeviceOpen = $event"
            :on-confirm="onAddDevice"
          />
        </div>
      </header>

      <div class="flex min-h-0 flex-1 flex-col gap-2 overflow-hidden p-3">
      <DeviceStats
        class="shrink-0"
        :total="summary.total"
        :usable="summary.usable"
        :working="summary.working"
        :offline="summary.offline"
      />

      <main class="flex min-h-0 flex-1 gap-2 overflow-hidden xl:grid xl:grid-cols-[220px_minmax(0,1fr)]">
        <!-- Groups Panel -->
        <div class="flex h-full min-h-0 flex-col overflow-hidden">
          <Card class="flex h-full min-h-0 flex-col gap-0 overflow-hidden rounded-lg border border-gray-100 bg-white py-0 shadow-sm">
            <CardHeader class="shrink-0 border-b border-gray-50 px-0 pb-0">
              <div class="flex items-center justify-between p-2.5">
                <div class="flex items-center gap-2">
                  <CardTitle class="text-xs font-semibold text-gray-700">
                    {{ t.devices.groupsTitle }}
                  </CardTitle>
                </div>

                <Dialog
                  :open="createGroupOpen"
                  @update:open="onCreateGroupDialogOpenChange"
                >
                  <DialogTrigger as-child>
                    <Button variant="outline" size="sm" class="h-7 gap-1 rounded px-2 text-xs text-gray-500 hover:text-gray-700">
                      <FolderPlus class="h-3.5 w-3.5" />
                      {{ t.devices.newGroup }}
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>{{ t.devices.createGroupTitle }}</DialogTitle>
                    </DialogHeader>
                    <div class="space-y-2">
                      <Label for="group-name">{{ t.devices.fields.groupName }}</Label>
                      <div class="flex items-center gap-2">
                        <Input
                          id="group-name"
                          v-model="createGroupName"
                        />
                        <Popover :open="createGroupColorOpen" @update:open="createGroupColorOpen = $event">
                          <PopoverTrigger as-child>
                            <button
                              type="button"
                              class="h-9 w-9 shrink-0 rounded-md border border-gray-300"
                              :style="{ backgroundColor: createGroupColor }"
                              aria-label="Pick group color"
                              title="Pick group color"
                            />
                          </PopoverTrigger>
                          <PopoverContent align="end" :side-offset="8" class="w-auto p-2">
                            <HexColorPicker :color="createGroupColor" @change="createGroupColor = $event" />
                          </PopoverContent>
                        </Popover>
                      </div>
                    </div>
                    <FeedbackTip v-if="createGroupError" :message="createGroupError" variant="error" :compact="false" />
                    <DialogFooter>
                      <Button variant="outline" @click="createGroupOpen = false">
                        {{ t.devices.actions.cancel }}
                      </Button>
                      <Button @click="onCreateGroup">{{ t.devices.actions.create }}</Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </div>

              <div class="border-t border-gray-50 p-2.5">
                <div class="relative">
                  <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-gray-400" />
                  <Input
                    class="h-7 rounded-md border-0 bg-gray-50 pl-8 text-xs text-gray-600 placeholder:text-gray-400"
                    :placeholder="t.devices.searchGroupPlaceholder"
                    v-model="groupKeyword"
                  />
                </div>
              </div>
            </CardHeader>

            <CardContent class="min-h-0 flex-1 overflow-y-auto p-2.5">
              <div class="space-y-0.5">
                <button
                  type="button"
                  @click="selectedGroupId = 'all'"
                  :class="cn(
                    'group flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs transition-colors',
                    selectedGroupId === 'all'
                      ? 'bg-gray-100 font-medium text-gray-900'
                      : 'text-gray-600 hover:bg-gray-50',
                  )"
                >
                  <span class="shrink-0"><FolderOpen class="h-3.5 w-3.5" /></span>
                  <span class="flex-1">{{ t.devices.allDevices }}</span>
                  <span class="tabular-nums text-gray-400">{{ counts.all }}</span>
                </button>
                <button
                  type="button"
                  @click="selectedGroupId = 'ungrouped'"
                  :class="cn(
                    'group flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs transition-colors',
                    selectedGroupId === 'ungrouped'
                      ? 'bg-gray-100 font-medium text-gray-900'
                      : 'text-gray-600 hover:bg-gray-50',
                  )"
                >
                  <span class="shrink-0"><Folder class="h-3.5 w-3.5" /></span>
                  <span class="flex-1">{{ t.devices.ungrouped }}</span>
                  <span class="tabular-nums text-gray-400">{{ counts.ungrouped }}</span>
                </button>
              </div>

              <template v-if="groups.length > 0">
                <div class="px-2.5 pb-1 pt-3">
                  <p class="text-[10px] font-semibold uppercase tracking-wider text-gray-400">{{ t.devices.groups }}</p>
                </div>

                <div class="space-y-0.5">
                  <div
                    v-for="group in visibleGroups"
                    :key="group.id"
                    @click="selectedGroupId = group.id"
                    @keydown="onGroupItemKeydown($event, group.id)"
                    role="button"
                    tabindex="0"
                    :class="cn(
                      'group flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs transition-colors',
                      selectedGroupId === group.id
                        ? 'bg-gray-100 font-medium text-gray-900'
                        : 'text-gray-600 hover:bg-gray-50',
                    )"
                  >
                    <span
                      class="h-2.5 w-2.5 shrink-0 rounded-sm shadow-sm"
                      :style="{ backgroundColor: group.color }"
                    />
                    <span class="flex-1 truncate font-medium">{{ getGroupName(group) }}</span>
                    <span class="flex items-center gap-1">
                      <span
                        v-if="(counts.onlineMap.get(group.id) ?? 0) > 0"
                        class="h-1.5 w-1.5 rounded-full bg-[var(--status-online)]"
                      />
                      <span :class="cn('tabular-nums', (groupMenuOpenId === group.id || false) ? 'hidden' : 'group-hover:hidden', selectedGroupId === group.id ? 'text-gray-500' : 'text-gray-400')">
                        {{ counts.groupMap.get(group.id) ?? 0 }}
                      </span>
                      <Popover
                        :open="groupMenuOpenId === group.id"
                        @update:open="onGroupMenuOpenChange($event, group.id)"
                      >
                        <PopoverTrigger as-child>
                          <button
                            type="button"
                            :class="cn(
                              'hidden h-4 w-4 items-center justify-center rounded-sm text-muted-foreground/80 hover:bg-muted hover:text-foreground',
                              groupMenuOpenId === group.id ? 'inline-flex' : 'group-hover:inline-flex',
                            )"
                            @click.stop
                          >
                            <MoreVertical class="h-3.5 w-3.5" />
                          </button>
                        </PopoverTrigger>
                        <PopoverContent
                          align="end"
                          class="w-auto max-w-none py-1 px-1.5"
                          @click.stop
                        >
                          <div v-if="groupDeleteConfirmId === group.id" class="flex items-center justify-center gap-1">
                            <p class="whitespace-nowrap text-[11px] text-foreground">
                              {{ t.devices.deleteGroupConfirmDesc }}
                            </p>
                            <div class="flex items-center gap-1">
                              <Button
                                variant="outline"
                                size="sm"
                                class="h-5 px-1.5 text-[11px]"
                                @click.stop="groupDeleteConfirmId = null"
                              >
                                {{ t.devices.actions.cancel }}
                              </Button>
                              <Button
                                size="sm"
                                class="h-5 bg-red-600 px-1.5 text-[11px] text-white hover:bg-red-700"
                                @click.stop="void onDeleteGroup(group.id)"
                              >
                                {{ t.common.delete }}
                              </Button>
                            </div>
                          </div>
                          <Button
                            v-else
                            variant="ghost"
                            size="sm"
                            class="h-5 justify-center gap-1 px-1.5 text-[11px] text-red-600 hover:bg-red-50 hover:text-red-700 dark:text-red-400 dark:hover:bg-red-950/20"
                            @click.stop="groupDeleteConfirmId = group.id"
                          >
                            <Trash2 class="h-3.5 w-3.5" />
                            {{ t.common.delete }}
                          </Button>
                        </PopoverContent>
                      </Popover>
                    </span>
                  </div>

                  <div v-if="visibleGroups.length === 0" class="px-2 py-4 text-center text-xs text-muted-foreground">
                    {{ t.devices.noGroupFound }}
                  </div>
                </div>
              </template>
            </CardContent>
          </Card>
        </div>

        <!-- Device List Panel -->
        <Card class="h-full min-h-0 gap-0 overflow-hidden rounded-lg border border-gray-100 bg-white py-0 shadow-sm">
          <!-- List header -->
          <CardHeader class="gap-3 border-b border-gray-100 px-4 py-3">
            <FeedbackTip v-if="loadError" :message="loadError" variant="error" :compact="false" />
            <FeedbackTip v-if="actionError" :key="actionError.id" :toast-id="actionError.id" :message="actionError.text" variant="error" :compact="false" />
            <FeedbackTip v-if="actionMessage" :key="actionMessage.id" :toast-id="actionMessage.id" :message="actionMessage.text" variant="success" :compact="false" />
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <CardTitle class="text-sm font-semibold text-gray-800">{{ activeGroupLabel }}</CardTitle>
                <Badge variant="secondary" class="h-5 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 tabular-nums">
                  {{ pageTotal.toLocaleString() }}
                </Badge>
              </div>

              <!-- Toolbar -->
              <div class="flex items-center gap-2">
                <!-- Search -->
                <div class="relative">
                  <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    class="h-8 w-[200px] border-gray-200 pl-8 text-xs text-gray-600 placeholder:text-gray-400"
                    :placeholder="t.devices.filterByIdPlaceholder"
                    v-model="deviceKeyword"
                  />
                  <button
                    v-if="deviceKeyword"
                    type="button"
                    @click="deviceKeyword = ''"
                    class="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X class="h-3 w-3" />
                  </button>
                </div>

                <!-- Status filter pill -->
                <DropdownMenu>
                  <DropdownMenuTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      :class="cn(
                        'h-8 gap-1 border-dashed text-xs font-normal',
                        statusFilter.size > 0 && 'border-solid bg-accent',
                      )"
                    >
                      <ListFilter class="h-3.5 w-3.5" />
                      {{ t.devices.table.status }}
                      <template v-if="statusFilter.size > 0">
                        <Separator orientation="vertical" class="mx-0.5 h-4" />
                        <span class="flex gap-1">
                          <span
                            v-for="s in STATUS_OPTIONS.filter((s) => statusFilter.has(s))"
                            :key="s"
                            class="rounded-sm bg-background px-1 text-xs font-medium"
                          >
                            {{ getStatusLabel(s) }}
                          </span>
                        </span>
                      </template>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" class="w-40">
                    <DropdownMenuCheckboxItem
                      v-for="s in STATUS_OPTIONS"
                      :key="s"
                      :model-value="statusFilter.has(s)"
                      :class="DROPDOWN_CHECKBOX_ITEM_CLASS"
                      @update:model-value="toggleStatusFilter(s, $event)"
                    >
                      <span class="pointer-events-none absolute left-2 flex size-3.5 items-center justify-center">
                        <DropdownMenuItemIndicator>
                          <Check class="size-4" />
                        </DropdownMenuItemIndicator>
                      </span>
                      <span class="flex items-center gap-2">
                        <span
                          class="h-2 w-2 rounded-full"
                          :style="{
                            backgroundColor: s === 'online'
                              ? 'var(--status-online)'
                              : s === 'pending'
                              ? 'var(--status-busy)'
                              : 'var(--status-offline)',
                          }"
                        />
                        {{ getStatusLabel(s) }}
                      </span>
                    </DropdownMenuCheckboxItem>
                    <template v-if="statusFilter.size > 0">
                      <DropdownMenuSeparator />
                      <DropdownMenuCheckboxItem
                        :model-value="false"
                        :class="cn(DROPDOWN_CHECKBOX_ITEM_CLASS, 'text-muted-foreground')"
                        @update:model-value="statusFilter = new Set()"
                      >
                        <span class="pointer-events-none absolute left-2 flex size-3.5 items-center justify-center">
                          <DropdownMenuItemIndicator>
                            <Check class="size-4" />
                          </DropdownMenuItemIndicator>
                        </span>
                        {{ t.devices.clearFilters }}
                      </DropdownMenuCheckboxItem>
                    </template>
                  </DropdownMenuContent>
                </DropdownMenu>

                <!-- View - column toggle -->
                <div>
                  <DropdownMenu>
                    <DropdownMenuTrigger as-child>
                      <Button variant="outline" size="sm" class="h-8 gap-1.5 text-xs font-normal">
                        <Settings2 class="h-3.5 w-3.5" />
                        {{ t.devices.view }}
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" class="w-44">
                      <DropdownMenuLabel class="text-xs font-medium">{{ t.devices.columnToggle }}</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuCheckboxItem
                        v-for="col in ALL_COLUMNS"
                        :key="col"
                        :model-value="visibleColumns.has(col)"
                        :class="cn(DROPDOWN_CHECKBOX_ITEM_CLASS, 'capitalize')"
                        @update:model-value="toggleColumn(col)"
                      >
                        <span class="pointer-events-none absolute left-2 flex size-3.5 items-center justify-center">
                          <DropdownMenuItemIndicator>
                            <Check class="size-4" />
                          </DropdownMenuItemIndicator>
                        </span>
                        {{ t.devices.table[col] }}
                      </DropdownMenuCheckboxItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            </div>
          </CardHeader>

          <CardContent class="relative flex min-h-0 flex-1 flex-col p-0 overflow-hidden">
            <!-- Table -->
            <div v-if="loading" class="flex h-full flex-col items-center justify-center gap-3">
              <div class="rounded-xl bg-muted/50 p-3">
                <RotateCw class="h-6 w-6 animate-spin text-muted-foreground/60" />
              </div>
              <p class="text-xs font-medium text-muted-foreground">{{ t.common.loading }}</p>
            </div>
            <div v-else-if="pagedRows.length === 0" class="flex h-full flex-col items-center justify-center text-center">
              <EmptyState
                :title="selectedGroupId === 'all'
                  ? t.devices.emptyAllTitle
                  : interpolate(t.devices.emptyGroupTitle, { group: activeGroupLabel })"
                :description="selectedGroupId === 'all' ? t.devices.emptyAllDesc : t.devices.emptyGroupDesc"
              >
                <Button
                  v-if="selectedGroupId !== 'all'"
                  variant="outline"
                  size="sm"
                  @click="
                    selectedGroupId = 'all';
                    page = 1;
                  "
                >
                  {{ t.devices.viewAllDevices }}
                </Button>
              </EmptyState>
            </div>
            <div v-else class="min-h-0 flex-1 overflow-auto">
              <table class="w-full text-xs border-collapse">
                <thead class="sticky top-0 z-10 bg-background border-b border-border">
                  <tr class="border-b border-border">
                    <th class="px-3 py-2 w-10">
                      <Checkbox
                        :checked="allFilteredSelected ? true : partialFilteredSelected ? 'indeterminate' : false"
                        @update:checked="onToggleSelectAllFiltered()"
                        :aria-label="t.devices.selectAllFiltered"
                      />
                    </th>
                    <template v-for="hc in headerColumns" :key="hc.col">
                      <th
                        v-if="visibleColumns.has(hc.col)"
                        :class="cn(
                          'px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap',
                          hc.sortKey && 'cursor-pointer hover:text-foreground'
                        )"
                        @click="hc.sortKey && handleSort(hc.sortKey)"
                      >
                        <div class="flex items-center gap-1">
                          <span>{{ t.devices.table[hc.col] }}</span>
                          <template v-if="hc.sortKey && sortConfig?.key === hc.sortKey">
                            <ChevronUp v-if="sortConfig?.order === 'asc'" class="h-3.5 w-3.5" />
                            <ChevronDown v-else class="h-3.5 w-3.5" />
                          </template>
                        </div>
                      </th>
                    </template>
                    <th class="px-3 py-2 w-10" />
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="(device, idx) in pagedRows"
                    :key="device.id"
                    :class="cn(
                      'border-b border-border/50 transition-colors hover:bg-muted/40 cursor-pointer',
                      idx % 2 === 0 ? 'bg-background' : 'bg-muted/10',
                      selectedIds.has(device.id) && 'bg-muted/30',
                    )"
                  >
                    <td class="px-3 py-2 w-10" @click.stop>
                      <Checkbox
                        :checked="selectedIds.has(device.id)"
                        @update:checked="onToggleDevice(device.id, $event)"
                        :aria-label="`${t.devices.table.deviceId}: ${device.id}`"
                      />
                    </td>

                    <td v-if="visibleColumns.has('deviceId')" class="px-3 py-2" @click="void onOpenDevice(device)">
                      <div class="flex items-center gap-2 font-mono">
                        <component
                          :is="modeIconComponent(device.mode)"
                          :class="cn('h-3.5 w-3.5 shrink-0', statusTextColor(device.status))"
                          :stroke-width="2.6"
                        />
                        <span class="truncate">{{ device.id }}</span>
                      </div>
                    </td>

                    <td v-if="visibleColumns.has('status')" class="px-3 py-2" @click="void onOpenDevice(device)">
                      <Badge variant="outline" :class="cn('text-xs font-normal', statusBadgeClass(device.status))">
                        {{ getStatusLabel(device.status) }}
                      </Badge>
                    </td>

                    <td v-if="visibleColumns.has('brand')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      <span class="capitalize">{{ device.brand }}</span>
                    </td>

                    <td v-if="visibleColumns.has('model')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      {{ device.model }}
                    </td>

                    <td v-if="visibleColumns.has('architecture')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      {{ device.architecture }}
                    </td>

                    <td v-if="visibleColumns.has('sdk')" class="px-3 py-2 truncate" @click="void onOpenDevice(device)">
                      <Badge variant="secondary" class="text-xs">
                        {{ androidVersionFromSdk(device.sdk) }}
                      </Badge>
                    </td>

                    <td v-if="visibleColumns.has('batt_percent')" class="px-3 py-2 truncate" @click="void onOpenDevice(device)">
                      <div class="flex items-center gap-2">
                        <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/40">
                          <div
                            class="h-full transition-all"
                            :style="{
                              width: `${device.batt_percent}%`,
                              backgroundColor: batteryColor(device.batt_percent),
                            }"
                          />
                        </div>
                        <span class="min-w-[32px] text-right text-xs tabular-nums text-muted-foreground">{{ device.batt_percent }}%</span>
                      </div>
                    </td>

                    <td
                      v-if="visibleColumns.has('remark')"
                      class="px-3 py-2 truncate text-muted-foreground"
                      @click.stop="startRemarkEdit(device)"
                    >
                      <Popover
                        :open="editingRemarkId === device.id"
                        @update:open="onRemarkPopoverOpenChange"
                      >
                        <PopoverAnchor as-child>
                          <div class="w-full">
                            <span
                              class="block max-w-[160px] truncate text-xs text-muted-foreground"
                              :title="device.remark || '-'"
                            >
                              {{ device.remark || '-' }}
                            </span>
                          </div>
                        </PopoverAnchor>
                        <PopoverContent
                          align="start"
                          class="w-[320px] p-2.5"
                          @click.stop
                        >
                          <div class="space-y-2">
                            <p class="text-xs font-medium text-foreground">{{ t.devices.remarkEditTitle }}</p>
                            <Input
                              autofocus
                              v-model="remarkDraft"
                              :disabled="savingRemarkId === device.id"
                              class="h-8 text-xs"
                              :placeholder="t.devices.addDevice_remarkPlaceholder"
                              @keydown="onRemarkInputKeydown($event, device)"
                            />
                            <div class="flex justify-end gap-2">
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                class="h-7 px-3 text-xs"
                                @click="cancelRemarkEdit"
                                :disabled="savingRemarkId === device.id"
                              >
                                {{ t.devices.remarkCancel }}
                              </Button>
                              <Button
                                type="button"
                                size="sm"
                                class="h-7 px-3 text-xs"
                                @click="void saveRemark(device)"
                                :disabled="savingRemarkId === device.id"
                              >
                                {{ t.devices.remarkConfirm }}
                              </Button>
                            </div>
                          </div>
                        </PopoverContent>
                      </Popover>
                    </td>

                    <td v-if="visibleColumns.has('serviceVersion')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      {{ device.serviceVersion }}
                    </td>

                    <td v-if="visibleColumns.has('registerTime')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      {{ formatTimestamp(device.registerTime) }}
                    </td>

                    <td v-if="visibleColumns.has('heartbeat')" class="px-3 py-2 truncate text-muted-foreground" @click="void onOpenDevice(device)">
                      {{ formatHeartbeat(t.devices.heartbeatMinutesAgo, device.lastHeartbeatMin) }}
                    </td>

                    <td class="px-3 py-2 w-10 text-right" @click="void onOpenDevice(device)">
                      <ChevronRight class="h-4 w-4 text-muted-foreground opacity-0 hover:opacity-100 transition-opacity" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- Pagination footer -->
            <div class="flex h-12 shrink-0 items-center justify-between border-t border-border bg-background px-4">
              <!-- Rows per page -->
              <div class="flex items-center gap-2 text-sm text-muted-foreground">
                <Select
                  :model-value="String(pageSize)"
                  @update:model-value="onPageSizeChange"
                >
                  <SelectTrigger size="sm" class="h-7 w-24 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="n in [100, 300, 500, 700, 900]" :key="n" :value="String(n)" class="text-xs">{{ n }}</SelectItem>
                  </SelectContent>
                </Select>
                <span class="text-xs">{{ t.devices.pagination.rowsPerPage }}</span>
              </div>

              <!-- Page numbers -->
              <div class="flex items-center gap-1 text-sm text-muted-foreground">
                <span class="mr-2 text-xs">{{ t.devices.pagination.pageOf.replace('{current}', String(safePage)).replace('{total}', String(totalPages)) }}</span>
                <Button variant="outline" size="icon" class="h-7 w-7" @click="page = 1" :disabled="safePage <= 1">
                  <ChevronsLeft class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" class="h-7 w-7" @click="page = Math.max(1, page - 1)" :disabled="safePage <= 1">
                  <ChevronLeft class="h-3.5 w-3.5" />
                </Button>
                <!-- Page number pills -->
                <template v-for="(item, i) in pageItems" :key="item === 'ellipsis' ? `e${i}` : item">
                  <span v-if="item === 'ellipsis'" class="px-1 text-xs text-muted-foreground">...</span>
                  <Button
                    v-else
                    :variant="item === safePage ? 'default' : 'outline'"
                    size="icon"
                    class="h-7 w-7 text-xs"
                    @click="page = Number(item)"
                  >
                    {{ item }}
                  </Button>
                </template>
                <Button variant="outline" size="icon" class="h-7 w-7" @click="page = Math.min(totalPages, page + 1)" :disabled="safePage >= totalPages">
                  <ChevronRight class="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" class="h-7 w-7" @click="page = totalPages" :disabled="safePage >= totalPages">
                  <ChevronsRight class="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>

            <!-- Floating selection bar -->
            <div v-if="selectedIds.size > 0" class="absolute bottom-14 left-1/2 z-20 -translate-x-1/2">
              <div class="flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 shadow-sm">
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7"
                  @click="selectedIds = new Set()"
                >
                  <X class="h-3.5 w-3.5" />
                </Button>
                <div class="flex items-center gap-1.5">
                  <span class="flex h-5 min-w-5 items-center justify-center rounded-full bg-foreground px-1.5 text-xs font-semibold text-background">
                    {{ selectedIds.size }}
                  </span>
                  <span class="max-w-[220px] truncate whitespace-nowrap text-sm text-muted-foreground">
                    {{ selectedIds.size }} {{ t.devices.selectionActions.devicesSelected }}
                  </span>
                </div>
                <Separator orientation="vertical" class="h-5" />
                <template v-if="restarting || movingGroup">
                  <span class="max-w-[160px] truncate whitespace-nowrap text-xs text-muted-foreground">
                    {{ restarting
                      ? interpolate(t.devices.restartRunning, { done: restartDone, total: restartTotal })
                      : t.devices.moveGroupRunning }}
                  </span>
                  <Separator orientation="vertical" class="h-5" />
                </template>
                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-gray-200 bg-white px-2.5 text-[11px] font-medium text-gray-700 hover:bg-gray-50"
                      @click="goPushFiles"
                    >
                      <Upload class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.pushFiles }}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{{ t.devices.selectionActions.pushFiles }}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-gray-200 bg-white px-2.5 text-[11px] font-medium text-gray-700 hover:bg-gray-50"
                      @click="goPullFiles"
                    >
                      <Download class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.pullFiles }}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{{ t.devices.selectionActions.pullFiles }}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-gray-200 bg-white px-2.5 text-[11px] font-medium text-gray-700 hover:bg-gray-50"
                      @click="goBatchCommand"
                    >
                      <Terminal class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.batchCommand }}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{{ t.devices.selectionActions.batchCommand }}</TooltipContent>
                </Tooltip>
                <Popover
                  :open="moveGroupOpen"
                  @update:open="onMoveGroupOpenChange"
                >
                  <PopoverTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-gray-200 bg-white px-2.5 text-[11px] font-medium text-gray-700 hover:bg-gray-50"
                      :disabled="movingGroup || restarting || deleting"
                      :title="t.devices.selectionActions.moveToGroup"
                    >
                      <RotateCw v-if="movingGroup" class="h-3.5 w-3.5 animate-spin" />
                      <FolderUp v-else class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.moveToGroup }}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="center" class="w-[260px] p-0">
                    <div class="p-2">
                      <div class="relative">
                        <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          v-model="moveGroupSearch"
                          :placeholder="t.devices.searchGroupPlaceholder"
                          class="h-8 pl-8 text-xs"
                          autofocus
                        />
                      </div>
                    </div>
                    <div class="border-t border-border" />
                    <div class="max-h-[240px] overflow-y-auto py-1">
                      <div v-if="moveGroupsLoading" class="flex items-center justify-center gap-2 px-4 py-8 text-xs text-muted-foreground">
                        <RotateCw class="h-3.5 w-3.5 animate-spin" />
                        {{ t.common.loading }}
                      </div>
                      <div v-else-if="moveGroupItems.length === 0" class="px-4 py-8 text-center text-xs text-muted-foreground">
                        {{ t.devices.noGroupFound }}
                      </div>
                      <template v-else>
                        <button
                          v-for="group in moveGroupItems"
                          :key="group.id"
                          type="button"
                          class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/60"
                          @click="void onMoveToGroup(group.id)"
                          :disabled="movingGroup"
                        >
                          <span class="h-2.5 w-2.5 shrink-0 rounded-sm" :style="{ backgroundColor: group.color }" />
                          <span class="flex-1 truncate">{{ group.name }}</span>
                          <span class="text-xs text-muted-foreground tabular-nums">{{ group.total ?? 0 }}</span>
                        </button>
                      </template>
                    </div>
                  </PopoverContent>
                </Popover>
                <Popover :open="restartConfirmOpen" @update:open="restartConfirmOpen = $event">
                  <PopoverTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-amber-500/30 bg-amber-500/5 px-2.5 text-[11px] font-medium text-amber-700 hover:bg-amber-500/10 dark:text-amber-300"
                      :disabled="restarting || movingGroup || deleting"
                      :title="restarting
                        ? interpolate(t.devices.restartRunning, { done: restartDone, total: restartTotal })
                        : t.devices.selectionActions.restart"
                    >
                      <RotateCw v-if="restarting" class="h-3.5 w-3.5 animate-spin" />
                      <Power v-else class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.restart }}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent side="top" align="end" class="w-auto max-w-none p-2.5">
                    <div class="flex items-center justify-between gap-2">
                      <p class="whitespace-nowrap text-xs text-foreground">
                        {{ interpolate(t.devices.restartConfirmDesc, { n: selectedIds.size }) }}
                      </p>
                      <div class="flex shrink-0 items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          class="h-6 px-2 text-[11px]"
                          @click="restartConfirmOpen = false"
                          :disabled="restarting"
                        >
                          {{ t.devices.actions.cancel }}
                        </Button>
                        <Button
                          size="sm"
                          class="h-6 px-2 text-[11px]"
                          @click="
                            restartConfirmOpen = false;
                            void onRestartSelected();
                          "
                          :disabled="restarting || movingGroup || deleting"
                        >
                          {{ t.devices.selectionActions.restart }}
                        </Button>
                      </div>
                    </div>
                  </PopoverContent>
                </Popover>
                <Popover :open="deleteConfirmOpen" @update:open="deleteConfirmOpen = $event">
                  <PopoverTrigger as-child>
                    <Button
                      variant="outline"
                      size="sm"
                      class="h-7 gap-1.5 border-destructive/40 bg-destructive/5 px-2.5 text-[11px] font-medium text-destructive hover:bg-destructive/10"
                      :disabled="movingGroup || restarting || deleting"
                      :title="t.devices.selectionActions.delete"
                    >
                      <RotateCw v-if="deleting" class="h-3.5 w-3.5 animate-spin" />
                      <Trash2 v-else class="h-3.5 w-3.5" />
                      {{ t.devices.selectionActions.delete }}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent side="top" align="end" class="w-auto max-w-none p-2.5">
                    <div class="flex items-center justify-between gap-2">
                      <p class="whitespace-nowrap text-xs text-foreground">
                        {{ interpolate(t.devices.deleteConfirmDesc, { n: selectedIds.size }) }}
                      </p>
                      <div class="flex shrink-0 items-center gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          class="h-6 px-2 text-[11px]"
                          @click="deleteConfirmOpen = false"
                          :disabled="deleting"
                        >
                          {{ t.devices.actions.cancel }}
                        </Button>
                        <Button
                          size="sm"
                          class="h-6 bg-destructive px-2 text-[11px] text-destructive-foreground hover:bg-destructive/90"
                          @click="
                            deleteConfirmOpen = false;
                            void onDeleteSelected();
                          "
                          :disabled="movingGroup || restarting || deleting"
                        >
                          {{ t.devices.selectionActions.delete }}
                        </Button>
                      </div>
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
      </div>
    </div>

    <Dialog
      :open="tokenConfigOpen"
      @update:open="onTokenConfigOpenChange"
    >
      <DialogContent class="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{{ t.devices.p2pConfigTitle }}</DialogTitle>
        </DialogHeader>
        <div class="space-y-3">
          <p class="text-xs leading-5 text-muted-foreground">
            {{ tokenConfigMode === 'forward' ? t.devices.forwardConfigDesc : t.devices.p2pConfigDesc }}
          </p>
          <div class="rounded-md border border-border bg-muted/20 p-3">
            <div v-if="tokenConfigLoading" class="flex items-center gap-2 text-xs text-muted-foreground">
              <RotateCw class="h-3.5 w-3.5 animate-spin" />
              {{ t.common.loading }}
            </div>
            <pre v-else class="max-h-48 overflow-auto whitespace-pre-wrap break-all text-[11px] leading-4"><code>{{ tokenConfigText || '—' }}</code></pre>
          </div>
          <FeedbackTip v-if="tokenConfigError" :message="tokenConfigError" variant="error" :compact="false" />
        </div>
        <DialogFooter>
          <div class="flex w-full items-center justify-between gap-3">
            <div class="min-h-5">
              <FeedbackTip
                v-if="tokenConfigTip"
                :key="tokenConfigTip.id"
                :toast-id="tokenConfigTip.id"
                :message="tokenConfigTip.text"
                :variant="tokenConfigTip.variant"
                compact
                class-name="max-w-[280px]"
                truncate
              />
            </div>
            <div class="flex items-center gap-2">
              <Button variant="outline" size="sm" class="h-8 text-xs" @click="closeTokenConfig">
                {{ t.devices.p2pConfigClose }}
              </Button>
              <Button size="sm" class="h-8 text-xs" @click="void copyTokenConfig()" :disabled="!tokenConfigText">
                {{ t.devices.p2pConfigCopy }}
              </Button>
            </div>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
