<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  ChevronLeft,
  ArrowUpRight,
  BatteryCharging,
  Cable,
  Download,
  Loader2,
  Plus,
  Search,
  Trash2,
  UserRound,
  Wifi,
  MapPin,
  Smartphone,
  Package,
  Zap,
  HardDrive,
  Clock,
  Activity,
  Layers,
} from "lucide-vue-next";
import * as echarts from "echarts";
import { SmoothieChart, TimeSeries } from "smoothie";
import { Sidebar } from "@/components/dashboard/sidebar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Tooltip as UITooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { apiRequest, formatApiError } from "@/lib/api";
import { matchHashPath, toHashHref, useHashPathname } from "@/lib/hash-router";
import { androidVersionFromSdk } from "@/lib/android-version";

type DeviceStatus = "online" | "offline" | "busy";

type DeviceDetailApi = {
  domain?: string;
  state?: string | number;
  locked?: boolean;
  batt_charging?: boolean;
  api_available?: boolean;
  cert?: string;
  public_ip?: string;
  ip_city?: string;
  brand?: string;
  model?: string;
  sdk?: string | number;
  abi?: string;
  mem_total?: number;
  disk_total?: number;
  boot_time?: number;
  last_heartbeat_time?: number;
  version?: string;
};

type UserApi = {
  id?: number | string;
  username?: string;
  name?: string;
  contact?: string | null;
  is_admin?: boolean;
};

type DeviceStatusPoint = {
  timestamp?: number;
  cpu_percent?: number;
  cpu_times_idle?: number;
  mem_percent?: number;
  cpu_times_user?: number;
  cpu_times_system?: number;
  core_temperature?: number;
  mem_shared?: number;
  mem_free?: number;
  mem_buffers?: number;
  mem_cached?: number;
  mem_available?: number;
  fd_count?: number;
  tcpcon_count?: number;
  udpcon_count?: number;
  thread_count?: number;
  crash_count?: number;
  net_io_bytes_sent?: number;
  net_io_bytes_recv?: number;
};

type ListEnvelope<T> = {
  data?: T[];
  total?: number;
};

type DeviceInfo = {
  id: string;
  status: DeviceStatus;
  publicIp: string;
  region: string;
  brand: string;
  model: string;
  osVersion: string;
  architecture: string;
  memory: string;
  disk: string;
  uptimeText: string;
  heartbeatText: string;
  isCharging: boolean;
  isApiAvailable: boolean;
  cert: string;
};

const C = {
  cpu: "#00ff00",
  cpuUser: "#f39c12",
  cpuSystem: "#2e86c1",
  cpuTemp: "#e11d48",
  netUp: "#cb4d1c",
  netDown: "#70bf56",
  file: "#f97316",
  socketTcp: "#8b5cf6",
  socketUdp: "#ec4899",
  thread: "#6366f1",
  crash: "#ef4444",
  free: "#3498db",
  buffer: "#f1c40f",
  cached: "#3a4899",
  available: "#10b981",
};

function normalizeStatus(state: string | number | undefined, locked: boolean): DeviceStatus {
  if (state === 1 || state === "online") return locked ? "busy" : "online";
  return "offline";
}

function toEpochSeconds(value?: number) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e11 ? Math.floor(n / 1000) : Math.floor(n);
}

function statusTimestampToMs(value?: number) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e11 ? Math.floor(n) : Math.floor(n * 1000);
}

function wsTimestampToMs(value?: number) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e11 ? Math.floor(n) : Math.floor(n * 1000);
}

function bytesToHuman(bytes?: number) {
  const n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function bytesToMB(bytes?: number) {
  return Number((Number(bytes || 0) / (1024 * 1024)).toFixed(2));
}

function relativeTime(seconds?: number) {
  const ts = Number(seconds || 0);
  if (!ts) return "-";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  const d = Math.floor(diff / 86400);
  const h = Math.floor((diff % 86400) / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function extractArray<T>(payload: unknown): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];
  const obj = payload as Record<string, unknown>;
  if (Array.isArray(obj.data)) return obj.data as T[];
  if (Array.isArray(obj.items)) return obj.items as T[];
  const nested = obj.data;
  if (nested && typeof nested === "object") {
    const nestedObj = nested as Record<string, unknown>;
    if (Array.isArray(nestedObj.data)) return nestedObj.data as T[];
    if (Array.isArray(nestedObj.items)) return nestedObj.items as T[];
  }
  return [];
}

const statusDotColors: Record<DeviceStatus, string> = {
  online: "bg-[var(--status-online)]",
  busy: "bg-[var(--status-busy)]",
  offline: "bg-[var(--status-offline)]",
};

const statusTextColors: Record<DeviceStatus, string> = {
  online: "text-[var(--status-online)]",
  busy: "text-[var(--status-busy)]",
  offline: "text-[var(--status-offline)]",
};

const hashPathname = useHashPathname();
const { t } = useTranslation();
const hashDeviceId = computed(() => matchHashPath(hashPathname.value, /^\/devices\/([^/]+)$/));
const deviceId = computed(() => hashDeviceId.value);

const loading = ref(true);
const loadError = ref<string | null>(null);
const device = ref<DeviceInfo | null>(null);
const users = ref<UserApi[]>([]);
const usersPickerOpen = ref(false);
const candidateUsers = ref<UserApi[]>([]);
const candidateUsersLoading = ref(false);
const userSearch = ref("");
const userActionBusy = ref(false);
const removingUserId = ref<string | number | null>(null);
const userTip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);
const historyPoints = ref<DeviceStatusPoint[]>([]);

const realtimeUsage = ref({ cpu: 0, mem: 0 });
const latestRate = ref({ up: 0, down: 0 });
const isDarkMode = ref(
  typeof document !== "undefined" && document.documentElement.classList.contains("dark"),
);

const rtCpuCanvasRef = ref<HTMLCanvasElement | null>(null);
const rtMemCanvasRef = ref<HTMLCanvasElement | null>(null);
const rtNetCanvasRef = ref<HTMLCanvasElement | null>(null);
const cpuChartRef = ref<HTMLDivElement | null>(null);
const resChartRef = ref<HTMLDivElement | null>(null);
const memChartRef = ref<HTMLDivElement | null>(null);

let wsInstance: WebSocket | null = null;
let wsTimer: number | null = null;

const cpuPercentRef = ref(0);
const memPercentRef = ref(0);
const netUpRef = ref(0);
const netDownRef = ref(0);

const prevNetCounterRef = ref<{ sent: number; recv: number; tsMs: number } | null>(null);

const realtimeChartsRef = ref<{ cpu?: SmoothieChart; mem?: SmoothieChart; net?: SmoothieChart }>({});
const realtimeSeriesRef = ref<{
  cpu?: TimeSeries;
  cpuIdle?: TimeSeries;
  cpuUser?: TimeSeries;
  cpuSystem?: TimeSeries;
  mem?: TimeSeries;
  memBuffers?: TimeSeries;
  memCached?: TimeSeries;
  memShared?: TimeSeries;
  netUp?: TimeSeries;
  netDown?: TimeSeries;
}>({});
const staticChartsRef = ref<{ cpu?: echarts.ECharts; resource?: echarts.ECharts; memory?: echarts.ECharts }>({});
const hasTrendData = computed(() => historyPoints.value.length > 0);

let themeObserver: MutationObserver | null = null;

const setupRealtimeCharts = () => {
  if (!rtCpuCanvasRef.value || !rtMemCanvasRef.value || !rtNetCanvasRef.value) return;
  const rtGridFill = isDarkMode.value ? "rgba(15, 23, 42, 0.55)" : "white";
  const rtGridStroke = isDarkMode.value ? "rgba(148, 163, 184, 0.18)" : "#f5f5f5";
  const rtLabelColor = isDarkMode.value ? "rgba(226, 232, 240, 0.8)" : "black";
  const rtTipColor = isDarkMode.value ? "rgba(203, 213, 225, 0.35)" : "#bbbbbb";

  const memChart = new SmoothieChart({
    responsive: true,
    yMinFormatter: () => "",
    yMaxFormatter: () => `${memPercentRef.value.toFixed(1)}% MEM`,
    millisPerPixel: 100,
    grid: { lineWidth: 1, millisPerLine: 500, verticalSections: 1, fillStyle: rtGridFill, strokeStyle: rtGridStroke },
    tooltipLine: { lineWidth: 0.5, strokeStyle: rtTipColor },
    labels: { fillStyle: rtLabelColor, fontFamily: "Courier New", fontSize: 10 },
    maxValue: 100,
    minValue: 0,
  });

  const cpuChart = new SmoothieChart({
    responsive: true,
    yMinFormatter: () => "",
    yMaxFormatter: () => `${cpuPercentRef.value.toFixed(1)}% CPU`,
    millisPerPixel: 100,
    grid: { lineWidth: 1, millisPerLine: 500, verticalSections: 1, fillStyle: rtGridFill, strokeStyle: rtGridStroke },
    tooltipLine: { lineWidth: 0.5, strokeStyle: rtTipColor },
    labels: { fillStyle: rtLabelColor, fontFamily: "Courier New", fontSize: 10 },
    maxValue: 100,
    minValue: 0,
  });

  const netChart = new SmoothieChart({
    responsive: true,
    yMinFormatter: () => `${bytesToHuman(netDownRef.value)}/s ⇣`,
    yMaxFormatter: () => `${bytesToHuman(netUpRef.value)}/s ⇡`,
    millisPerPixel: 100,
    grid: { lineWidth: 1, millisPerLine: 500, verticalSections: 2, fillStyle: rtGridFill, strokeStyle: rtGridStroke },
    tooltipLine: { lineWidth: 0.5, strokeStyle: rtTipColor },
    labels: { fillStyle: rtLabelColor, fontFamily: "Courier New", fontSize: 10 },
    minValue: 0,
  });

  const mem = new TimeSeries();
  const memBuffers = new TimeSeries();
  const memCached = new TimeSeries();
  const memShared = new TimeSeries();

  const cpu = new TimeSeries();
  const cpuIdle = new TimeSeries();
  const cpuUser = new TimeSeries();
  const cpuSystem = new TimeSeries();

  const netDown = new TimeSeries();
  const netUp = new TimeSeries();

  memChart.addTimeSeries(mem, { lineWidth: 1, strokeStyle: "#3498db", fillStyle: "rgba(52, 152, 219, 0.1)", interpolation: "bezier" });
  memChart.addTimeSeries(memBuffers, { lineWidth: 0.5, strokeStyle: "#f1c40f", fillStyle: "rgba(241, 196, 15, 0.01)", interpolation: "bezier" });
  memChart.addTimeSeries(memCached, { lineWidth: 0.5, strokeStyle: "#3a4899", fillStyle: "rgba(58, 72, 153, 0.01)", interpolation: "bezier" });
  memChart.addTimeSeries(memShared, { lineWidth: 0.5, strokeStyle: "#e74c3c", fillStyle: "rgba(231, 76, 60, 0.01)", interpolation: "bezier" });

  cpuChart.addTimeSeries(cpu, { lineWidth: 1.2, strokeStyle: "#00ff00", fillStyle: "rgba(0, 255, 0, 0.1)", interpolation: "bezier" });
  cpuChart.addTimeSeries(cpuIdle, { lineWidth: 0.5, strokeStyle: "#979a9a", fillStyle: "rgba(151, 154, 154, 0.01)", interpolation: "bezier" });
  cpuChart.addTimeSeries(cpuUser, { lineWidth: 0.5, strokeStyle: "#f39c12", fillStyle: "rgba(243, 156, 18, 0.01)", interpolation: "bezier" });
  cpuChart.addTimeSeries(cpuSystem, { lineWidth: 0.5, strokeStyle: "#2e86c1", fillStyle: "rgba(46, 134, 193, 0.01)", interpolation: "bezier" });

  netChart.addTimeSeries(netDown, {
    lineWidth: 1.2,
    strokeStyle: C.netDown,
    fillStyle: "rgba(112, 191, 86, 0.08)",
    interpolation: "bezier",
  });
  netChart.addTimeSeries(netUp, {
    lineWidth: 0.8,
    strokeStyle: C.netUp,
    fillStyle: "rgba(203, 77, 28, 0.1)",
    interpolation: "bezier",
  });

  memChart.streamTo(rtMemCanvasRef.value);
  cpuChart.streamTo(rtCpuCanvasRef.value);
  netChart.streamTo(rtNetCanvasRef.value);

  realtimeChartsRef.value = { cpu: cpuChart, mem: memChart, net: netChart };
  realtimeSeriesRef.value = {
    cpu,
    cpuIdle,
    cpuUser,
    cpuSystem,
    mem,
    memBuffers,
    memCached,
    memShared,
    netUp,
    netDown,
  };
};

const teardownRealtimeCharts = () => {
  Object.values(realtimeChartsRef.value).forEach((c) => c?.stop());
  realtimeChartsRef.value = {};
  realtimeSeriesRef.value = {};
};

const updateStaticCharts = () => {
  if (!cpuChartRef.value || !resChartRef.value || !memChartRef.value) return;
  const points = historyPoints.value;
  const axisTextColor = isDarkMode.value ? "#9CA3AF" : "#6B7280";
  const axisLineColor = isDarkMode.value ? "rgba(148, 163, 184, 0.35)" : "rgba(100, 116, 139, 0.3)";
  const splitLineColor = isDarkMode.value ? "rgba(148, 163, 184, 0.22)" : "rgba(100, 116, 139, 0.18)";
  const titleColor = isDarkMode.value ? "#9CA3AF" : "#707B7C";

  const xData = points.map((p) => {
    const sec = toEpochSeconds(p.timestamp);
    const dt = new Date(sec * 1000);
    const m = String(dt.getMonth() + 1).padStart(2, "0");
    const da = String(dt.getDate()).padStart(2, "0");
    const h = String(dt.getHours()).padStart(2, "0");
    const mi = String(dt.getMinutes()).padStart(2, "0");
    return `${m}/${da} ${h}:${mi}`;
  });

  const cpuSeries = points.map((p, i) => [xData[i], Number(p.cpu_percent || 0)]);
  const userSeries = points.map((p, i) => [xData[i], Number(p.cpu_times_user || 0)]);
  const systemSeries = points.map((p, i) => [xData[i], Number(p.cpu_times_system || 0)]);
  const tempSeries = points.map((p, i) => [xData[i], Number(p.core_temperature || 0)]);

  const freeSeries = points.map((p, i) => [xData[i], bytesToMB(p.mem_free)]);
  const bufferSeries = points.map((p, i) => [xData[i], bytesToMB(p.mem_buffers)]);
  const cachedSeries = points.map((p, i) => [xData[i], bytesToMB(p.mem_cached)]);
  const availableSeries = points.map((p, i) => [xData[i], bytesToMB(p.mem_available)]);

  const fileSeries = points.map((p, i) => [xData[i], Number(p.fd_count || 0)]);
  const tcpSeries = points.map((p, i) => [xData[i], Number(p.tcpcon_count || 0)]);
  const udpSeries = points.map((p, i) => [xData[i], Number(p.udpcon_count || 0)]);
  const threadSeries = points.map((p, i) => [xData[i], Number(p.thread_count || 0)]);
  const crashSeries = points.map((p, i) => [xData[i], Number(p.crash_count || 0)]);

  const getChart = (key: "cpu" | "resource" | "memory", dom: HTMLDivElement) => {
    const curr = staticChartsRef.value[key];
    if (curr) return curr;
    const c = echarts.init(dom);
    staticChartsRef.value[key] = c;
    return c;
  };

  const cpuChart = getChart("cpu", cpuChartRef.value);
  const resourceChart = getChart("resource", resChartRef.value);
  const memoryChart = getChart("memory", memChartRef.value);

  cpuChart.setOption({
    animation: true,
    color: [C.cpu, C.cpuUser, C.cpuSystem, C.cpuTemp],
    legend: { data: ["CPU", "User", "System", "Temp"], left: "right", textStyle: { color: axisTextColor } },
    tooltip: { show: true, trigger: "item" },
    xAxis: [{ data: xData, axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    yAxis: [{ axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    title: [{ text: "CPU", left: "left", textStyle: { fontSize: 18, color: titleColor } }],
    dataZoom: [{ show: true, type: "inside", start: 0, end: 100 }],
    grid: { left: 50, right: 10, top: 50, bottom: 20 },
    series: [
      { type: "line", name: "CPU", data: cpuSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "User", data: userSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "System", data: systemSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "Temp", data: tempSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.12 } },
    ],
  }, { notMerge: true });

  resourceChart.setOption({
    animation: true,
    legend: {
      data: ["File", "TCP", "UDP", "Thread", "Crash"],
      selected: { File: false, Thread: false, Crash: false },
      left: "right",
      textStyle: { color: axisTextColor },
    },
    tooltip: { show: true, trigger: "item" },
    xAxis: [{ data: xData, axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    yAxis: [{ axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    title: [{ text: "RES", left: "left", textStyle: { fontSize: 18, color: titleColor } }],
    dataZoom: [{ show: true, type: "inside", start: 0, end: 100 }],
    grid: { left: 50, right: 10, top: 50, bottom: 20 },
    series: [
      { type: "line", name: "File", data: fileSeries, lineStyle: { width: 1 } },
      { type: "line", name: "TCP", data: tcpSeries, lineStyle: { width: 1 } },
      { type: "line", name: "UDP", data: udpSeries, lineStyle: { width: 1 } },
      { type: "line", name: "Thread", data: threadSeries, lineStyle: { width: 1 } },
      { type: "line", name: "Crash", data: crashSeries, lineStyle: { width: 1 } },
    ],
  }, { notMerge: true });

  memoryChart.setOption({
    animation: true,
    legend: { data: ["free", "buffer", "cached", "available"], left: "right", textStyle: { color: axisTextColor } },
    tooltip: { show: true, trigger: "item" },
    xAxis: [{ data: xData, axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    yAxis: [{ axisLabel: { color: axisTextColor }, axisLine: { lineStyle: { color: axisLineColor } }, splitLine: { show: true, lineStyle: { color: splitLineColor } } }],
    title: [{ text: "MEM", left: "left", textStyle: { fontSize: 18, color: titleColor } }],
    dataZoom: [{ show: true, type: "inside", start: 0, end: 100 }],
    grid: { left: 50, right: 10, top: 50, bottom: 20 },
    series: [
      { type: "line", name: "free", data: freeSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "buffer", data: bufferSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "cached", data: cachedSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
      { type: "line", name: "available", data: availableSeries, lineStyle: { width: 1 }, areaStyle: { opacity: 0.25 } },
    ],
  }, { notMerge: true });
};

const disposeStaticCharts = () => {
  Object.values(staticChartsRef.value).forEach((chart) => chart?.dispose());
  staticChartsRef.value = {};
};

const resizeStaticCharts = () => {
  staticChartsRef.value.cpu?.resize();
  staticChartsRef.value.resource?.resize();
  staticChartsRef.value.memory?.resize();
};

const clearSendTimer = () => {
  if (wsTimer !== null) {
    window.clearInterval(wsTimer);
    wsTimer = null;
  }
};

const setupWebSocket = () => {
  if (!deviceId.value) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/d/${encodeURIComponent(deviceId.value)}/ws/command`;
  const ws = new WebSocket(wsUrl);
  wsInstance = ws;

  ws.onopen = () => {
    clearSendTimer();
    wsTimer = window.setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send("status");
    }, 1000);
  };

  ws.onmessage = (evt) => {
    try {
      const payload = JSON.parse(String(evt.data || "{}")) as { data?: DeviceStatusPoint; timestamp?: number };
      const data = payload.data || {};
      const tsMs = wsTimestampToMs(payload.timestamp) || Date.now();
      const sent = Number(data.net_io_bytes_sent || 0);
      const recv = Number(data.net_io_bytes_recv || 0);

      const cpu = Number(data.cpu_percent || 0);
      const mem = Number(data.mem_percent || 0);
      cpuPercentRef.value = cpu;
      memPercentRef.value = mem;
      realtimeUsage.value = { cpu, mem };

      const prev = prevNetCounterRef.value;
      const realtimeSeries = realtimeSeriesRef.value;
      if (realtimeSeries.cpu) {
        realtimeSeries.cpu.append(tsMs, cpu);
        realtimeSeries.cpuIdle?.append(tsMs, Number(data.cpu_times_idle || 0));
        realtimeSeries.cpuUser?.append(tsMs, Number(data.cpu_times_user || 0));
        realtimeSeries.cpuSystem?.append(tsMs, Number(data.cpu_times_system || 0));

        realtimeSeries.mem?.append(tsMs, mem);
        realtimeSeries.memBuffers?.append(tsMs, Number(data.mem_buffers || 0));
        realtimeSeries.memCached?.append(tsMs, Number(data.mem_cached || 0));
        realtimeSeries.memShared?.append(tsMs, Number(data.mem_shared || 0));
      }

      if (prev && tsMs > prev.tsMs && realtimeSeries.netUp && realtimeSeries.netDown) {
        const up = prev.sent ? Math.max(0, sent - prev.sent) : 0;
        const down = prev.recv ? Math.max(0, recv - prev.recv) : 0;

        netUpRef.value = up;
        netDownRef.value = down;
        latestRate.value = { up, down };

        realtimeSeries.netUp.append(tsMs, up);
        realtimeSeries.netDown.append(tsMs, down);
      }

      prevNetCounterRef.value = { sent, recv, tsMs };
    } catch {
      // ignore malformed ws payloads
    }
  };

  ws.onclose = () => {
    clearSendTimer();
  };
};

const teardownWebSocket = () => {
  clearSendTimer();
  if (wsInstance) {
    wsInstance.close();
    wsInstance = null;
  }
};

onMounted(() => {
  const updateTheme = () => {
    isDarkMode.value = document.documentElement.classList.contains("dark");
  };
  updateTheme();
  themeObserver = new MutationObserver(updateTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  window.addEventListener("resize", resizeStaticCharts);
});

onBeforeUnmount(() => {
  themeObserver?.disconnect();
  themeObserver = null;
  window.removeEventListener("resize", resizeStaticCharts);
  teardownRealtimeCharts();
  teardownWebSocket();
  disposeStaticCharts();
});

watch(deviceId, (_value, _oldValue, onCleanup) => {
  if (!deviceId.value) {
    loading.value = false;
    return;
  }
  let cancelled = false;

  const load = async () => {
    loading.value = true;
    loadError.value = null;
    const id = deviceId.value;
    if (!id) return;
    try {
      const [deviceResp, usersResp, statsResp] = await Promise.all([
        apiRequest<DeviceDetailApi>(`/api/v1/device/${encodeURIComponent(id)}`, {
          method: "GET",
          errorMessage: "Failed to load device",
        }),
        apiRequest<ListEnvelope<UserApi>>(`/api/v1/device/${encodeURIComponent(id)}/alloc?page=1&size=200`, {
          method: "GET",
          errorMessage: "Failed to load device users",
        }),
        apiRequest<ListEnvelope<DeviceStatusPoint>>(`/api/v1/device/${encodeURIComponent(id)}/status?limit=2048`, {
          method: "GET",
          errorMessage: "Failed to load device status",
        }),
      ]);

      if (cancelled) return;

      const raw = (deviceResp.data as unknown as DeviceDetailApi) || {};
      const status = normalizeStatus(raw.state, Boolean(raw.locked));

      device.value = {
        id: String(raw.domain || id),
        status,
        publicIp: String(raw.public_ip || "-"),
        region: String(raw.ip_city || "-"),
        brand: String(raw.brand || "-"),
        model: String(raw.model || "-"),
        osVersion: androidVersionFromSdk(raw.sdk),
        architecture: String(raw.abi || "-"),
        memory: bytesToHuman(raw.mem_total),
        disk: bytesToHuman(raw.disk_total),
        uptimeText: relativeTime(raw.boot_time),
        heartbeatText: relativeTime(raw.last_heartbeat_time),
        isCharging: Boolean(raw.batt_charging),
        isApiAvailable: Boolean(raw.api_available),
        cert: String(raw.cert || ""),
      };

      users.value = extractArray<UserApi>(usersResp.data);

      const points = extractArray<DeviceStatusPoint>(statsResp.data)
        .sort((a, b) => statusTimestampToMs(a.timestamp) - statusTimestampToMs(b.timestamp));
      historyPoints.value = points;

      const last = points[points.length - 1];
      if (last) {
        const cpu = Number(last.cpu_percent || 0);
        const mem = Number(last.mem_percent || 0);
        realtimeUsage.value = { cpu, mem };
        cpuPercentRef.value = cpu;
        memPercentRef.value = mem;
        prevNetCounterRef.value = {
          sent: Number(last.net_io_bytes_sent || 0),
          recv: Number(last.net_io_bytes_recv || 0),
          tsMs: statusTimestampToMs(last.timestamp),
        };
      }

      if (points.length >= 2) {
        const p1 = points[points.length - 2];
        const p2 = points[points.length - 1];
        const dt = Math.max(0.001, (statusTimestampToMs(p2.timestamp) - statusTimestampToMs(p1.timestamp)) / 1000);
        const up = Math.max(0, Number(p2.net_io_bytes_sent || 0) - Number(p1.net_io_bytes_sent || 0)) / dt;
        const down = Math.max(0, Number(p2.net_io_bytes_recv || 0) - Number(p1.net_io_bytes_recv || 0)) / dt;
        latestRate.value = { up, down };
        netUpRef.value = up;
        netDownRef.value = down;
      }
    } catch (err) {
      if (!cancelled) loadError.value = formatApiError(err, "Failed to load device details");
    } finally {
      if (!cancelled) loading.value = false;
    }
  };

  load();
  onCleanup(() => {
    cancelled = true;
  });
}, { immediate: true });

watch([usersPickerOpen, userSearch, users, deviceId], (_values, _oldValues, onCleanup) => {
  if (!usersPickerOpen.value || !deviceId.value) return;
  let cancelled = false;
  const loadCandidates = async () => {
    candidateUsersLoading.value = true;
    try {
      const qs = new URLSearchParams({
        page: "1",
        size: "20",
        sort: "id",
        order: "desc",
      });
      const keyword = userSearch.value.trim();
      if (keyword) {
        qs.set("filter", JSON.stringify([{ field: "name", op: "like", value: keyword }]));
      }
      const resp = await apiRequest<ListEnvelope<UserApi>>(`/api/v1/user?${qs.toString()}`, {
        method: "GET",
        errorMessage: "Failed to load user list",
      });
      if (cancelled) return;
      const allocated = new Set(users.value.map((u) => String(u.id ?? "")));
      const list = extractArray<UserApi>(resp.data).filter((u) => {
        const uid = String(u?.id ?? "");
        return Boolean(uid) && !allocated.has(uid) && !Boolean(u?.is_admin);
      });
      candidateUsers.value = list;
    } catch {
      if (!cancelled) candidateUsers.value = [];
    } finally {
      if (!cancelled) candidateUsersLoading.value = false;
    }
  };
  void loadCandidates();
  onCleanup(() => {
    cancelled = true;
  });
});

watch([deviceId, isDarkMode], async () => {
  teardownRealtimeCharts();
  await nextTick();
  setupRealtimeCharts();
  if (!realtimeChartsRef.value.cpu) {
    await nextTick();
    setupRealtimeCharts();
  }
}, { immediate: true, flush: "post" });

watch([historyPoints, isDarkMode], () => {
  updateStaticCharts();
}, { flush: "post" });

watch(hasTrendData, (value) => {
  if (value) return;
  disposeStaticCharts();
});

watch(deviceId, () => {
  teardownWebSocket();
  setupWebSocket();
}, { immediate: true });

const d = computed<DeviceInfo>(
  () =>
    device.value || {
      id: deviceId.value || "-",
      status: "offline" as DeviceStatus,
      publicIp: "-",
      region: "-",
      brand: "-",
      model: "-",
      osVersion: "-",
      architecture: "-",
      memory: "-",
      disk: "-",
      uptimeText: "-",
      heartbeatText: "-",
      isCharging: false,
      isApiAvailable: false,
      cert: "",
    },
);

const onDownloadCert = () => {
  if (!d.value.cert) return;
  const blob = new Blob([d.value.cert], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${d.value.id}.pem`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const showUserTip = (text: string, variant: FeedbackTipVariant = "error") => {
  userTip.value = { id: Date.now() + Math.random(), text, variant };
};

const reloadAssignedUsers = async () => {
  if (!deviceId.value) return;
  const resp = await apiRequest<ListEnvelope<UserApi>>(`/api/v1/device/${encodeURIComponent(deviceId.value)}/alloc?page=1&size=200`, {
    method: "GET",
    errorMessage: "Failed to load device users",
  });
  users.value = extractArray<UserApi>(resp.data);
};

const onAddUser = async (uid: string | number) => {
  if (!deviceId.value || !uid) return;
  userActionBusy.value = true;
  try {
    await apiRequest(`/api/v1/device/${encodeURIComponent(deviceId.value)}/alloc`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id: String(uid) }).toString(),
    });
    await reloadAssignedUsers();
    usersPickerOpen.value = false;
    userSearch.value = "";
    showUserTip(t.value.deviceDetail.addUserSuccess, "success");
  } catch (err) {
    showUserTip(formatApiError(err, t.value.deviceDetail.addUserFailed), "error");
  } finally {
    userActionBusy.value = false;
  }
};

const onRemoveUser = async (uid: string | number) => {
  if (!deviceId.value || !uid) return;
  removingUserId.value = uid;
  try {
    await apiRequest(`/api/v1/device/${encodeURIComponent(deviceId.value)}/alloc?id=${encodeURIComponent(String(uid))}`, {
      method: "DELETE",
    });
    await reloadAssignedUsers();
    showUserTip(t.value.deviceDetail.removeUserSuccess, "success");
  } catch (err) {
    showUserTip(formatApiError(err, t.value.deviceDetail.removeUserFailed), "error");
  } finally {
    removingUserId.value = null;
  }
};
</script>

<template>
  <div class="flex h-screen bg-[#f5f5f7] dark:bg-background">
    <Sidebar />

    <main class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <div class="flex h-14 shrink-0 items-center border-b border-gray-100 bg-white px-5 dark:border-border dark:bg-background">
        <div class="flex w-full min-w-0 items-center justify-between gap-3">
          <div class="flex items-center gap-2">
            <Button as-child size="icon" variant="ghost" class="h-7 w-7 shrink-0">
              <a :href="toHashHref('/devices')">
                <ChevronLeft class="h-3.5 w-3.5" />
              </a>
            </Button>
            <div>
              <p class="text-xs text-muted-foreground">{{ t.deviceDetail.title }}</p>
              <p class="truncate text-base font-semibold leading-tight">{{ d.id }}</p>
            </div>
          </div>
          <span :class="cn('inline-flex items-center gap-1.5 font-medium', statusTextColors[d.status])">
            <span :class="cn('inline-block h-2 w-2 rounded-full', statusDotColors[d.status])" />
            {{ t.deviceDetail.statusText[d.status] }}
          </span>
        </div>
      </div>

      <div class="flex-1 overflow-y-auto p-3">
        <div class="flex h-full min-h-0 gap-3">
          <aside class="flex w-80 shrink-0 flex-col gap-3 overflow-y-auto rounded-lg border border-border bg-card p-3">
            <div>
              <div class="flex items-center justify-between">
                <h2 class="text-sm font-semibold text-foreground">{{ t.deviceDetail.deviceInfo }}</h2>
                <div class="flex items-center gap-1">
                  <UITooltip :delay-duration="100">
                    <TooltipTrigger as-child>
                      <Button variant="ghost" size="icon" class="relative h-7 w-7 rounded text-muted-foreground hover:bg-muted/50 hover:text-foreground">
                        <BatteryCharging :class="cn('h-4 w-4', d.isCharging ? 'text-blue-500 animate-pulse' : 'text-slate-400')" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" class="text-xs">
                      {{ d.isCharging ? t.deviceDetail.actions.chargingActive : t.deviceDetail.actions.notCharging }}
                    </TooltipContent>
                  </UITooltip>
                  <UITooltip :delay-duration="100">
                    <TooltipTrigger as-child>
                      <Button variant="ghost" size="icon" class="relative h-7 w-7 rounded text-muted-foreground hover:bg-muted/50 hover:text-foreground">
                        <Cable :class="cn('h-4 w-4', d.isApiAvailable ? 'text-emerald-500' : 'text-red-500')" />
                        <span :class="cn('absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full', d.isApiAvailable ? 'bg-emerald-500' : 'bg-red-500')" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" class="text-xs">
                      {{ d.isApiAvailable ? t.deviceDetail.actions.apiAvailable : t.deviceDetail.actions.apiUnavailable }}
                    </TooltipContent>
                  </UITooltip>
                  <UITooltip :delay-duration="100">
                    <TooltipTrigger as-child>
                      <Button variant="ghost" size="icon" class="h-7 w-7 rounded text-muted-foreground hover:bg-muted/50 hover:text-foreground" @click="onDownloadCert">
                        <Download class="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" class="text-xs">{{ t.deviceDetail.actions.downloadCert }}</TooltipContent>
                  </UITooltip>
                  <UITooltip :delay-duration="100">
                    <TooltipTrigger as-child>
                      <Button as-child variant="ghost" size="sm" class="h-7 gap-1 rounded px-2 text-xs text-muted-foreground hover:bg-muted/50 hover:text-foreground">
                        <a :href="`/d/${encodeURIComponent(d.id)}/`" target="_blank" rel="noreferrer">
                          {{ t.deviceDetail.actions.gotoRemote }}
                          <ArrowUpRight class="h-3.5 w-3.5" />
                        </a>
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" class="text-xs">{{ t.deviceDetail.actions.gotoRemote }}</TooltipContent>
                  </UITooltip>
                </div>
              </div>
            </div>

            <Card class="flex flex-1 flex-col rounded-lg border border-border bg-card p-3 shadow-none">
              <CardHeader class="shrink-0 p-0">
                <CardTitle class="inline-flex items-center gap-1 text-xs font-semibold">
                  <Smartphone class="h-3.5 w-3.5 text-muted-foreground" />
                  {{ t.deviceDetail.deviceInfo }}
                </CardTitle>
              </CardHeader>
              <CardContent class="flex-1 overflow-y-auto p-0 pt-2">
                <div class="space-y-1.5 text-[11px]">
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Wifi class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.publicIp }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', 'font-mono')">{{ d.publicIp || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><MapPin class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.region }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.region || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Smartphone class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.brand }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.brand || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Smartphone class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.model }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.model || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Layers class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.osVersion }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.osVersion || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Package class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.architecture }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', 'font-mono')">{{ d.architecture || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Zap class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.memory }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', 'font-mono')">{{ d.memory || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><HardDrive class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.disk }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', 'font-mono')">{{ d.disk || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Clock class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.uptime }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.uptimeText || "-" }}</p>
                  </div>
                  <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                    <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                      <span class="text-muted-foreground"><Activity class="h-3 w-3" /></span>
                      {{ t.deviceDetail.fields.lastHeartbeat }}
                    </p>
                    <p :class="cn('truncate text-[11px] font-medium', '')">{{ d.heartbeatText || "-" }}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-border bg-card p-3">
              <div class="mb-2 flex items-center justify-between gap-2">
                <p class="inline-flex items-center gap-1 text-xs font-semibold">
                  <UserRound class="h-3.5 w-3.5 text-muted-foreground" />
                  {{ t.deviceDetail.assignedUsers }}
                </p>
                <Popover :open="usersPickerOpen" @update:open="usersPickerOpen = $event">
                  <PopoverTrigger as-child>
                    <Button variant="ghost" size="icon" class="h-6 w-6">
                      <Plus class="h-3.5 w-3.5" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="end" class="w-[260px] p-0">
                    <div class="p-2">
                      <div class="relative">
                        <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          class="h-8 pl-8 text-xs"
                          :placeholder="t.deviceDetail.searchUserPlaceholder"
                          v-model="userSearch"
                        />
                      </div>
                    </div>
                    <div class="border-t border-border" />
                    <div class="max-h-[220px] overflow-y-auto py-1">
                      <div v-if="candidateUsersLoading" class="flex items-center justify-center gap-2 px-3 py-8 text-xs text-muted-foreground">
                        <Loader2 class="h-3.5 w-3.5 animate-spin" />
                        {{ t.common.loading }}
                      </div>
                      <p v-else-if="candidateUsers.length === 0" class="px-3 py-8 text-center text-xs text-muted-foreground">{{ t.deviceDetail.noCandidateUsers }}</p>
                      <button
                        v-else
                        v-for="(u, idx) in candidateUsers"
                        :key="`${u.id || 'c'}-${idx}`"
                        type="button"
                        :disabled="userActionBusy"
                        @click="void onAddUser(String(u.id || ''))"
                        class="flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-muted/50"
                      >
                        <span class="h-2.5 w-2.5 shrink-0 rounded-sm bg-blue-500/80" />
                        <span class="flex-1 truncate">{{ u.name || u.username || "-" }}</span>
                      </button>
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
              <FeedbackTip v-if="userTip" :key="userTip.id" :toast-id="userTip.id" :message="userTip.text" :variant="userTip.variant" class="mb-1" />
              <div class="min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
                <p v-if="users.length === 0" class="px-2 py-3 text-center text-xs text-muted-foreground">{{ t.deviceDetail.noUsers }}</p>
                <div v-else v-for="(u, idx) in users" :key="`${u.id || 'u'}-${idx}`" class="flex items-center gap-2 rounded-md border border-border px-2 py-2">
                  <span class="inline-flex h-5 w-5 shrink-0 items-center justify-center text-muted-foreground">
                    <UserRound class="h-3.5 w-3.5" />
                  </span>
                  <span class="min-w-0 flex-1 truncate text-xs font-medium text-foreground">{{ u.name || u.username || "-" }}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    class="h-6 w-6 text-destructive hover:text-destructive"
                    :disabled="removingUserId === u.id"
                    @click="void onRemoveUser(String(u.id || ''))"
                  >
                    <Loader2 v-if="removingUserId === u.id" class="h-3.5 w-3.5 animate-spin" />
                    <Trash2 v-else class="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          </aside>

          <div class="grid min-w-0 flex-1 auto-rows-[1fr_1fr] grid-cols-[1fr_1fr] gap-3 overflow-auto">
            <Card v-if="loadError" class="col-span-2 border-border/70 bg-background">
              <CardContent class="py-3">
                <FeedbackTip :message="loadError" variant="error" :compact="false" />
              </CardContent>
            </Card>

            <Card class="flex flex-col overflow-hidden">
              <CardHeader class="shrink-0 px-3 pb-0 pt-0">
                <div class="flex items-start justify-between gap-2">
                  <CardTitle class="text-sm font-semibold">{{ t.deviceDetail.charts.realtime }}</CardTitle>
                  <div class="flex flex-col items-end gap-0.5 text-[10px] font-mono">
                    <span class="text-muted-foreground">
                      <span class="font-semibold text-foreground">{{ realtimeUsage.cpu.toFixed(1) }}%</span> CPU
                      <span class="font-semibold text-foreground">{{ realtimeUsage.mem.toFixed(1) }}%</span> MEM
                    </span>
                    <span>
                      <span class="font-medium" :style="{ color: C.netUp }">{{ bytesToHuman(latestRate.up) }}/s ↑</span>
                      <span class="font-medium" :style="{ color: C.netDown }">{{ bytesToHuman(latestRate.down) }}/s ↓</span>
                    </span>
                  </div>
                </div>
              </CardHeader>
              <CardContent class="relative min-h-0 flex-1 px-1 pb-0 pt-0">
                <div class="flex h-full flex-col">
                  <div class="flex h-1/2">
                    <canvas ref="rtCpuCanvasRef" class="h-full w-1/2" />
                    <canvas ref="rtMemCanvasRef" class="h-full w-1/2" />
                  </div>
                  <div class="h-1/2">
                    <canvas ref="rtNetCanvasRef" class="h-full w-full" />
                  </div>
                </div>
                <div v-if="loading" class="pointer-events-none absolute inset-0 flex items-center justify-center">
                  <div class="rounded-md border border-border bg-background px-3 py-2 text-xs text-muted-foreground">{{ t.common.loading }}</div>
                </div>
              </CardContent>
            </Card>

            <Card class="flex flex-col overflow-hidden">
              <CardContent class="min-h-0 flex-1 p-0">
                <div v-if="hasTrendData" ref="cpuChartRef" class="h-full w-full" />
                <div v-else class="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
                  <Activity class="h-6 w-6" />
                  <p class="text-xs">{{ t.devices.noData }}</p>
                </div>
              </CardContent>
            </Card>

            <Card class="flex flex-col overflow-hidden">
              <CardContent class="min-h-0 flex-1 p-0">
                <div v-if="hasTrendData" ref="resChartRef" class="h-full w-full" />
                <div v-else class="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
                  <Activity class="h-6 w-6" />
                  <p class="text-xs">{{ t.devices.noData }}</p>
                </div>
              </CardContent>
            </Card>

            <Card class="flex flex-col overflow-hidden">
              <CardContent class="min-h-0 flex-1 p-0">
                <div v-if="hasTrendData" ref="memChartRef" class="h-full w-full" />
                <div v-else class="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
                  <Activity class="h-6 w-6" />
                  <p class="text-xs">{{ t.devices.noData }}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>
