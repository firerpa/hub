<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useHashRouter } from "@/lib/hash-router";
import {
  ArrowDown,
  ChevronLeft,
  CheckCircle2,
  Clock,
  FileText,
  Minus,
  Plus,
  RotateCw,
  X,
  Zap,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { apiRequest, formatApiError } from "@/lib/api";
import { interpolate, useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type DeviceStatus = "online" | "offline" | "busy";

type TargetDevice = {
  id: string;
  status: DeviceStatus;
  brand: string;
  model: string;
  rawState: string;
  locked: boolean;
};

type DeviceApiItem = {
  domain?: string;
  state?: string;
  locked?: boolean;
  brand?: string;
  model?: string;
};

type ListEnvelope<T> = {
  data?: T[];
};

type PullFile = {
  id: string;
  path: string;
};

type PullStatus = "idle" | "pending" | "pulling" | "success" | "failed";

type DevicePullFileState = {
  status: PullStatus;
  progress: number;
  error?: string;
};

type DevicePullState = {
  status: PullStatus;
  progress: number;
  error?: string;
  currentPath?: string;
  files?: Record<string, DevicePullFileState>;
};

type PulledFileRecord = {
  sessionId: number;
  domain: string;
  remotePath: string;
  blob: Blob;
};

const TAR_BLOCK_SIZE = 512;

function normalizeStatus(state: string, locked: boolean): DeviceStatus {
  if (state === "online") return locked ? "busy" : "online";
  return "offline";
}

function normalizePullPath(path: string): string {
  return String(path || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/");
}

function encodePathSegment(seg: string): string {
  return encodeURIComponent(seg).replace(/%2F/gi, "/");
}

function encodePath(path: string): string {
  return path
    .split("/")
    .map((seg) => encodePathSegment(seg))
    .join("/");
}

function recomputePullProgress(state: DevicePullState): DevicePullState {
  const files = state.files || {};
  const ids = Object.keys(files);
  if (!ids.length) return state;
  const sum = ids.reduce((acc, id) => acc + (Number(files[id]?.progress) || 0), 0);
  return {
    ...state,
    progress: Math.max(0, Math.min(100, Math.floor(sum / ids.length))),
  };
}

function parsePositiveInt(value?: string | null): number {
  const raw = String(value || "").trim();
  if (!raw) return 0;
  const num = Number(raw);
  return Number.isFinite(num) && num > 0 ? Math.floor(num) : 0;
}

function parseContentRangeTotal(value?: string | null): number {
  const raw = String(value || "").trim();
  if (!raw) return 0;
  const match = raw.match(/\/(\d+)\s*$/);
  return match ? parsePositiveInt(match[1]) : 0;
}

function resolveDownloadTotalFromHeaders(xhr: XMLHttpRequest): number {
  const names = [
    "x-file-size",
    "x-content-length",
    "x-original-content-length",
    "x-download-size",
    "content-length",
  ];
  for (const name of names) {
    const total = parsePositiveInt(xhr.getResponseHeader(name));
    if (total > 0) return total;
  }
  return parseContentRangeTotal(xhr.getResponseHeader("content-range"));
}

function sanitizeArchiveSegment(value: string): string {
  return String(value || "")
    .replace(/[<>:"\\|?*\u0000-\u001f]/g, "_")
    .replace(/\s+/g, " ")
    .trim();
}

function buildArchiveEntryName(domain: string, remotePath: string): string {
  const safeDomain = sanitizeArchiveSegment(domain) || "device";
  const safePath = normalizePullPath(remotePath)
    .replace(/^\/+/, "")
    .split("/")
    .filter(Boolean)
    .map((seg) => sanitizeArchiveSegment(seg) || "file")
    .join("/");
  return `${safeDomain}/${safePath || "unnamed.bin"}`;
}

const tarTextEncoder = new TextEncoder();

function writeTarString(buffer: Uint8Array, offset: number, length: number, value: string): void {
  const bytes = tarTextEncoder.encode(value || "");
  buffer.set(bytes.slice(0, Math.max(0, length)), offset);
}

function writeTarOctal(buffer: Uint8Array, offset: number, length: number, value: number): void {
  const safe = Math.max(0, Math.floor(Number(value) || 0));
  const raw = safe.toString(8);
  const digits = Math.max(0, length - 1);
  const out = raw.length > digits ? raw.slice(raw.length - digits) : raw.padStart(digits, "0");
  writeTarString(buffer, offset, digits, out);
  if (length > 0) buffer[offset + length - 1] = 0;
}

function writeTarName(header: Uint8Array, name: string): void {
  const normalized = String(name || "").replace(/^\/+/, "");
  const byteLen = tarTextEncoder.encode(normalized).length;
  if (byteLen <= 100) {
    writeTarString(header, 0, 100, normalized);
    return;
  }

  const parts = normalized.split("/");
  for (let i = 1; i < parts.length; i += 1) {
    const prefix = parts.slice(0, i).join("/");
    const tail = parts.slice(i).join("/");
    if (tarTextEncoder.encode(prefix).length <= 155 && tarTextEncoder.encode(tail).length <= 100) {
      writeTarString(header, 0, 100, tail);
      writeTarString(header, 345, 155, prefix);
      return;
    }
  }

  writeTarString(header, 0, 100, normalized.slice(-100));
}

function buildTarHeader(name: string, size: number, mtime: number): Uint8Array {
  const header = new Uint8Array(TAR_BLOCK_SIZE);
  writeTarName(header, name);
  writeTarOctal(header, 100, 8, 0o644);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, size);
  writeTarOctal(header, 136, 12, mtime);
  for (let i = 148; i < 156; i += 1) header[i] = 0x20;
  header[156] = "0".charCodeAt(0);
  writeTarString(header, 257, 6, "ustar\0");
  writeTarString(header, 263, 2, "00");
  const checksum = header.reduce((sum, value) => sum + value, 0);
  const check = checksum.toString(8).padStart(6, "0").slice(-6);
  writeTarString(header, 148, 6, check);
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

async function buildTarBlob(files: PulledFileRecord[]): Promise<Blob> {
  const chunks: BlobPart[] = [];
  const now = Math.floor(Date.now() / 1000);

  for (const file of files) {
    const data = new Uint8Array(await file.blob.arrayBuffer());
    const header = buildTarHeader(buildArchiveEntryName(file.domain, file.remotePath), data.length, now);
    chunks.push(header);
    chunks.push(data);
    const pad = (TAR_BLOCK_SIZE - (data.length % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    if (pad) chunks.push(new Uint8Array(pad));
  }

  chunks.push(new Uint8Array(TAR_BLOCK_SIZE * 2));
  return new Blob(chunks, { type: "application/x-tar" });
}

function triggerBrowserDownload(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function buildPullArchiveName(): string {
  const date = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `pull-device-files-${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(
    date.getHours(),
  )}${pad(date.getMinutes())}${pad(date.getSeconds())}.tar`;
}

async function parsePullErrorMessage(xhr: XMLHttpRequest, fallback: string): Promise<string> {
  const status = Number(xhr.status || 0);
  const prefix = status > 0 ? `HTTP ${status}` : "HTTP error";

  // Pull request uses `responseType = "blob"`, so error payload is usually in `response`.
  const payload = xhr.response;
  if (payload instanceof Blob) {
    const raw = (await payload.text()).trim();
    if (!raw) return `${fallback} (${prefix})`;
    try {
      const json = JSON.parse(raw) as { message?: unknown; error?: unknown };
      if (typeof json.message === "string" && json.message) return `${json.message} (${prefix})`;
      if (typeof json.error === "string" && json.error) return `${json.error} (${prefix})`;
    } catch {
      // ignore json parse errors
    }
    return `${raw} (${prefix})`;
  }

  // Fallback for plain text / empty bodies.
  const raw = String(xhr.responseText || "").trim();
  if (!raw) return `${fallback} (${prefix})`;
  try {
    const json = JSON.parse(raw) as { message?: unknown; error?: unknown };
    if (typeof json.message === "string" && json.message) return `${json.message} (${prefix})`;
    if (typeof json.error === "string" && json.error) return `${json.error} (${prefix})`;
  } catch {
    // ignore json parse errors
  }
  return `${raw} (${prefix})`;
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  const limit = Math.max(1, Math.min(items.length || 1, Math.floor(concurrency) || 1));
  let index = 0;
  await Promise.all(
    Array.from({ length: limit }, async () => {
      while (index < items.length) {
        const current = items[index];
        index += 1;
        await worker(current);
      }
    }),
  );
}

function idlePullState(): DevicePullState {
  return { status: "idle", progress: 0 };
}

const router = useHashRouter();
const { t } = useTranslation();

const devices = ref<TargetDevice[]>([]);
const loadingDevices = ref(true);
const loadError = ref<string | null>(null);

const pullTimeout = ref(600);
const concurrency = ref(5);
const filePath = ref("");
const files = ref<PullFile[]>([]);
const pulling = ref(false);
const actionMessage = ref<string | null>(null);
const actionError = ref<string | null>(null);
const pullState = ref<Record<string, DevicePullState>>({});

let pullSession = 0;
const pullXhrs = new Map<string, XMLHttpRequest>();
const pulledBlobMap = new Map<string, PulledFileRecord>();

const abortAllPullXhrs = () => {
  for (const xhr of pullXhrs.values()) {
    try {
      xhr.abort();
    } catch {
      // ignore
    }
  }
  pullXhrs.clear();
};

onUnmounted(() => {
  pullSession += 1;
  abortAllPullXhrs();
});

let loadToken = 0;

const loadSelectedDevices = async () => {
  const token = ++loadToken;
  loadingDevices.value = true;
  loadError.value = null;
  try {
    const raw = sessionStorage.getItem("pull_device_ids");
    const idsRaw = raw ? (JSON.parse(raw) as unknown) : [];
    const ids = Array.isArray(idsRaw)
      ? idsRaw.map((v) => String(v || "").trim()).filter(Boolean)
      : [];

    if (!ids.length) {
      if (token === loadToken) devices.value = [];
      return;
    }

    const params = new URLSearchParams({ page: "1", size: String(Math.max(ids.length, 1000)) });
    params.set(
      "filter",
      JSON.stringify([
        {
          field: "domain",
          op: "in",
          value: ids,
        },
      ]),
    );

    const response = await apiRequest<ListEnvelope<DeviceApiItem>>(`/api/v1/device?${params.toString()}`, {
      cache: "no-store",
      errorMessage: t.value.pullPage.loadDevicesFailed,
    });

    const apiList = Array.isArray(response.data?.data) ? response.data.data : [];
    const mapped = apiList
      .map((item: DeviceApiItem) => {
        const id = String(item.domain || "");
        if (!id) return null;
        return {
          id,
          status: normalizeStatus(String(item.state || ""), Boolean(item.locked)),
          brand: String(item.brand || "-"),
          model: String(item.model || "-"),
          rawState: String(item.state || ""),
          locked: Boolean(item.locked),
        } satisfies TargetDevice;
      })
      .filter((item: TargetDevice | null): item is TargetDevice => Boolean(item));

    const byId = new Map(mapped.map((item) => [item.id, item]));
    const ordered = ids
      .map((id) => byId.get(id))
      .filter((item): item is TargetDevice => Boolean(item));

    if (token === loadToken) {
      devices.value = ordered;
    }
  } catch (error) {
    if (token === loadToken) {
      loadError.value = formatApiError(error, t.value.pullPage.loadDevicesFailed);
      devices.value = [];
    }
  } finally {
    if (token === loadToken) {
      loadingDevices.value = false;
    }
  }
};

onMounted(() => {
  void loadSelectedDevices();
});

onUnmounted(() => {
  loadToken += 1;
});

watch(
  () => t.value.pullPage.loadDevicesFailed,
  () => {
    void loadSelectedDevices();
  },
);

const onlineTargets = computed(() => devices.value.filter((d) => d.status === "online"));
const operableTargets = computed(() => devices.value.filter((d) => d.rawState === "online"));

const onlineCount = computed(() => onlineTargets.value.length);
const offlineCount = computed(() => devices.value.filter((d) => d.status === "offline").length);
const busyCount = computed(() => devices.value.filter((d) => d.status === "busy").length);

const normalizedPaths = computed(() =>
  Array.from(new Set(files.value.map((item) => normalizePullPath(item.path)).filter(Boolean))),
);

const hasTask = computed(() => Object.keys(pullState.value).length > 0);

const successFileCount = computed(() =>
  Object.values(pullState.value).reduce((sum, item) => {
    const fileStates = item.files || {};
    const successCount = Object.values(fileStates).filter((state) => state.status === "success").length;
    return sum + successCount;
  }, 0),
);
const pullStatusText = computed<Record<PullStatus, string>>(() => ({
  idle: t.value.pullPage.statusIdle,
  pending: t.value.pullPage.statusPending,
  pulling: t.value.pullPage.statusPulling,
  success: t.value.pullPage.statusSuccess,
  failed: t.value.pullPage.statusFailed,
}));

const statusLabels = computed(() => ({
  online: t.value.pullPage.statusOnline,
  offline: t.value.pullPage.statusOffline,
  busy: t.value.pullPage.statusBusy,
}));

const statusBadge = (status: DeviceStatus) => {
  const labels = statusLabels.value;
  const map: Record<DeviceStatus, { label: string; color: string; bg: string }> = {
    online: {
      label: labels.online,
      color: "text-green-600",
      bg: "bg-green-100 dark:bg-green-900/40",
    },
    offline: {
      label: labels.offline,
      color: "text-gray-600",
      bg: "bg-gray-100 dark:bg-gray-800/40",
    },
    busy: {
      label: labels.busy,
      color: "text-yellow-600",
      bg: "bg-yellow-100 dark:bg-yellow-900/40",
    },
  };
  return map[status];
};

const deviceRows = computed(() =>
  devices.value.map((device) => {
    const task = pullState.value[device.id];
    const success = task?.status === "success";
    const failed = task?.status === "failed";
    const activePath = task?.currentPath ? normalizePullPath(task.currentPath) : "";
    const showDetails = Boolean(task && task.status !== "idle" && task.status !== "success");
    const progress = Math.max(0, Math.min(100, Number(task?.progress || 0)));
    const statusLabel = task ? pullStatusText.value[task.status] : "";
    const taskStatus = task?.status;
    const taskProgress = task?.progress ?? 0;
    return {
      device,
      success,
      failed,
      activePath,
      showDetails,
      progress,
      statusLabel,
      taskStatus,
      taskProgress,
    };
  }),
);

const resetPullResult = () => {
  pullSession += 1;
  abortAllPullXhrs();
  pulledBlobMap.clear();
  pullState.value = {};
  actionMessage.value = null;
  actionError.value = null;
};

const addFile = () => {
  if (pulling.value) return;
  const normalized = normalizePullPath(filePath.value);
  if (!normalized) return;

  const prev = files.value;
  if (prev.some((item) => normalizePullPath(item.path) === normalized)) {
    // keep existing list
  } else {
    files.value = [...prev, { id: `${normalized}::${Date.now()}`, path: normalized }];
  }
  filePath.value = "";
  resetPullResult();
};

const removeFile = (id: string) => {
  if (pulling.value) return;
  files.value = files.value.filter((item) => item.id !== id);
  resetPullResult();
};

const clearFiles = () => {
  if (pulling.value) return;
  files.value = [];
  resetPullResult();
};

const updatePullState = (
  deviceId: string,
  updater: (current: DevicePullState) => DevicePullState,
) => {
  const current: DevicePullState = pullState.value[deviceId] || idlePullState();
  pullState.value = {
    ...pullState.value,
    [deviceId]: recomputePullProgress(updater(current)),
  };
};

const fetchFileFromDevice = (
  domain: string,
  remotePath: string,
  timeoutSec: number,
  onProgress: (pct: number) => void,
) =>
  new Promise<Blob>((resolve, reject) => {
    const normalizedPath = normalizePullPath(remotePath).replace(/^\/+/, "");
    if (!normalizedPath) {
      reject(new Error(t.value.pullPage.pathEmpty));
      return;
    }

    const url = `/d/${encodeURIComponent(domain)}/fs/${encodePath(normalizedPath)}`;
    const xhrKey = `${domain}::${normalizedPath}`;
    const xhr = new XMLHttpRequest();
    pullXhrs.set(xhrKey, xhr);

    xhr.open("GET", url, true);
    xhr.withCredentials = true;
    xhr.responseType = "blob";
    xhr.timeout = Math.max(10, Number(timeoutSec) || 600) * 1000;

    let headerTotal = 0;
    const resolveHeaderTotal = () => {
      if (headerTotal > 0) return headerTotal;
      headerTotal = resolveDownloadTotalFromHeaders(xhr);
      return headerTotal;
    };

    xhr.onreadystatechange = () => {
      if (xhr.readyState >= XMLHttpRequest.HEADERS_RECEIVED) {
        resolveHeaderTotal();
      }
    };

    xhr.onprogress = (evt) => {
      let total = evt.lengthComputable ? evt.total : 0;
      if (!total) {
        total = resolveHeaderTotal();
      }
      const loaded = evt.loaded || 0;
      const pct = total
        ? Math.min(99, Math.floor((loaded / total) * 100))
        : loaded > 0
          ? Math.min(95, 15 + Math.floor(Math.log2(loaded + 1) * 6))
          : 0;
      onProgress(pct);
    };

    xhr.onload = async () => {
      pullXhrs.delete(xhrKey);
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response as Blob);
        return;
      }
      reject(new Error(await parsePullErrorMessage(xhr, t.value.pullPage.pullFailed)));
    };

    xhr.onerror = () => {
      pullXhrs.delete(xhrKey);
      reject(new Error(t.value.pullPage.networkError));
    };

    xhr.onabort = () => {
      pullXhrs.delete(xhrKey);
      reject(new Error(t.value.pullPage.cancelled));
    };

    xhr.ontimeout = () => {
      pullXhrs.delete(xhrKey);
      reject(new Error(t.value.pullPage.downloadTimeout));
    };

    xhr.send();
  });

const finalizePullArchive = async () => {
  const sessionId = pullSession;
  const filesToExport = Array.from(pulledBlobMap.values()).filter((item) => item.sessionId === sessionId);
  if (!filesToExport.length) {
    actionError.value = t.value.pullPage.noFilesForExport;
    return;
  }

  try {
    const tarBlob = await buildTarBlob(filesToExport);
    triggerBrowserDownload(tarBlob, buildPullArchiveName());
    actionError.value = null;
    actionMessage.value = interpolate(t.value.pullPage.exportedSummary, { n: filesToExport.length });
  } catch (error) {
    actionError.value = formatApiError(error, t.value.pullPage.exportFailed);
  }
};

const startPull = async () => {
  if (pulling.value) return;
  if (!operableTargets.value.length || !normalizedPaths.value.length) return;

  const sessionId = pullSession + 1;
  pullSession = sessionId;
  abortAllPullXhrs();
  pulledBlobMap.clear();

  actionError.value = null;
  actionMessage.value = null;
  pulling.value = true;

  const initialState: Record<string, DevicePullState> = {};
  for (const device of operableTargets.value) {
    const filesByPath: Record<string, DevicePullFileState> = {};
    for (const path of normalizedPaths.value) {
      filesByPath[path] = { status: "pending", progress: 0 };
    }
    initialState[device.id] = {
      status: "pending",
      progress: 0,
      currentPath: normalizedPaths.value[0],
      files: filesByPath,
    };
  }
  pullState.value = initialState;

  let failedDevices = 0;

  await runWithConcurrency(operableTargets.value, Math.max(1, concurrency.value), async (device) => {
    if (sessionId !== pullSession) return;

    let deviceFailed = false;
    let lastError = "";

    for (const path of normalizedPaths.value) {
      if (sessionId !== pullSession) return;

      updatePullState(device.id, (current) => {
        const filesByPath = { ...(current.files || {}) };
        filesByPath[path] = { status: "pulling", progress: 0 };
        return {
          ...current,
          status: "pulling",
          error: undefined,
          currentPath: path,
          files: filesByPath,
        };
      });

      let blob: Blob;
      try {
        blob = await fetchFileFromDevice(
          device.id,
          path,
          Math.max(10, pullTimeout.value),
          (pct) => {
            if (sessionId !== pullSession) return;
            updatePullState(device.id, (current) => {
              const filesByPath = { ...(current.files || {}) };
              filesByPath[path] = { status: "pulling", progress: pct };
              return {
                ...current,
                status: "pulling",
                currentPath: path,
                files: filesByPath,
              };
            });
          },
        );
      } catch (error) {
        if (sessionId !== pullSession) return;
        deviceFailed = true;
        lastError = formatApiError(error, t.value.pullPage.pullFailed);
        updatePullState(device.id, (current) => {
          const filesByPath = { ...(current.files || {}) };
          filesByPath[path] = {
            status: "failed",
            progress: filesByPath[path]?.progress ?? 0,
            error: lastError,
          };
          return {
            ...current,
            status: "failed",
            error: lastError,
            currentPath: path,
            files: filesByPath,
          };
        });
        continue;
      }

      if (sessionId !== pullSession) return;
      pulledBlobMap.set(`${device.id}::${path}`, {
        sessionId,
        domain: device.id,
        remotePath: path,
        blob,
      });

      updatePullState(device.id, (current) => {
        const filesByPath = { ...(current.files || {}) };
        filesByPath[path] = { status: "success", progress: 100 };
        return {
          ...current,
          status: "pulling",
          error: undefined,
          currentPath: path,
          files: filesByPath,
        };
      });
    }

    if (sessionId !== pullSession) return;
    if (deviceFailed) {
      failedDevices += 1;
    }
    pullState.value = {
      ...pullState.value,
      [device.id]: {
        ...(pullState.value[device.id] || idlePullState()),
        status: deviceFailed ? "failed" : "success",
        progress: 100,
        error: deviceFailed ? lastError : undefined,
      },
    };
  });

  if (sessionId !== pullSession) return;

  const successFiles = Array.from(pulledBlobMap.values()).filter((item) => item.sessionId === sessionId).length;

  if (successFiles <= 0) {
    actionError.value =
      failedDevices > 0
        ? interpolate(t.value.pullPage.noFilesDownloadedWithFailed, { failed: failedDevices })
        : t.value.pullPage.noFilesDownloaded;
  } else if (failedDevices > 0) {
    actionError.value = interpolate(t.value.pullPage.downloadedFailedSummary, { ok: successFiles, failed: failedDevices });
  } else {
    actionMessage.value = interpolate(t.value.pullPage.downloadedSummary, { n: successFiles });
  }

  pulling.value = false;
};

const retryPullDevice = async (deviceId: string) => {
  if (pulling.value) return;
  const device = operableTargets.value.find((item) => item.id === deviceId);
  if (!device) return;
  const previous = pullState.value[deviceId];
  const failedPaths = Object.entries(previous?.files || {})
    .filter(([, state]) => state.status === "failed")
    .map(([path]) => path);
  const targetPaths = failedPaths.length ? failedPaths : normalizedPaths.value;
  if (!targetPaths.length) return;

  const sessionId = pullSession || 1;
  pullSession = sessionId;
  abortAllPullXhrs();
  actionError.value = null;
  actionMessage.value = null;
  pulling.value = true;

  pullState.value = (() => {
    const prev = pullState.value;
    const current: DevicePullState = prev[deviceId] || idlePullState();
    const filesByPath = { ...(current.files || {}) };
    for (const path of targetPaths) {
      filesByPath[path] = { status: "pending", progress: 0 };
    }
    return {
      ...prev,
      [deviceId]: {
        ...current,
        status: "pending",
        error: undefined,
        currentPath: targetPaths[0],
        files: filesByPath,
      },
    };
  })();

  try {
    let deviceFailed = false;
    let lastError = "";

    for (const path of targetPaths) {
      if (sessionId !== pullSession) return;
      updatePullState(deviceId, (current) => {
        const filesByPath = { ...(current.files || {}) };
        filesByPath[path] = { status: "pulling", progress: 0 };
        return {
          ...current,
          status: "pulling",
          error: undefined,
          currentPath: path,
          files: filesByPath,
        };
      });

      let blob: Blob;
      try {
        blob = await fetchFileFromDevice(
          deviceId,
          path,
          Math.max(10, pullTimeout.value),
          (pct) => {
            if (sessionId !== pullSession) return;
            updatePullState(deviceId, (current) => {
              const filesByPath = { ...(current.files || {}) };
              filesByPath[path] = { status: "pulling", progress: pct };
              return {
                ...current,
                status: "pulling",
                currentPath: path,
                files: filesByPath,
              };
            });
          },
        );
      } catch (error) {
        if (sessionId !== pullSession) return;
        deviceFailed = true;
        lastError = formatApiError(error, t.value.pullPage.pullFailed);
        updatePullState(deviceId, (current) => {
          const filesByPath = { ...(current.files || {}) };
          filesByPath[path] = {
            status: "failed",
            progress: filesByPath[path]?.progress ?? 0,
            error: lastError,
          };
          return {
            ...current,
            status: "failed",
            error: lastError,
            currentPath: path,
            files: filesByPath,
          };
        });
        continue;
      }
      if (sessionId !== pullSession) return;
      pulledBlobMap.set(`${deviceId}::${path}`, {
        sessionId,
        domain: deviceId,
        remotePath: path,
        blob,
      });
      updatePullState(deviceId, (current) => {
        const filesByPath = { ...(current.files || {}) };
        filesByPath[path] = { status: "success", progress: 100 };
        return {
          ...current,
          status: "pulling",
          error: undefined,
          currentPath: path,
          files: filesByPath,
        };
      });
    }

    if (sessionId !== pullSession) return;
    pullState.value = {
      ...pullState.value,
      [deviceId]: {
        ...(pullState.value[deviceId] || idlePullState()),
        status: deviceFailed ? "failed" : "success",
        progress: 100,
        error: deviceFailed ? lastError : undefined,
      },
    };
    if (deviceFailed) {
      actionError.value = lastError;
    } else {
      actionMessage.value = interpolate(t.value.pullPage.retrySuccess, { id: deviceId });
    }
  } finally {
    if (sessionId === pullSession) {
      pulling.value = false;
    }
  }
};

const actionLabel = computed(() =>
  !pulling.value && hasTask.value && successFileCount.value > 0
    ? t.value.pullPage.exportFiles
    : pulling.value
      ? t.value.pullPage.pulling
      : t.value.pullPage.startPull,
);

const canPullAction = computed(
  () =>
    !pulling.value &&
    !loadingDevices.value &&
    ((operableTargets.value.length > 0 && normalizedPaths.value.length > 0) ||
      (hasTask.value && successFileCount.value > 0)),
);

const handlePullAction = async () => {
  if (!canPullAction.value) return;

  if (!pulling.value && hasTask.value && successFileCount.value > 0) {
    await finalizePullArchive();
    return;
  }

  await startPull();
};

const onRetry = (deviceId: string) => {
  void retryPullDevice(deviceId);
};

const onFilePathKeydown = (e: KeyboardEvent) => {
  if (e.key === "Enter") addFile();
};
</script>

<template>
  <div class="flex h-screen w-full overflow-hidden bg-[#f5f5f7]">
    <Sidebar />

    <div class="flex h-screen min-w-0 flex-1 flex-col lg:ml-[220px]">
      <header class="flex h-14 shrink-0 items-center justify-between border-b border-gray-100 bg-white px-5">
        <div class="flex items-center gap-3">
          <Button as-child size="icon" variant="ghost" class="h-8 w-8">
            <button @click="router.back()">
              <ChevronLeft class="h-4 w-4" />
            </button>
          </Button>
          <div>
            <p class="text-base font-semibold leading-tight">{{ t.pullPage.title }}</p>
          </div>
        </div>

        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2">
            <Clock class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.pullPage.timeout }}</span>
            <Input
              :model-value="pullTimeout"
              @update:model-value="pullTimeout = Number($event) || 0"
              type="number"
              class="h-7 w-20 font-mono text-xs"
              :disabled="pulling"
            />
            <span class="text-xs text-muted-foreground">s</span>
          </div>

          <Separator orientation="vertical" class="h-5" />

          <div class="flex items-center gap-2">
            <Zap class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.pullPage.concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.max(1, concurrency - 1)"
              :disabled="concurrency <= 1 || pulling"
            >
              <Minus class="h-3 w-3" />
            </Button>
            <span class="w-5 text-center text-xs">{{ concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.min(20, concurrency + 1)"
              :disabled="concurrency >= 20 || pulling"
            >
              <Plus class="h-3 w-3" />
            </Button>
          </div>
        </div>
      </header>

      <main class="flex min-h-0 flex-1 gap-2 overflow-hidden p-3">
        <aside class="flex min-h-0 w-96 shrink-0 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
          <div class="flex items-center justify-between border-b border-gray-100 px-6 py-4">
            <div>
              <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {{ t.pullPage.targetDevices }}
              </p>
              <p class="mt-1 text-2xl font-bold">{{ devices.length }}</p>
            </div>
            <div class="space-y-1 text-right text-xs text-muted-foreground">
              <div class="flex items-center justify-end gap-1.5">
                <div class="h-2 w-2 rounded-full bg-green-500" />
                <span>{{ onlineCount }}</span>
              </div>
              <div class="flex items-center justify-end gap-1.5">
                <div class="h-2 w-2 rounded-full bg-yellow-500" />
                <span>{{ busyCount }}</span>
              </div>
              <div class="flex items-center justify-end gap-1.5">
                <div class="h-2 w-2 rounded-full bg-gray-400" />
                <span>{{ offlineCount }}</span>
              </div>
            </div>
          </div>
          <ScrollArea class="min-h-0 flex-1">
            <div class="w-full">
              <div class="grid grid-cols-[1fr_260px] border-b border-border px-6 py-2 text-xs font-semibold text-muted-foreground">
                <div>{{ t.pullPage.deviceId }}</div>
                <div class="text-right" />
              </div>
              <div
                v-for="row in deviceRows"
                :key="row.device.id"
                class="overflow-hidden border-b border-border/60 px-6 py-2.5 hover:bg-muted/50"
              >
                <div class="flex w-full items-center justify-between gap-4">
                  <div class="flex min-w-0 items-start gap-3">
                    <div class="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center">
                      <button
                        v-if="row.failed"
                        class="inline-flex h-4 w-4 items-center justify-center text-blue-600 disabled:opacity-50"
                        :disabled="pulling"
                        @click="onRetry(row.device.id)"
                        :aria-label="t.pullPage.retry"
                        :title="t.pullPage.retry"
                      >
                        <RotateCw class="h-3.5 w-3.5" />
                      </button>
                      <CheckCircle2
                        v-else-if="row.success"
                        class="h-4 w-4 text-emerald-500 animate-pulse"
                      />
                      <div
                        v-else
                        :class="
                          cn(
                            'h-2.5 w-2.5 rounded-full',
                            row.device.status === 'online'
                              ? 'bg-green-500'
                              : row.device.status === 'busy'
                                ? 'bg-yellow-500'
                                : 'bg-gray-400',
                          )
                        "
                      />
                    </div>
                    <div class="min-w-0">
                      <p class="truncate font-mono text-xs font-semibold text-foreground">{{ row.device.id }}</p>
                      <p class="text-xs text-muted-foreground">
                        {{ row.device.brand }} {{ row.device.model }}
                      </p>
                    </div>
                  </div>
                  <div class="shrink-0">
                    <Badge
                      :class="cn('font-medium', statusBadge(row.device.status).bg, statusBadge(row.device.status).color)"
                      variant="outline"
                    >
                      {{ statusBadge(row.device.status).label }}
                    </Badge>
                  </div>
                </div>
                <div v-if="row.showDetails" class="mx-auto mt-2 w-full max-w-[520px] min-w-0 space-y-1">
                  <div class="flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                    <p class="min-w-0 flex-1 truncate">
                      {{ row.statusLabel }} {{ row.activePath }}
                    </p>
                    <span class="shrink-0">{{ row.taskProgress }}%</span>
                  </div>
                  <div class="h-1 w-full overflow-hidden rounded bg-muted/80">
                    <div
                      :class="
                        cn(
                          'h-full transition-all duration-200',
                          row.taskStatus === 'failed' ? 'bg-destructive' : 'bg-emerald-500',
                        )
                      "
                      :style="{ width: `${Math.max(2, row.progress)}%` }"
                    />
                  </div>
                </div>
              </div>
            </div>
          </ScrollArea>
        </aside>

        <div class="flex min-w-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
          <div class="shrink-0 border-b border-gray-100 bg-white px-6 py-4">
            <div>
              <p class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {{ t.pullPage.targetFiles }}
              </p>
              <div class="flex items-center gap-2">
                <Input
                  v-model="filePath"
                  @keydown="onFilePathKeydown"
                  :placeholder="t.pullPage.pathPlaceholder"
                  class="h-8 font-mono text-xs"
                  :disabled="pulling"
                />
                <Button size="sm" class="h-8 w-8 shrink-0 p-0" @click="addFile" :disabled="pulling || !filePath.trim()">
                  <Plus class="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>

          <div class="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto bg-white p-6">
            <div
              v-if="files.length === 0"
              class="flex flex-1 flex-col items-center justify-center gap-2 text-muted-foreground"
            >
              <FileText class="h-6 w-6 opacity-40" />
              <p class="text-xs">{{ t.pullPage.noFiles }}</p>
            </div>
            <div v-else class="flex flex-col gap-2">
              <div class="flex items-center justify-between px-3 py-2">
                <span class="text-xs text-muted-foreground">
                  {{ interpolate(t.pullPage.fileCount, { n: files.length }) }}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-6 px-2 text-xs text-destructive hover:text-destructive"
                  @click="clearFiles"
                  :disabled="pulling"
                >
                  {{ t.pullPage.clear }}
                </Button>
              </div>
              <div class="overflow-hidden rounded-lg border border-gray-100">
                <div class="divide-y divide-gray-100">
                  <div
                    v-for="(item, idx) in files"
                    :key="item.id"
                    :class="
                      cn(
                        'flex items-center justify-between gap-3 px-3 py-2 text-xs',
                        idx % 2 === 0 ? 'bg-muted/40' : 'bg-muted/60',
                      )
                    "
                  >
                    <div class="min-w-0 flex items-center gap-2">
                      <FileText class="h-4 w-4 shrink-0 text-blue-500" />
                      <span class="truncate">{{ item.path }}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      class="h-5 w-5 text-destructive hover:text-destructive"
                      @click="removeFile(item.id)"
                      :disabled="pulling"
                    >
                      <X class="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="flex shrink-0 items-center justify-between border-t border-gray-100 bg-white px-6 py-2">
            <div class="flex min-w-0 items-center gap-3">
              <p class="truncate text-xs text-muted-foreground">
                {{ interpolate(t.pullPage.fileCount, { n: normalizedPaths.length }) }} •
                {{ t.pullPage.timeout }} {{ pullTimeout }}{{ t.pullPage.timeoutUnit }} •
                {{ t.pullPage.concurrency }} {{ concurrency }}
              </p>
              <p v-if="loadingDevices" class="shrink-0 text-[11px] text-muted-foreground">
                {{ t.pullPage.loadingDevices }}
              </p>
              <div class="min-h-0 shrink-0">
                <FeedbackTip v-if="loadError" :message="loadError" variant="error" compact />
                <FeedbackTip v-else-if="actionError" :message="actionError" variant="error" compact />
                <FeedbackTip v-else-if="actionMessage" :message="actionMessage" variant="success" compact />
              </div>
            </div>

            <div class="flex items-center gap-2">
              <Button variant="outline" size="sm" class="h-7" @click="router.back()">
                {{ t.pullPage.cancel }}
              </Button>
              <Button :disabled="!canPullAction" @click="handlePullAction" size="sm" class="h-7 gap-1">
                <ArrowDown class="h-3 w-3" />
                {{ actionLabel }}
              </Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>
</template>
