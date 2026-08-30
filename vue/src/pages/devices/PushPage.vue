<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useHashRouter } from "@/lib/hash-router";
import { useDropzone, type FileRejection } from "@/lib/use-dropzone";
import {
  ArrowDown,
  ChevronLeft,
  CheckCircle2,
  FileText,
  FolderOpen,
  Minus,
  Plus,
  RotateCw,
  Upload,
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

type PushFile = {
  id: string;
  file: File;
  sizeLabel: string;
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

type UploadStatus = "idle" | "pending" | "uploading" | "success" | "failed";

type DeviceFileUploadState = {
  status: UploadStatus;
  progress: number;
  error?: string;
};

type DeviceUploadState = {
  status: UploadStatus;
  progress: number;
  error?: string;
  currentFileId?: string;
  files?: Record<string, DeviceFileUploadState>;
};

const MAX_SINGLE_FILE_BYTES = 512 * 1024 * 1024;
const PUSH_UPLOAD_TIMEOUT_SEC = 900;

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function normalizeStatus(state: string, locked: boolean): DeviceStatus {
  if (state === "online") return locked ? "busy" : "online";
  return "offline";
}

function fileIdOf(file: File): string {
  return `${file.name}::${file.size}::${file.lastModified}`;
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

function normalizeTargetDir(dir: string): string {
  let next = String(dir || "").trim().replace(/\\/g, "/");
  if (!next) next = "/sdcard/";
  if (!next.endsWith("/")) next += "/";
  return next;
}

function buildRemotePath(dir: string, filename: string): string {
  const target = normalizeTargetDir(dir);
  return `${target}${filename}`.replace(/\\/g, "/").replace(/^\/+/, "");
}

function recomputeDeviceProgress(state: DeviceUploadState): DeviceUploadState {
  const files = state.files || {};
  const ids = Object.keys(files);
  if (!ids.length) return state;
  const sum = ids.reduce((acc, id) => acc + (Number(files[id]?.progress) || 0), 0);
  return {
    ...state,
    progress: Math.max(0, Math.min(100, Math.floor(sum / ids.length))),
  };
}

function normalizeSelectedFiles(files: File[]): File[] {
  const accepted: File[] = [];
  for (const file of files) {
    if ((Number(file?.size) || 0) <= MAX_SINGLE_FILE_BYTES) {
      accepted.push(file);
    }
  }
  return accepted;
}

function mergePushFiles(existing: PushFile[], incoming: File[]): PushFile[] {
  const map = new Map<string, PushFile>();
  for (const item of existing) {
    map.set(item.id, item);
  }
  for (const file of normalizeSelectedFiles(incoming)) {
    const id = fileIdOf(file);
    if (!map.has(id)) {
      map.set(id, {
        id,
        file,
        sizeLabel: fmtSize(Number(file.size || 0)),
      });
    }
  }
  return Array.from(map.values());
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

function parseXhrMessage(xhr: XMLHttpRequest, fallback: string): string {
  const raw = String(xhr.responseText || "").trim();
  if (!raw) return `${fallback} (HTTP ${xhr.status})`;
  try {
    const payload = JSON.parse(raw) as { message?: unknown; error?: unknown };
    if (typeof payload.message === "string" && payload.message) return payload.message;
    if (typeof payload.error === "string" && payload.error) return payload.error;
  } catch {
    // ignore
  }
  return raw;
}

function idleUploadState(): DeviceUploadState {
  return { status: "idle", progress: 0 };
}

const router = useHashRouter();
const { t } = useTranslation();

const devices = ref<TargetDevice[]>([]);
const loadingDevices = ref(true);
const loadError = ref<string | null>(null);

const targetDir = ref("/sdcard/");
const concurrency = ref(3);
const files = ref<PushFile[]>([]);
const pushing = ref(false);
const actionMessage = ref<string | null>(null);
const actionError = ref<string | null>(null);
const uploadState = ref<Record<string, DeviceUploadState>>({});

let session = 0;
const pushXhrs = new Map<string, XMLHttpRequest>();

const abortAllPushXhrs = () => {
  for (const xhr of pushXhrs.values()) {
    try {
      xhr.abort();
    } catch {
      // ignore
    }
  }
  pushXhrs.clear();
};

onUnmounted(() => {
  session += 1;
  abortAllPushXhrs();
});

let loadToken = 0;

const loadSelectedDevices = async () => {
  const token = ++loadToken;
  loadingDevices.value = true;
  loadError.value = null;
  try {
    const raw = sessionStorage.getItem("push_device_ids");
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
      errorMessage: t.value.pushPage.loadDevicesFailed,
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
      loadError.value = formatApiError(error, t.value.pushPage.loadDevicesFailed);
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
  () => t.value.pushPage.loadDevicesFailed,
  () => {
    void loadSelectedDevices();
  },
);

const onlineTargets = computed(() => devices.value.filter((d) => d.status === "online"));
const operableTargets = computed(() => devices.value.filter((d) => d.rawState === "online"));

const onlineCount = computed(() => onlineTargets.value.length);
const offlineCount = computed(() => devices.value.filter((d) => d.status === "offline").length);
const busyCount = computed(() => devices.value.filter((d) => d.status === "busy").length);

const totalBytes = computed(() =>
  files.value.reduce((sum, item) => sum + Number(item.file?.size || 0), 0),
);
const fileNameById = computed<Record<string, string>>(() =>
  Object.fromEntries(files.value.map((item) => [item.id, item.file.name])),
);
const uploadStatusText = computed<Record<UploadStatus, string>>(() => ({
  idle: t.value.pushPage.statusIdle,
  pending: t.value.pushPage.statusPending,
  uploading: t.value.pushPage.statusUploading,
  success: t.value.pushPage.statusSuccess,
  failed: t.value.pushPage.statusFailed,
}));

const statusLabels = computed(() => ({
  online: t.value.pushPage.statusOnline,
  offline: t.value.pushPage.statusOffline,
  busy: t.value.pushPage.statusBusy,
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
    const task = uploadState.value[device.id];
    const success = task?.status === "success";
    const failed = task?.status === "failed";
    const activeFileName = task?.currentFileId ? fileNameById.value[task.currentFileId] || "" : "";
    const showDetails = Boolean(task && task.status !== "idle" && task.status !== "success");
    const progress = Math.max(0, Math.min(100, Number(task?.progress || 0)));
    const statusLabel = task ? uploadStatusText.value[task.status] : "";
    const taskStatus = task?.status;
    const taskProgress = task?.progress ?? 0;
    return {
      device,
      success,
      failed,
      activeFileName,
      showDetails,
      progress,
      statusLabel,
      taskStatus,
      taskProgress,
    };
  }),
);

const addFiles = (incoming: File[]) => {
  if (!incoming.length) return;
  actionError.value = null;
  files.value = mergePushFiles(files.value, incoming);
};

const handleFileRejections = (rejections: FileRejection[]) => {
  if (!rejections.length) return;
  const oversized = rejections.filter((item) =>
    item.errors.some((err) => err.code === "file-too-large"),
  );
  if (oversized.length > 0) {
    actionError.value = interpolate(t.value.pushPage.fileTooLarge, { n: oversized.length, size: "512MB" });
  }
};

const removeFile = (id: string) => {
  if (pushing.value) return;
  files.value = files.value.filter((item) => item.id !== id);
};

const clearFiles = () => {
  if (pushing.value) return;
  files.value = [];
};

const { getRootProps, getInputProps, isDragActive, setInputRef } = useDropzone({
  maxSize: MAX_SINGLE_FILE_BYTES,
  onDrop: (acceptedFiles, fileRejections) => {
    addFiles(acceptedFiles);
    handleFileRejections(fileRejections);
  },
  onDropRejected: handleFileRejections,
  multiple: true,
  disabled: pushing,
});

const updateDeviceState = (
  deviceId: string,
  updater: (current: DeviceUploadState) => DeviceUploadState,
) => {
  const current: DeviceUploadState = uploadState.value[deviceId] || idleUploadState();
  uploadState.value = {
    ...uploadState.value,
    [deviceId]: recomputeDeviceProgress(updater(current)),
  };
};

const uploadFileToDevice = (
  domain: string,
  remotePath: string,
  file: File,
  onProgress: (pct: number) => void,
) =>
  new Promise<void>((resolve, reject) => {
    const url = `/d/${encodeURIComponent(domain)}/upload/${encodePath(remotePath)}`;
    const xhr = new XMLHttpRequest();
    pushXhrs.set(domain, xhr);

    xhr.open("PUT", url, true);
    xhr.withCredentials = true;
    xhr.timeout = PUSH_UPLOAD_TIMEOUT_SEC * 1000;

    xhr.upload.onprogress = (evt) => {
      const total = evt.lengthComputable ? evt.total : file.size;
      const loaded = evt.loaded || 0;
      const pct = total ? Math.min(99, Math.floor((loaded / total) * 100)) : 0;
      onProgress(pct);
    };

    xhr.onload = () => {
      pushXhrs.delete(domain);
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      reject(new Error(parseXhrMessage(xhr, t.value.pushPage.uploadFailed)));
    };

    xhr.onerror = () => {
      pushXhrs.delete(domain);
      reject(new Error(t.value.pushPage.networkError));
    };

    xhr.onabort = () => {
      pushXhrs.delete(domain);
      reject(new Error(t.value.pushPage.cancelled));
    };

    xhr.ontimeout = () => {
      pushXhrs.delete(domain);
      reject(new Error(t.value.pushPage.uploadTimeout));
    };

    // Override multipart default: send raw binary file content in request body.
    xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");
    xhr.send(file);
  });

const canPush = computed(
  () => files.value.length > 0 && operableTargets.value.length > 0 && !pushing.value && !loadingDevices.value,
);

const handlePush = async () => {
  if (!canPush.value) return;

  const sessionId = session + 1;
  session = sessionId;
  abortAllPushXhrs();

  actionError.value = null;
  actionMessage.value = null;
  pushing.value = true;

  const selectedFiles = files.value.map((item) => item.file);
  const fileIds = selectedFiles.map((file) => fileIdOf(file));
  let failedDevices = 0;

  const initialState: Record<string, DeviceUploadState> = {};
  for (const device of operableTargets.value) {
    const fileState: Record<string, DeviceFileUploadState> = {};
    for (const fileId of fileIds) {
      fileState[fileId] = { status: "pending", progress: 0 };
    }
    initialState[device.id] = {
      status: "pending",
      progress: 0,
      currentFileId: fileIds[0],
      files: fileState,
    };
  }
  uploadState.value = initialState;

  await runWithConcurrency(operableTargets.value, Math.max(1, concurrency.value), async (device) => {
    if (sessionId !== session) return;

    let deviceFailed = false;
    let lastError = "";

    for (const file of selectedFiles) {
      if (sessionId !== session) return;

      const fileId = fileIdOf(file);
      updateDeviceState(device.id, (current) => {
        const filesById = { ...(current.files || {}) };
        filesById[fileId] = { status: "uploading", progress: 0 };
        return {
          ...current,
          status: "uploading",
          error: undefined,
          currentFileId: fileId,
          files: filesById,
        };
      });

      const remotePath = buildRemotePath(targetDir.value, file.name);
      try {
        await uploadFileToDevice(device.id, remotePath, file, (pct) => {
          if (sessionId !== session) return;
          updateDeviceState(device.id, (current) => {
            const filesById = { ...(current.files || {}) };
            filesById[fileId] = {
              status: "uploading",
              progress: pct,
            };
            return {
              ...current,
              status: "uploading",
              currentFileId: fileId,
              files: filesById,
            };
          });
        });
      } catch (error) {
        if (sessionId !== session) return;
        deviceFailed = true;
        lastError = formatApiError(error, t.value.pushPage.uploadFailed);
        updateDeviceState(device.id, (current) => {
          const filesById = { ...(current.files || {}) };
          filesById[fileId] = {
            status: "failed",
            progress: filesById[fileId]?.progress ?? 0,
            error: lastError,
          };
          return {
            ...current,
            status: "failed",
            error: lastError,
            currentFileId: fileId,
            files: filesById,
          };
        });
        continue;
      }

      if (sessionId !== session) return;
      updateDeviceState(device.id, (current) => {
        const filesById = { ...(current.files || {}) };
        filesById[fileId] = { status: "success", progress: 100 };
        return {
          ...current,
          status: "uploading",
          error: undefined,
          currentFileId: fileId,
          files: filesById,
        };
      });
    }

    if (sessionId !== session) return;
    if (deviceFailed) {
      failedDevices += 1;
    }
    uploadState.value = {
      ...uploadState.value,
      [device.id]: {
        ...(uploadState.value[device.id] || idleUploadState()),
        status: deviceFailed ? "failed" : "success",
        progress: 100,
        error: deviceFailed ? lastError : undefined,
      },
    };
  });

  if (sessionId !== session) return;

  if (failedDevices > 0) {
    actionError.value = interpolate(t.value.pushPage.devicesFailed, { n: failedDevices });
  } else {
    actionMessage.value = interpolate(t.value.pushPage.uploadedSummary, { n: operableTargets.value.length });
  }
  pushing.value = false;
};

const retryUploadDevice = async (deviceId: string) => {
  if (pushing.value) return;
  const device = operableTargets.value.find((item) => item.id === deviceId);
  if (!device) return;
  const previous = uploadState.value[deviceId];
  const failedIds = Object.entries(previous?.files || {})
    .filter(([, state]) => state.status === "failed")
    .map(([id]) => id);
  const targetFileIds = failedIds.length ? failedIds : files.value.map((item) => item.id);
  if (!targetFileIds.length) return;

  const sessionId = session + 1;
  session = sessionId;
  abortAllPushXhrs();
  actionError.value = null;
  actionMessage.value = null;
  pushing.value = true;

  uploadState.value = (() => {
    const prev = uploadState.value;
    const current: DeviceUploadState = prev[deviceId] || idleUploadState();
    const filesById = { ...(current.files || {}) };
    for (const fileId of targetFileIds) {
      filesById[fileId] = { status: "pending", progress: 0 };
    }
    return {
      ...prev,
      [deviceId]: {
        ...current,
        status: "pending",
        error: undefined,
        currentFileId: targetFileIds[0],
        files: filesById,
      },
    };
  })();

  try {
    let deviceFailed = false;
    let lastError = "";

    for (const fileId of targetFileIds) {
      if (sessionId !== session) return;
      const pushFile = files.value.find((item) => item.id === fileId);
      if (!pushFile) continue;
      updateDeviceState(deviceId, (current) => {
        const filesById = { ...(current.files || {}) };
        filesById[fileId] = { status: "uploading", progress: 0 };
        return {
          ...current,
          status: "uploading",
          error: undefined,
          currentFileId: fileId,
          files: filesById,
        };
      });
      const remotePath = buildRemotePath(targetDir.value, pushFile.file.name);
      try {
        await uploadFileToDevice(deviceId, remotePath, pushFile.file, (pct) => {
          if (sessionId !== session) return;
          updateDeviceState(deviceId, (current) => {
            const filesById = { ...(current.files || {}) };
            filesById[fileId] = { status: "uploading", progress: pct };
            return {
              ...current,
              status: "uploading",
              currentFileId: fileId,
              files: filesById,
            };
          });
        });
      } catch (error) {
        if (sessionId !== session) return;
        deviceFailed = true;
        lastError = formatApiError(error, t.value.pushPage.uploadFailed);
        updateDeviceState(deviceId, (current) => {
          const filesById = { ...(current.files || {}) };
          filesById[fileId] = {
            status: "failed",
            progress: filesById[fileId]?.progress ?? 0,
            error: lastError,
          };
          return {
            ...current,
            status: "failed",
            error: lastError,
            currentFileId: fileId,
            files: filesById,
          };
        });
        continue;
      }
      if (sessionId !== session) return;
      updateDeviceState(deviceId, (current) => {
        const filesById = { ...(current.files || {}) };
        filesById[fileId] = { status: "success", progress: 100 };
        return {
          ...current,
          status: "uploading",
          error: undefined,
          currentFileId: fileId,
          files: filesById,
        };
      });
    }

    if (sessionId !== session) return;
    uploadState.value = {
      ...uploadState.value,
      [deviceId]: {
        ...(uploadState.value[deviceId] || idleUploadState()),
        status: deviceFailed ? "failed" : "success",
        progress: 100,
        error: deviceFailed ? lastError : undefined,
      },
    };
    if (deviceFailed) {
      actionError.value = lastError;
    } else {
      actionMessage.value = interpolate(t.value.pushPage.retrySuccess, { id: deviceId });
    }
  } finally {
    if (sessionId === session) {
      pushing.value = false;
    }
  }
};

const onRetry = (deviceId: string) => {
  void retryUploadDevice(deviceId);
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
            <p class="text-base font-semibold leading-tight">{{ t.pushPage.title }}</p>
          </div>
        </div>

        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2">
            <FolderOpen class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.pushPage.targetDir }}</span>
            <Input
              v-model="targetDir"
              class="h-7 w-40 font-mono text-xs"
              placeholder="/sdcard/"
              :disabled="pushing"
            />
          </div>

          <Separator orientation="vertical" class="h-5" />

          <div class="flex items-center gap-2">
            <Zap class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.pushPage.concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.max(1, concurrency - 1)"
              :disabled="concurrency <= 1 || pushing"
            >
              <Minus class="h-3 w-3" />
            </Button>
            <span class="w-5 text-center text-xs">{{ concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.min(20, concurrency + 1)"
              :disabled="concurrency >= 20 || pushing"
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
                {{ t.pushPage.targetDevices }}
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
                <div>{{ t.pushPage.deviceId }}</div>
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
                        :disabled="pushing"
                        @click="onRetry(row.device.id)"
                        :aria-label="t.pushPage.retry"
                        :title="t.pushPage.retry"
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
                      {{ row.statusLabel }} {{ row.activeFileName }}
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
          <div class="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto bg-white p-6">
            <div
              v-bind="getRootProps()"
              :class="
                cn(
                  'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed bg-muted px-6 py-8 transition-colors',
                  isDragActive
                    ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/20'
                    : 'border-gray-200 hover:border-blue-400',
                  pushing && 'cursor-not-allowed opacity-60',
                )
              "
            >
              <input :ref="setInputRef" v-bind="getInputProps()" />
              <Upload :class="cn('h-6 w-6', isDragActive ? 'text-blue-500' : 'text-muted-foreground')" />
              <p class="text-center text-xs">{{ t.pushPage.dropzone }}</p>
              <p class="text-[11px] text-muted-foreground">{{ t.pushPage.maxSingleFileHint }}</p>
            </div>

            <div
              v-if="files.length === 0"
              class="flex flex-1 flex-col items-center justify-center gap-2 text-muted-foreground"
            >
              <FileText class="h-6 w-6 opacity-40" />
              <p class="text-xs">{{ t.pushPage.noFiles }}</p>
            </div>
            <div v-else class="flex flex-col gap-2">
              <div class="flex items-center justify-between px-3 py-2">
                <span class="text-xs text-muted-foreground">
                  {{ interpolate(t.pushPage.fileCount, { n: files.length }) }}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-6 px-2 text-xs text-destructive hover:text-destructive"
                  @click="clearFiles()"
                  :disabled="pushing"
                >
                  {{ t.pushPage.clear }}
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
                      <span class="truncate">{{ item.file.name }}</span>
                    </div>
                    <div class="flex shrink-0 items-center gap-2">
                      <span class="text-xs text-muted-foreground">{{ item.sizeLabel }}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="h-5 w-5 text-destructive hover:text-destructive"
                        @click="removeFile(item.id)"
                        :disabled="pushing"
                      >
                        <X class="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="flex shrink-0 items-center justify-between border-t border-gray-100 bg-white px-6 py-2">
            <div class="flex min-w-0 items-center gap-3">
              <p class="truncate text-xs text-muted-foreground">
                {{ normalizeTargetDir(targetDir) }} • {{ t.pushPage.concurrency }} {{ concurrency }} •
                {{ fmtSize(totalBytes) }}
              </p>
              <p v-if="loadingDevices" class="shrink-0 text-[11px] text-muted-foreground">
                {{ t.pushPage.loadingDevices }}
              </p>
              <div class="min-h-0 shrink-0">
                <FeedbackTip v-if="loadError" :message="loadError" variant="error" compact />
                <FeedbackTip v-else-if="actionError" :message="actionError" variant="error" compact />
                <FeedbackTip v-else-if="actionMessage" :message="actionMessage" variant="success" compact />
              </div>
            </div>

            <div class="flex items-center gap-2">
              <Button variant="outline" size="sm" class="h-7" @click="router.back()">
                {{ t.pushPage.cancel }}
              </Button>
              <Button :disabled="!canPush" @click="handlePush" size="sm" class="h-7 gap-1">
                <ArrowDown v-if="pushing" class="h-3 w-3" />
                <Upload v-else class="h-3 w-3" />
                {{ pushing ? t.pushPage.pushing : t.pushPage.startPush }}
              </Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>
</template>
