<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useHashRouter } from "@/lib/hash-router";
import {
  ChevronLeft,
  ChevronDown,
  CheckCircle2,
  Clock,
  Minus,
  Play,
  Plus,
  RotateCw,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
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

type CommandStatus = "idle" | "pending" | "running" | "success" | "failed";

type DeviceCommandState = {
  status: CommandStatus;
  exitCode?: number;
  output?: string;
  error?: string;
  expanded?: boolean;
};

function normalizeStatus(state: string, locked: boolean): DeviceStatus {
  if (state === "online") return locked ? "busy" : "online";
  return "offline";
}

function parseShellResponse(raw: string): { exitCode: number; output: string; error: string } {
  try {
    const data = JSON.parse(raw || "{}") as {
      exitCode?: unknown;
      output?: unknown;
      error?: unknown;
      data?: unknown;
    };

    const nested = (data?.data && typeof data.data === "object" ? data.data : null) as
      | { exitCode?: unknown; output?: unknown; error?: unknown }
      | null;

    const exitCode = Number((nested?.exitCode ?? data?.exitCode) ?? 1);
    const output = String((nested?.output ?? data?.output) ?? "");
    const error = String((nested?.error ?? data?.error) ?? "");
    return { exitCode, output, error };
  } catch {
    throw new Error("Response parse failed");
  }
}

function runShellCommand(
  domain: string,
  command: string,
  timeoutSec: number,
  asRoot: boolean,
  sessionId: number,
  commandXhrs: Map<string, XMLHttpRequest>,
) {
  return new Promise<{ exitCode: number; output: string; error: string }>((resolve, reject) => {
    const url = `/d/${encodeURIComponent(domain)}/shell`;
    const xhr = new XMLHttpRequest();
    const xhrKey = `${sessionId}::${domain}`;
    commandXhrs.set(xhrKey, xhr);

    xhr.open("POST", url, true);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.timeout = Math.max(5, Math.max(1, Number(timeoutSec) || 10) + 5) * 1000;

    xhr.onload = () => {
      commandXhrs.delete(xhrKey);
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(`Request failed (${xhr.status})`));
        return;
      }
      try {
        resolve(parseShellResponse(xhr.responseText || "{}"));
      } catch (error) {
        reject(error);
      }
    };
    xhr.onerror = () => {
      commandXhrs.delete(xhrKey);
      reject(new Error("Network error"));
    };
    xhr.onabort = () => {
      commandXhrs.delete(xhrKey);
      reject(new Error("Cancelled"));
    };
    xhr.ontimeout = () => {
      commandXhrs.delete(xhrKey);
      reject(new Error("Request timeout"));
    };

    const form = new URLSearchParams();
    form.set("command", command);
    form.set("timeout", String(timeoutSec));
    if (asRoot) form.set("role", "root");
    xhr.send(form.toString());
  });
}

const router = useHashRouter();
const { t } = useTranslation();

const devices = ref<TargetDevice[]>([]);
const loadingDevices = ref(true);
const loadError = ref<string | null>(null);

const timeoutVal = ref(10);
const concurrency = ref(5);
const script = ref("");
const rootMode = ref(false);
const executing = ref(false);
const actionMessage = ref<string | null>(null);
const actionError = ref<string | null>(null);

const commandState = ref<Record<string, DeviceCommandState>>({});
const sessionRef = ref(0);
const commandXhrsRef = ref<Map<string, XMLHttpRequest>>(new Map());

const textareaRef = ref<HTMLTextAreaElement | null>(null);
const lineNumberRef = ref<HTMLDivElement | null>(null);

const editorMonospaceStyle = {
  fontFamily: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
};
const editorTextareaStyle = {
  fontFamily: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
  tabSize: 2,
};

const setDeviceCommandState = (
  deviceId: string,
  updater: (current: DeviceCommandState) => DeviceCommandState,
) => {
  const current = commandState.value[deviceId] || { status: "idle" as CommandStatus };
  commandState.value = {
    ...commandState.value,
    [deviceId]: updater(current),
  };
};

const abortAllCommands = () => {
  for (const xhr of commandXhrsRef.value.values()) {
    try {
      xhr.abort();
    } catch {
      // ignore
    }
  }
  commandXhrsRef.value.clear();
};

onBeforeUnmount(() => {
  sessionRef.value += 1;
  abortAllCommands();
});

watch(
  () => t.value.batchCommandPage.loadDevicesFailed,
  (_value, _oldValue, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });

    const loadSelectedDevices = async () => {
      loadingDevices.value = true;
      loadError.value = null;
      try {
        const raw = sessionStorage.getItem("push_device_ids");
        const idsRaw = raw ? (JSON.parse(raw) as unknown) : [];
        const ids = Array.isArray(idsRaw)
          ? idsRaw.map((v) => String(v || "").trim()).filter(Boolean)
          : [];

        if (!ids.length) {
          if (!cancelled) devices.value = [];
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
          errorMessage: t.value.batchCommandPage.loadDevicesFailed,
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

        if (!cancelled) {
          devices.value = ordered;
        }
      } catch (error) {
        if (!cancelled) {
          loadError.value = formatApiError(error, t.value.batchCommandPage.loadDevicesFailed);
          devices.value = [];
        }
      } finally {
        if (!cancelled) {
          loadingDevices.value = false;
        }
      }
    };

    void loadSelectedDevices();
  },
  { immediate: true },
);

const onlineCount = computed(() => devices.value.filter((d) => d.status === "online").length);
const offlineCount = computed(() => devices.value.filter((d) => d.status === "offline").length);
const busyCount = computed(() => devices.value.filter((d) => d.status === "busy").length);
const operableTargets = computed(() => devices.value.filter((d) => d.rawState === "online"));

const canExecute = computed(
  () => script.value.trim().length > 0 && operableTargets.value.length > 0 && !executing.value && !loadingDevices.value,
);

const executeForDevices = async (targets: TargetDevice[], sourceCommand: string) => {
  const cleanCommand = sourceCommand.trim();
  if (!cleanCommand || !targets.length) return;

  const sessionId = sessionRef.value + 1;
  sessionRef.value = sessionId;
  abortAllCommands();

  actionError.value = null;
  actionMessage.value = null;
  executing.value = true;

  const initialState: Record<string, DeviceCommandState> = {};
  for (const device of targets) {
    initialState[device.id] = {
      status: "pending",
      output: "",
      error: "",
      exitCode: undefined,
      expanded: false,
    };
  }
  commandState.value = initialState;

  const limit = Math.max(1, Math.min(targets.length || 1, Math.floor(concurrency.value) || 1));
  let cursor = 0;
  let failed = 0;
  let success = 0;

  const worker = async () => {
    while (cursor < targets.length) {
      const index = cursor;
      cursor += 1;
      const device = targets[index];
      if (!device || sessionId !== sessionRef.value) return;

      setDeviceCommandState(device.id, (current) => ({
        ...current,
        status: "running",
        error: "",
      }));

      try {
        const result = await runShellCommand(
          device.id,
          cleanCommand,
          Number(timeoutVal.value) || 10,
          rootMode.value,
          sessionId,
          commandXhrsRef.value,
        );
        if (sessionId !== sessionRef.value) return;

        const done = Number(result.exitCode) === 0;
        if (done) success += 1;
        else failed += 1;

        setDeviceCommandState(device.id, (current) => ({
          ...current,
          status: done ? "success" : "failed",
          exitCode: Number(result.exitCode),
          output: String(result.output || ""),
          error: String(result.error || ""),
        }));
      } catch (error) {
        if (sessionId !== sessionRef.value) return;
        failed += 1;
        setDeviceCommandState(device.id, (current) => ({
          ...current,
          status: "failed",
          output: "",
          error: formatApiError(error, t.value.batchCommandPage.executeFailed),
          exitCode: undefined,
        }));
      }
    }
  };

  await Promise.all(Array.from({ length: limit }, async () => worker()));
  if (sessionId !== sessionRef.value) return;

  if (failed > 0) {
    actionError.value = interpolate(t.value.batchCommandPage.summaryFailed, { ok: success, failed });
  } else {
    actionMessage.value = interpolate(t.value.batchCommandPage.summarySuccess, { n: success });
  }
  executing.value = false;
};

const handleExecute = async () => {
  if (!script.value.trim()) {
    actionError.value = t.value.batchCommandPage.inputCommandFirst;
    return;
  }
  if (!operableTargets.value.length) {
    actionError.value = t.value.batchCommandPage.noOnlineDevices;
    return;
  }
  await executeForDevices(operableTargets.value, script.value);
};

const retryDevice = async (deviceId: string) => {
  if (executing.value) return;
  const target = operableTargets.value.find((item) => item.id === deviceId);
  if (!target) return;
  if (!script.value.trim()) {
    actionError.value = t.value.batchCommandPage.inputCommandFirst;
    return;
  }
  await executeForDevices([target], script.value);
  actionMessage.value = interpolate(t.value.batchCommandPage.retrySuccess, { id: deviceId });
};

const onRetry = (deviceId: string) => {
  void retryDevice(deviceId);
};

const toggleExpand = (deviceId: string) => {
  setDeviceCommandState(deviceId, (current) => ({
    ...current,
    expanded: !current.expanded,
  }));
};

const onRowKeyDown = (e: KeyboardEvent, deviceId: string) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    toggleExpand(deviceId);
  }
};

const statusBadge = (status: DeviceStatus) => {
  const map: Record<DeviceStatus, { label: string; color: string; bg: string }> = {
    online: {
      label: t.value.batchCommandPage.statusOnline,
      color: "text-green-600",
      bg: "bg-green-100 dark:bg-green-900/40",
    },
    offline: {
      label: t.value.batchCommandPage.statusOffline,
      color: "text-gray-600",
      bg: "bg-gray-100 dark:bg-gray-800/40",
    },
    busy: {
      label: t.value.batchCommandPage.statusBusy,
      color: "text-yellow-600",
      bg: "bg-yellow-100 dark:bg-yellow-900/40",
    },
  };
  return map[status];
};

const deviceRows = computed(() =>
  devices.value.map((device) => {
    const task = commandState.value[device.id];
    const success = task?.status === "success";
    const failed = task?.status === "failed";
    const runningState = task?.status === "pending" || task?.status === "running";
    const expanded = Boolean(task?.expanded);
    const outputText = String(task?.output || "").trim();
    const errorText = String(task?.error || "").trim();
    const hasOutput = outputText.length > 0;
    const hasError = errorText.length > 0;
    return { device, success, failed, runningState, expanded, outputText, errorText, hasOutput, hasError };
  }),
);

const lineCount = computed(() => Math.max(script.value.split("\n").length, 1));

const handleEditorScroll = () => {
  if (textareaRef.value && lineNumberRef.value) {
    lineNumberRef.value.scrollTop = textareaRef.value.scrollTop;
  }
};

const handleEditorKeyDown = (e: KeyboardEvent) => {
  if (e.key === "Tab") {
    e.preventDefault();
    const textarea = e.currentTarget as HTMLTextAreaElement;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const newValue = script.value.substring(0, start) + "  " + script.value.substring(end);
    script.value = newValue;
    requestAnimationFrame(() => {
      textarea.selectionStart = textarea.selectionEnd = start + 2;
    });
  }
};

const onScriptInput = (e: Event) => {
  script.value = (e.target as HTMLTextAreaElement).value;
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
            <p class="text-base font-semibold leading-tight">{{ t.batchCommandPage.title }}</p>
          </div>
        </div>

        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2">
            <Clock class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.batchCommandPage.timeout }}</span>
            <Input
              :model-value="timeoutVal"
              @update:model-value="timeoutVal = Math.max(1, Number($event) || 1)"
              type="number"
              class="h-7 w-20 font-mono text-xs"
              :disabled="executing"
            />
            <span class="text-xs text-muted-foreground">{{ t.batchCommandPage.timeoutUnit }}</span>
          </div>
          <Separator orientation="vertical" class="h-5" />
          <div class="flex items-center gap-2">
            <Zap class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="text-xs text-muted-foreground">{{ t.batchCommandPage.concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.max(1, concurrency - 1)"
              :disabled="concurrency <= 1 || executing"
            >
              <Minus class="h-3 w-3" />
            </Button>
            <span class="w-5 text-center text-xs">{{ concurrency }}</span>
            <Button
              variant="ghost"
              size="icon"
              class="h-6 w-6"
              @click="concurrency = Math.min(50, concurrency + 1)"
              :disabled="concurrency >= 50 || executing"
            >
              <Plus class="h-3 w-3" />
            </Button>
          </div>
        </div>
      </header>

      <main class="flex min-h-0 flex-1 gap-2 overflow-hidden p-3">
        <aside
          class="flex min-h-0 w-96 min-w-96 max-w-96 shrink-0 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm"
        >
          <div class="flex items-center justify-between border-b border-gray-100 px-6 py-4">
            <div>
              <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {{ t.batchCommandPage.targetDevices }}
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
          <div class="min-h-0 w-full min-w-0 max-w-full flex-1 overflow-y-auto overflow-x-hidden">
            <div class="w-full min-w-0 max-w-full overflow-x-hidden">
              <div
                class="grid grid-cols-[1fr_auto] border-b border-border px-6 py-2 text-xs font-semibold text-muted-foreground"
              >
                <div>{{ t.batchCommandPage.deviceId }}</div>
                <div class="text-right" />
              </div>
              <div
                v-for="row in deviceRows"
                :key="row.device.id"
                class="overflow-hidden border-b border-border/60 px-6 py-2.5 hover:bg-muted/50"
              >
                <div
                  role="button"
                  tabindex="0"
                  class="flex w-full min-w-0 cursor-pointer items-start justify-between gap-4 text-left"
                  @click="toggleExpand(row.device.id)"
                  @keydown="onRowKeyDown($event, row.device.id)"
                >
                  <div class="flex min-w-0 items-start gap-3">
                    <div class="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center">
                      <button
                        v-if="row.failed"
                        class="inline-flex h-4 w-4 items-center justify-center text-blue-600 disabled:opacity-50"
                        :disabled="executing"
                        @click="onRetry(row.device.id)"
                        :aria-label="t.batchCommandPage.retry"
                        :title="t.batchCommandPage.retry"
                      >
                        <RotateCw class="h-3.5 w-3.5" />
                      </button>
                      <CheckCircle2 v-else-if="row.success" class="h-4 w-4 animate-pulse text-emerald-500" />
                      <RotateCw v-else-if="row.runningState" class="h-3.5 w-3.5 animate-spin text-blue-500" />
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
                      <p class="text-xs text-muted-foreground">{{ row.device.brand }} {{ row.device.model }}</p>
                    </div>
                  </div>
                  <div class="shrink-0">
                    <div class="flex items-center gap-2">
                      <Badge
                        :class="cn('font-medium', statusBadge(row.device.status).bg, statusBadge(row.device.status).color)"
                        variant="outline"
                      >
                        {{ statusBadge(row.device.status).label }}
                      </Badge>
                      <ChevronDown
                        :class="
                          cn('h-3.5 w-3.5 text-muted-foreground transition-transform', row.expanded && 'rotate-180')
                        "
                      />
                    </div>
                  </div>
                </div>
                <div v-if="row.expanded" class="mt-2 w-full min-w-0 space-y-1 overflow-x-hidden">
                  <div v-if="row.hasOutput || !row.hasError" class="min-w-0 space-y-1">
                    <p class="text-[11px] text-muted-foreground">{{ t.batchCommandPage.output }}</p>
                    <pre
                      class="max-h-28 w-full min-w-0 max-w-full overflow-x-auto overflow-y-auto rounded border border-border bg-muted/40 p-2 text-[11px] leading-4 text-foreground whitespace-pre"
                    >{{ row.hasOutput ? row.outputText : t.batchCommandPage.emptyOutput }}</pre>
                  </div>
                  <div v-if="row.hasError" class="min-w-0 space-y-1">
                    <p class="text-[11px] text-destructive">{{ t.batchCommandPage.error }}</p>
                    <pre
                      class="max-h-28 w-full min-w-0 max-w-full overflow-x-auto overflow-y-auto rounded border border-destructive/40 bg-destructive/5 p-2 text-[11px] leading-4 text-destructive whitespace-pre"
                    >{{ row.errorText }}</pre>
                  </div>
                  <div v-if="!row.hasOutput && !row.hasError && row.runningState" class="text-[11px] text-muted-foreground">
                    {{ t.batchCommandPage.waitingOutput }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </aside>

        <div class="flex min-w-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white shadow-sm">
          <div class="mt-0 flex shrink-0 items-center justify-between border-b border-gray-100 bg-white px-4 py-1">
            <div class="flex items-center gap-3">
              <div class="flex items-center gap-1.5">
                <div class="h-3 w-3 rounded-full bg-red-500" />
                <div class="h-3 w-3 rounded-full bg-yellow-500" />
                <div class="h-3 w-3 rounded-full bg-green-500" />
              </div>
              <span class="text-xs font-medium text-foreground">script.sh</span>
            </div>
            <button
              @click="!executing && (rootMode = !rootMode)"
              :class="
                cn(
                  'flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-all',
                  rootMode
                    ? 'border-red-500/30 bg-red-500/15 text-red-600 dark:text-red-400'
                    : 'border-green-500/30 bg-green-500/15 text-green-600 dark:text-green-400 hover:bg-green-500/25',
                  executing && 'cursor-not-allowed opacity-70',
                )
              "
            >
              <ShieldCheck class="h-3.5 w-3.5" />
              {{ rootMode ? t.batchCommandPage.modePrivileged : t.batchCommandPage.modeNormal }}
            </button>
          </div>

          <div class="min-h-0 flex-1 overflow-hidden border border-t-0 border-gray-100 bg-[#1e1e2e]">
            <div class="flex h-full overflow-hidden bg-[#1e1e2e]">
              <div
                ref="lineNumberRef"
                class="shrink-0 select-none overflow-hidden border-r border-[#313244] bg-[#181825] py-3 pl-4 pr-3"
                :style="editorMonospaceStyle"
              >
                <div v-for="i in lineCount" :key="i" class="text-right text-xs leading-5 text-[#585b70]">
                  {{ i }}
                </div>
              </div>

              <textarea
                ref="textareaRef"
                :value="script"
                @input="onScriptInput"
                @scroll="handleEditorScroll"
                @keydown="handleEditorKeyDown"
                :placeholder="t.batchCommandPage.scriptPlaceholder"
                :disabled="executing"
                spellcheck="false"
                autocomplete="off"
                autocapitalize="off"
                :class="
                  cn(
                    'flex-1 resize-none bg-transparent px-4 py-3 outline-none',
                    'text-xs leading-5 text-[#cdd6f4] caret-[#89b4fa]',
                    'placeholder:text-[#585b70]',
                    'selection:bg-[#45475a]',
                    executing && 'cursor-not-allowed opacity-70',
                  )
                "
                :style="editorTextareaStyle"
              />
            </div>
          </div>

          <div class="mt-0 flex shrink-0 items-center justify-between border-t border-gray-100 bg-white px-4 py-2">
            <div class="flex min-w-0 items-center gap-3">
              <div class="flex items-center gap-4">
                <span class="text-xs text-muted-foreground">
                  {{ script.split("\n").length }} {{ t.batchCommandPage.lines }}
                </span>
                <span
                  v-if="rootMode"
                  class="flex items-center gap-1 text-xs font-medium text-red-600 dark:text-red-400"
                >
                  <ShieldCheck class="h-3 w-3" />
                  {{ t.batchCommandPage.modeRoot }}
                </span>
                <span
                  v-else
                  class="flex items-center gap-1 text-xs font-medium text-green-600 dark:text-green-400"
                >
                  <Terminal class="h-3 w-3" />
                  {{ t.batchCommandPage.modeShell }}
                </span>
              </div>
              <p v-if="loadingDevices" class="shrink-0 text-[11px] text-muted-foreground">
                {{ t.batchCommandPage.loadingDevices }}
              </p>
              <div class="min-h-0 shrink-0">
                <FeedbackTip v-if="loadError" :message="loadError" variant="error" compact />
                <FeedbackTip
                  v-else-if="actionError"
                  :message="actionError"
                  variant="error"
                  compact
                  class-name="max-w-[620px]"
                  truncate
                />
                <FeedbackTip v-else-if="actionMessage" :message="actionMessage" variant="success" compact />
              </div>
            </div>
            <div class="flex items-center gap-2">
              <Button variant="outline" size="sm" class="h-7" @click="router.back()">
                {{ t.batchCommandPage.cancel }}
              </Button>
              <Button :disabled="!canExecute" @click="void handleExecute()" size="sm" class="h-7 gap-1.5">
                <RotateCw v-if="executing" class="h-3 w-3 animate-spin" />
                <Play v-else class="h-3 w-3" />
                {{ executing ? t.batchCommandPage.executing : t.batchCommandPage.startExecute }}
              </Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>
</template>
