<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { DiffEditor, MonacoEditor } from "@/components/ui/monaco";
import { useTheme } from "@/lib/theme";
import {
  ArrowLeft,
  CalendarClock,
  Bug,
  ChevronLeft,
  ChevronsUpDown,
  FileCode2,
  History,
  Inbox,
  Loader2,
  Menu,
  MonitorSmartphone,
  Play,
  Plus,
  Search,
  Share2,
  ShieldAlert,
  Smartphone,
  Square,
  Tag,
  Trash2,
  Upload,
  User,
  UserRound,
  X,
} from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { FeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { apiRequest, formatApiError } from "@/lib/api";
import { leaveThroughUnsavedGuard, matchHashPath, useHashNavigationGuard, useHashPathname, useHashRouter, useHashSearchParams } from "@/lib/hash-router";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type OnMount = (editor: any, monaco: any) => void;

type ScriptVersion = {
  id: number;
  version: string;
  change_log?: string;
  create_time?: number;
};

type ScriptDetail = {
  id: number;
  name: string;
  description?: string;
  type: number;
  entry?: { params?: unknown } | null;
  params?: unknown;
  create_time?: number;
  owner?: { id?: number; name?: string; username?: string };
  versions: ScriptVersion[];
};

type ScriptUser = {
  id: number;
  name?: string;
  username?: string;
  contact?: string;
};

type IdleDevice = {
  key: string;
  domain: string;
  devId: string;
  brand: string;
  model: string;
  deviceName: string;
  apiAvailable: boolean;
};

type ModelOption = {
  id: string;
  label: string;
  provider?: string;
  apiBase?: string;
  apiKey?: string;
  modelName?: string;
  visionMode?: boolean;
  visionScale?: number;
  temperature?: number;
  maxTokens?: number;
  contextWindow?: number;
  stepDelay?: number;
};

type DiffState = {
  enabled: boolean;
  originalVersionId: number | null;
  modifiedVersionId: number | null;
  originalCode: string;
  modifiedCode: string;
};

type ScriptDraft = {
  versionId: number | null;
  code: string;
  savedAt: number;
};

type DebugStackFrame = {
  filename?: string;
  lineno?: number;
  function?: string;
};

type DebugLocal = {
  name?: string;
  type?: string;
};

type DebugCapabilities = {
  cmd: string[];
  bp: string[];
  eval: boolean;
};

type ProjectionFrame = {
  width: number;
  height: number;
  yuv: Uint8Array;
};

const VERSION_LEN_MAX = 16;

const PLACEHOLDER_TEMPLATE = `#!encoding=utf8
from celery import Task
from celery.worker.request import Request

from typing import Annotated
from lamda.executor import BaseTaskExecutor


class FireRPATaskBaseRequest(Request):
    """
    By overriding the callbacks in this class, we ensure comprehensive monitoring of the 
    task execution lifecycle. 

    Unlike hooks in the BaseTask or Executor—which may be terminated abruptly if the 
    process crashes or commits suicide — this class acts as an external observer. It remains 
    operational even when the task process is destroyed, ensuring that failure signals 
    are correctly captured and processed.
    see: https://docs.celeryq.dev/en/stable/reference/celery.worker.request.html#celery-worker-requests
    """
    def on_accepted(self, pid, time_accepted):
        super().on_accepted(pid, time_accepted)
    def on_timeout(self, soft, timeout):
        super().on_timeout(soft, timeout)
    def on_failure(self, exc_info, send_failed_event=True, return_ok=False):
        super().on_failure(exc_info, send_failed_event=send_failed_event, return_ok=return_ok)
    def on_success(self, failed__retval__runtime, **kwargs):
        super().on_success(failed__retval__runtime, **kwargs)
    def on_retry(self, exc_info):
        super().on_retry(exc_info)


class FireRPABaseTaskExecutor(Task):
    Request = FireRPATaskBaseRequest
    """
    Use this class for standard lifecycle management, such as routine initialization, 
    resource cleanup, and task-level monitoring. While this class manages the standard 
    flow, critical system-level failures (where the process dies) should be handled 
    by the FireRPATaskBaseRequest callbacks.

    Warning: Modifying this class name will result in task execution failure. 
    see: https://docs.celeryq.dev/en/main/userguide/tasks.html
    """
    def before_start(self, task_id, args, kwargs):
        print (f"{task_id} starting with args {args}")
    def on_success(self, retval, task_id, args, kwargs):
        print (f"{task_id} succeeded with result: {retval}")
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        print (f"{task_id} failed: {exc}")
    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        print (f"{task_id} finished with status: {status}")


class FireRPATaskExecutor(BaseTaskExecutor):
    def initialize(self{arguments}):
        self.logger.info("prepare")
    def execute(self):
        self.logger.info("execute")
        self.device.screenshot(30).save("/sdcard/screenshot.png")
        self.send_message(dict(type="data", name="source", data={"name": "value"}))
        self.send_message(dict(type="file", name="screenshot", data={"path": "/sdcard/screenshot.png", "type": "image/png"}))
        self.send_message(dict(type="log", name="hello", data={"message": "Hello World"}))
        return dict(message="Hello World")
    def finalize(self):
        self.logger.info("cleanup")
`;

const PLACEHOLDER_TEMPLATE_PROMPT = `#!encoding=utf8
from celery import Task
from celery.worker.request import Request

from typing import Annotated
from lamda.executor import BaseTaskExecutor
from lamda.ai import tool, AnyLLMUiautomatorAgent as _AnyLLMUiautomatorAgent


class FireRPATaskBaseRequest(Request):
    """
    By overriding the callbacks in this class, we ensure comprehensive monitoring of the
    task execution lifecycle.

    Unlike hooks in the BaseTask or Executor—which may be terminated abruptly if the
    process crashes or commits suicide—this class acts as an external observer. It remains
    operational even when the task process is destroyed, ensuring that failure signals
    are correctly captured and processed.
    see: https://docs.celeryq.dev/en/stable/reference/celery.worker.request.html#celery-worker-requests
    """
    def on_accepted(self, pid, time_accepted):
        super().on_accepted(pid, time_accepted)
    def on_timeout(self, soft, timeout):
        super().on_timeout(soft, timeout)
    def on_failure(self, exc_info, send_failed_event=True, return_ok=False):
        super().on_failure(exc_info, send_failed_event=send_failed_event, return_ok=return_ok)
    def on_success(self, failed__retval__runtime, **kwargs):
        super().on_success(failed__retval__runtime, **kwargs)
    def on_retry(self, exc_info):
        super().on_retry(exc_info)


class FireRPABaseTaskExecutor(Task):
    Request = FireRPATaskBaseRequest
    """
    Use this class for standard lifecycle management, such as routine initialization,
    resource cleanup, and task-level monitoring. While this class manages the standard
    flow, critical system-level failures (where the process dies) should be handled
    by the FireRPATaskBaseRequest callbacks.

    Warning: Modifying this class name will result in task execution failure.
    see: https://docs.celeryq.dev/en/main/userguide/tasks.html
    """
    def before_start(self, task_id, args, kwargs):
        print (f"{task_id} starting with args {args}")
    def on_success(self, retval, task_id, args, kwargs):
        print (f"{task_id} succeeded with result: {retval}")
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        print (f"{task_id} failed: {exc}")
    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        print (f"{task_id} finished with status: {status}")


class AnyLLMUiautomatorAgent(_AnyLLMUiautomatorAgent):
    """ You can add your own AI tool in this class."""
    @tool(description="Echo a hello message.")
    def sayHello(self, name: str):
        return f"Hello, {name}"


class FireRPATaskExecutor(BaseTaskExecutor):
    def initialize(self{arguments}):
        self.agent.set_device(self.device)
        self.agent.set_tool_callback(self.on_tool_call)
        self.agent.set_message_callback(self.on_assistant_message)
        self.agent.set_usage_callback(self.on_api_usage)
    def on_api_usage(self, usage):
        self.send_message(dict(type="ai/usage", data=dict(total_tokens=usage.get("total_tokens", 0))))
    def on_tool_call(self, name, arguments):
        self.send_message(dict(type="ai/tool", data=dict(name=name, arguments=arguments)))
    def on_assistant_message(self, role, message):
        self.send_message(dict(type="ai/message", data=dict(role=role, content=message["content"])))
    def execute(self):
        self.logger.info("execute")
        self.device.screenshot(30).save("/sdcard/screenshot.png")
        self.send_message(dict(type="data", name="source", data={"name": "value"}))
        self.send_message(dict(type="file", name="screenshot", data={"path": "/sdcard/screenshot.png", "type": "image/png"}))
        self.send_message(dict(type="log", name="hello", data={"message": "Hello World"}))
        reason = self.agent.instruct("""
Help me open System Settings (com.android.settings), then open Network settings, and finally open Network tethering.
        """)
        return dict(message=f"AI completed with {reason}")
    def finalize(self):
        self.logger.info("cleanup")
`;

type ParamItem = { name: string; type?: string; description?: string };

const paramTypeMapping: Record<string, string> = {
  string: "str",
  object: "dict",
  integer: "int",
  float: "float",
  boolean: "bool",
  array: "list",
  "number(float)": "float",
};

function parseParams(raw: unknown): ParamItem[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw as ParamItem[];
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as ParamItem[]) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function normalizeParamType(raw?: string): "string" | "integer" | "float" | "boolean" | "list" | "object" {
  const t = String(raw || "").toLowerCase();
  if (["int", "integer"].includes(t)) return "integer";
  if (["float", "number", "number(float)"].includes(t)) return "float";
  if (["bool", "boolean"].includes(t)) return "boolean";
  if (["list", "array"].includes(t)) return "list";
  if (["object", "dict"].includes(t)) return "object";
  return "string";
}

function toPythonLiteral(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "None";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => toPythonLiteral(item)).join(", ")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}: ${toPythonLiteral(v)}`).join(", ")}}`;
  }
  return "None";
}

function toBooleanLoose(value: unknown, fallback = false) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  const t = String(value ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(t)) return true;
  if (["0", "false", "no", "off", ""].includes(t)) return false;
  return fallback;
}

function toNumberLoose(value: unknown, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function buildTemplateWithParams(template: string, rawParams: unknown): string {
  const params = parseParams(rawParams).filter((p) => (p?.name || "").trim());
  if (!params.length) return template.replace("{arguments}", "");
  const args = params
    .map((p) => {
      const name = (p.name || "").trim();
      const pyType = paramTypeMapping[(p.type || "").toLowerCase()] || "str";
      const desc = (p.description || "").trim().replace(/"/g, '\\"');
      return desc
        ? `, ${name}: Annotated[${pyType}, "${desc}"] = None`
        : `, ${name}: ${pyType}`;
    })
    .join("");
  return template.replace("{arguments}", args);
}

function buildScriptTemplate(scriptType: number, rawParams: unknown): string {
  if (scriptType === 1) return buildTemplateWithParams(PLACEHOLDER_TEMPLATE_PROMPT, rawParams);
  return buildTemplateWithParams(PLACEHOLDER_TEMPLATE, rawParams);
}

function tsText(ts?: number) {
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

function ownerText(detail?: ScriptDetail | null) {
  if (!detail?.owner) return "-";
  return detail.owner.name || detail.owner.username || "-";
}

function normalizeVersions(raw: any): ScriptVersion[] {
  const list = Array.isArray(raw) ? raw : [];
  return list
    .map((v: any) => ({
      id: Number(v?.id ?? 0),
      version: String(v?.version || "-"),
      change_log: String(v?.change_log || ""),
      create_time: Number(v?.create_time ?? 0),
    }))
    .filter((v: ScriptVersion) => v.id > 0)
    .sort((a, b) => Number(b.create_time || 0) - Number(a.create_time || 0));
}

function nowHms() {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

const DEBUG_MIN_SOURCE_BLOCK_HEIGHT = 84;
const DEBUG_MIN_OUTPUT_HEIGHT = 52;
const DEBUG_CONSOLE_ROW_HEIGHT = 34;
const PROJECTION_MIN_WIDTH = 220;
const PROJECTION_MIN_HEIGHT = 240;
const PROJECTION_CHROME_HEIGHT = 64;
const PROJECTION_PORTRAIT_WIDTH_RATIO = 0.15;
const PROJECTION_LANDSCAPE_WIDTH_RATIO = 0.30;
const PROJECTION_DEFAULT_ASPECT_WIDTH = 16;
const PROJECTION_DEFAULT_ASPECT_HEIGHT = 9;

function clampNum(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

const router = useHashRouter();
const { resolvedTheme } = useTheme();
const { t } = useTranslation();
const hashPathname = useHashPathname();
const hashSearchParams = useHashSearchParams();
const hashId = computed(() => matchHashPath(hashPathname.value, /^\/scripts\/([^/]+)$/));
const scriptId = Number(hashId.value || 0);
const routeVersionId = computed(() => {
  const raw = (hashSearchParams.value.get("versionId") || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
});

const loading = ref(false);
const tip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);

const detail = ref<ScriptDetail | null>(null);
const selfId = ref(0);
const versions = ref<ScriptVersion[]>([]);
const selectedVersionId = ref<number | null>(null);
const editorCode = ref("");
const baseEditorCode = ref("");
const diffState = ref<DiffState>({
  enabled: false,
  originalVersionId: null,
  modifiedVersionId: null,
  originalCode: "",
  modifiedCode: "",
});

const publishOpen = ref(false);
const publishing = ref(false);
const publishVersion = ref("");
const publishChangeLog = ref("");
const debugDeviceOpen = ref(false);
const debugDeviceLoading = ref(false);
const debugDeviceKeyword = ref("");
const debugDeviceId = ref("");
const idleDevices = ref<IdleDevice[]>([]);
const debugDialogOpen = ref(false);
const debugModelsLoading = ref(false);
const debugModels = ref<ModelOption[]>([]);
const debugModelId = ref("");
const debugParamInputs = ref<Record<string, string>>({});
const debugMode = ref(false);
const debugWsStatus = ref<"disconnected" | "connecting" | "connected" | "error">("disconnected");
const debugSourceLines = ref<string[]>([]);
const debugStoppedLine = ref<number | null>(null);
const debugBreakpoints = ref<number[]>([]);
const debugLocalsRaw = ref<DebugLocal[]>([]);
const debugStackRaw = ref<DebugStackFrame[]>([]);
const debugOutput = ref("");
const debugConsoleCode = ref("");
const debugExecState = ref<"idle" | "starting" | "running" | "paused" | "terminated" | "error">("idle");
const debugCapabilities = ref<DebugCapabilities>({
  cmd: ["continue", "next", "out", "quit", "step"],
  bp: ["toggle"],
  eval: true,
});

const sharedUsers = ref<ScriptUser[]>([]);
const usersOpen = ref(false);
const usersLoading = ref(false);
const usersSearch = ref("");
const candidateUsers = ref<ScriptUser[]>([]);
const allocBusy = ref(false);
const draftApplying = ref(false);
const unsavedDialogOpen = ref(false);
let pendingAction: null | (() => void | Promise<void>) = null;
let unsavedDialogOpenCurrent = false;
let debugDeviceReq = 0;
let debugModelReq = 0;
let debugWs: WebSocket | null = null;
let debugReconnectTimer: number | null = null;
let debugAutoReconnect = false;
let debugRunLock = false;
let debugRunCode = "";
const debugOutputScrollRef = ref<HTMLDivElement | null>(null);
let debugOutputStickToBottom = true;
let debugSourceEditor: any = null;
let debugSourceMonaco: any = null;
let scriptEditor: any = null;
let diffEditor: any = null;
let debugSourceDecorations: string[] = [];
const debugLeftSplitRef = ref<HTMLDivElement | null>(null);
const debugSourceBlockHeight = ref<number | null>(null);
const debugRunLocked = ref(false);
const debugOutputFocused = ref(false);
const debugOutputResizeHot = ref(false);
const debugProjectionOpen = ref(false);
const debugProjectionStatus = ref<"idle" | "connecting" | "connected" | "error">("idle");
const debugProjectionRect = ref({ x: 16, y: 16, width: PROJECTION_MIN_WIDTH, height: PROJECTION_MIN_HEIGHT });
const debugProjectionRotation = ref(0);
const debugProjectionTouchReady = ref(false);
const debugProjectionFrameSize = ref({ width: 0, height: 0 });
const debugProjectionCanvasViewSize = ref({ width: 0, height: 0 });
const debugProjectionHostRef = ref<HTMLDivElement | null>(null);
const debugProjectionCanvasRef = ref<HTMLCanvasElement | null>(null);
const debugProjectionViewportRef = ref<HTMLDivElement | null>(null);
let debugProjectionWs: WebSocket | null = null;
let debugProjectionTouchWs: WebSocket | null = null;
let debugProjectionCommandWs: WebSocket | null = null;
let debugProjectionWorker: Worker | null = null;
let debugProjectionWorkerUrl: string | null = null;
let debugProjectionRotationTimer: number | null = null;
let debugProjectionRotationRestartTimer: number | null = null;
let debugProjectionTouchDown = false;
let debugProjectionTouchSize = { width: 0, height: 0 };
let debugProjectionDomain = "";
let debugProjectionRotationCurrent: number | null = null;
let debugProjectionRotationInit = false;
let debugProjectionRectUserSized = false;
let debugProjectionAutoFitDone = false;

const showTip = (text: string, variant: FeedbackTipVariant = "error") => {
  tip.value = { id: Date.now() + Math.random(), text, variant };
};

const setRunLocked = (locked: boolean) => {
  debugRunLock = locked;
  debugRunLocked.value = locked;
};

const resetDebugConsole = () => {
  debugRunCode = "";
  debugLocalsRaw.value = [];
  debugStackRaw.value = [];
  debugOutput.value = "";
  debugStoppedLine.value = null;
  debugBreakpoints.value = [];
  debugSourceLines.value = editorCode.value ? editorCode.value.split(/\r?\n/) : [];
  debugExecState.value = "idle";
  setRunLocked(false);
};

const appendDebugOutput = (text: string, withNewline = false, stream: "stdout" | "stderr" = "stdout") => {
  const chunk = withNewline ? `${text}\n` : text;
  const base = debugOutput.value || "";
  if (!chunk) return;
  const needsSeparator = base.length > 0 && !base.endsWith("\n") && !chunk.startsWith("\n");
  const rawChunk = chunk.replace(/\r/g, "");
  const hasText = rawChunk.trim().length > 0;
  const hasLeadingTimestamp = /^\s*\d{2}:\d{2}:\d{2}\b/.test(rawChunk);
  const normalizedChunk =
    hasText && !hasLeadingTimestamp ? `${nowHms()} [${stream}] ${rawChunk}` : rawChunk;
  const merged = `${base}${needsSeparator ? "\n" : ""}${normalizedChunk}`;
  const rows = merged.split("\n");
  const normalized: string[] = [];
  for (const row of rows) {
    const isBlank = row.trim() === "";
    if (isBlank) {
      if (normalized.length === 0) continue;
      if (normalized[normalized.length - 1].trim() === "") continue;
    }
    normalized.push(row);
  }
  debugOutput.value = normalized.join("\n");
};

const sendDebugMessage = (payload: Record<string, unknown>) => {
  const ws = debugWs;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    showTip(t.value.scriptsPage.debugWsNotConnected);
    return false;
  }
  ws.send(JSON.stringify(payload));
  return true;
};

const isOwner = computed(() => {
  if (!detail.value?.owner?.id) return false;
  return selfId.value > 0 && Number(detail.value.owner.id) === selfId.value;
});

const latestVersion = computed(() => versions.value[0]?.version || "-");
const lastUpdated = computed(() => (versions.value[0]?.create_time ? tsText(versions.value[0].create_time) : "-"));
const isDirty = computed(() => isOwner.value && !diffState.value.enabled && editorCode.value !== baseEditorCode.value);

watch(unsavedDialogOpen, (v) => {
  unsavedDialogOpenCurrent = v;
}, { immediate: true });

// 浏览器后退可能接连触发 popstate 与 hashchange，
// 任一触发源弹窗后，其余事件必须被去重，否则会连续弹出两次确认框。
let unsavedPromptLock = false;
const promptUnsaved = (action: () => void | Promise<void>) => {
  if (unsavedDialogOpenCurrent || unsavedPromptLock) return;
  unsavedPromptLock = true;
  window.setTimeout(() => {
    unsavedPromptLock = false;
  }, 800);
  pendingAction = action;
  unsavedDialogOpenCurrent = true;
  unsavedDialogOpen.value = true;
};

const { allowNextNavigation, restoreGuard } = useHashNavigationGuard(() => Boolean(isOwner.value && isDirty.value), (next, current) => {
  if (!(isOwner.value && isDirty.value)) return;
  promptUnsaved(() => {
    allowNextNavigation();
    if (next.pathname === current.pathname && next.search === current.search) {
      leaveThroughUnsavedGuard();
      return;
    }
    router.push(`${next.pathname}${next.search}`);
  });
});

const selectedDebugDevice = computed(
  () => idleDevices.value.find((item) => item.key === debugDeviceId.value) || null,
);
const selectedDebugModel = computed(
  () => debugModels.value.find((item) => item.id === debugModelId.value) || null,
);
const debugParams = computed(() => parseParams(detail.value?.entry?.params ?? detail.value?.params).filter((p) => (p.name || "").trim()));
const isHybridScript = computed(() => Number(detail.value?.type ?? 0) === 1);
const debugRunBusy = computed(() => debugExecState.value === "starting" || debugExecState.value === "running");
const debugRunning = computed(() => debugExecState.value === "starting" || debugExecState.value === "running" || debugExecState.value === "paused");
const debugCanControl = computed(() => debugExecState.value === "paused");
const debugCanRun = computed(() => debugWsStatus.value === "connected" && debugExecState.value === "idle" && !debugRunLocked.value);
const debugCanEnd = computed(() => debugRunning.value && debugWsStatus.value === "connected" && debugCapabilities.value.cmd.includes("quit"));
const debugStatusText = computed(() => {
  if (debugExecState.value === "starting") return t.value.scriptsPage.debugStateStarting;
  if (debugExecState.value === "running") return t.value.scriptsPage.debugStateRunning;
  if (debugExecState.value === "paused") return t.value.scriptsPage.debugStatePaused;
  if (debugExecState.value === "terminated") return t.value.scriptsPage.debugStateTerminated;
  if (debugExecState.value === "error") return t.value.scriptsPage.debugStateError;
  return t.value.scriptsPage.debugStateIdle;
});
const debugOutputRows = computed(() => {
  if (!debugOutput.value) return [] as { ts: string; stream: string; msg: string }[];
  return debugOutput.value
    .split("\n")
    .map((line) => line.replace(/\r/g, ""))
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const m = line.match(/^(\d{2}:\d{2}:\d{2})\s+\[(stdout|stderr)\]\s*(.*)$/i);
      if (m) {
        return { ts: m[1], stream: String(m[2] || "stdout").toLowerCase(), msg: m[3] || "" };
      }
      const m2 = line.match(/^(\d{2}:\d{2}:\d{2})\s+(.*)$/);
      if (m2) {
        return { ts: m2[1], stream: "stdout", msg: m2[2] || "" };
      }
      return { ts: "", stream: "stdout", msg: line };
    });
});
const streamTextOf = (stream: string) => (String(stream || "stdout").toLowerCase() === "stderr" ? "stderr" : "stdout");
const scrollDebugOutputToBottom = () => {
  const el = debugOutputScrollRef.value;
  if (!el) return;
  el.scrollTop = el.scrollHeight;
};

const handleDebugOutputScroll = () => {
  const el = debugOutputScrollRef.value;
  if (!el) return;
  const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
  debugOutputStickToBottom = distance <= 20;
};

watch([debugMode, debugOutput, debugOutputFocused, () => debugOutputRows.value.length], () => {
  if (!debugMode.value) return;
  if (!debugOutputFocused.value || debugOutputStickToBottom) {
    scrollDebugOutputToBottom();
    debugOutputStickToBottom = true;
  }
}, { flush: "post" });

const startDebugVerticalResize = (event: MouseEvent) => {
  const container = debugLeftSplitRef.value;
  if (!container) return;
  event.preventDefault();
  const rect = container.getBoundingClientRect();
  const startTop = rect.top;
  const totalHeight = rect.height;
  const onMove = (e: MouseEvent) => {
    const raw = e.clientY - startTop;
    const maxSource = Math.max(
      DEBUG_MIN_SOURCE_BLOCK_HEIGHT,
      totalHeight - DEBUG_CONSOLE_ROW_HEIGHT - DEBUG_MIN_OUTPUT_HEIGHT,
    );
    const next = Math.min(maxSource, Math.max(DEBUG_MIN_SOURCE_BLOCK_HEIGHT, raw));
    debugSourceBlockHeight.value = next;
  };
  const onUp = () => {
    window.removeEventListener("mousemove", onMove);
    window.removeEventListener("mouseup", onUp);
    document.body.style.userSelect = "";
    document.body.style.cursor = "";
  };
  document.body.style.userSelect = "none";
  document.body.style.cursor = "row-resize";
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
};

const isNearOutputTopEdge = (event: MouseEvent) => {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
  const y = event.clientY - rect.top;
  return y >= 0 && y <= 6;
};

const getDebugDeviceServerBase = () => {
  if (typeof window === "undefined") return "";
  const domain = String(selectedDebugDevice.value?.domain || "").trim();
  if (!domain) return "";
  return `${window.location.protocol}//${window.location.host}/d/${encodeURIComponent(domain)}`;
};

const getProjectionScreenSize = () => {
  const touchW = debugProjectionTouchSize.width;
  const touchH = debugProjectionTouchSize.height;
  if (touchW > 0 && touchH > 0) return { width: touchW, height: touchH };
  const frameW = debugProjectionFrameSize.value.width;
  const frameH = debugProjectionFrameSize.value.height;
  if (frameW > 0 && frameH > 0) return { width: frameW, height: frameH };
  return null;
};

const applyDefaultProjectionRect = () => {
  const host = debugProjectionHostRef.value;
  const hostRect = host?.getBoundingClientRect();
  const hostWidth = hostRect?.width || (typeof window !== "undefined" ? window.innerWidth : 1280);
  const hostHeight = hostRect?.height || (typeof window !== "undefined" ? window.innerHeight : 720);

  let windowWidth = Math.round(hostWidth * PROJECTION_PORTRAIT_WIDTH_RATIO);
  windowWidth = clampNum(windowWidth, PROJECTION_MIN_WIDTH, hostWidth);

  let windowHeight = Math.round(windowWidth * (PROJECTION_DEFAULT_ASPECT_HEIGHT / PROJECTION_DEFAULT_ASPECT_WIDTH));
  windowHeight = clampNum(windowHeight, PROJECTION_MIN_HEIGHT, hostHeight);

  if (windowHeight >= hostHeight) {
    windowHeight = hostHeight;
    windowWidth = clampNum(
      Math.round(windowHeight * (PROJECTION_DEFAULT_ASPECT_WIDTH / PROJECTION_DEFAULT_ASPECT_HEIGHT)),
      PROJECTION_MIN_WIDTH,
      hostWidth,
    );
  }

  const x = clampNum(16, 0, Math.max(0, hostWidth - windowWidth));
  const y = clampNum(16, 0, Math.max(0, hostHeight - windowHeight));
  debugProjectionRect.value = { x, y, width: windowWidth, height: windowHeight };
};

const tryAutoFitProjectionRect = () => {
  if (!debugProjectionOpen.value || debugProjectionRectUserSized || debugProjectionAutoFitDone) return;
  const screen = getProjectionScreenSize();
  if (!screen) return;
  const host = debugProjectionHostRef.value;
  if (!host) return;
  const hostRect = host.getBoundingClientRect();
  if (!hostRect.width || !hostRect.height) return;

  const { width: screenW, height: screenH } = screen;
  const isPortrait = screenH > screenW;
  const widthRatio = isPortrait ? PROJECTION_PORTRAIT_WIDTH_RATIO : PROJECTION_LANDSCAPE_WIDTH_RATIO;

  const rot = ((debugProjectionRotation.value % 4) + 4) % 4;
  const displayW = rot === 1 || rot === 3 ? screenH : screenW;
  const displayH = rot === 1 || rot === 3 ? screenW : screenH;
  if (!displayW || !displayH) return;

  let windowWidth = Math.round(hostRect.width * widthRatio);
  windowWidth = clampNum(windowWidth, PROJECTION_MIN_WIDTH, hostRect.width);

  let viewportHeight = Math.round(windowWidth * (displayH / displayW));
  viewportHeight = Math.max(viewportHeight, PROJECTION_MIN_HEIGHT - PROJECTION_CHROME_HEIGHT);

  let windowHeight = viewportHeight + PROJECTION_CHROME_HEIGHT;
  if (windowHeight > hostRect.height) {
    windowHeight = Math.max(PROJECTION_MIN_HEIGHT, hostRect.height);
    viewportHeight = Math.max(1, windowHeight - PROJECTION_CHROME_HEIGHT);
    windowWidth = clampNum(Math.round(viewportHeight * (displayW / displayH)), PROJECTION_MIN_WIDTH, hostRect.width);
    windowHeight = Math.min(hostRect.height, viewportHeight + PROJECTION_CHROME_HEIGHT);
  }

  const x = clampNum(16, 0, Math.max(0, hostRect.width - windowWidth));
  const y = clampNum(16, 0, Math.max(0, hostRect.height - windowHeight));
  debugProjectionRect.value = { x, y, width: windowWidth, height: windowHeight };
  debugProjectionAutoFitDone = true;
};

const drawProjectionFrame = (frame: ProjectionFrame) => {
  const canvas = debugProjectionCanvasRef.value;
  if (!canvas) return;
  const width = Number(frame.width || 0);
  const height = Number(frame.height || 0);
  if (!width || !height) return;
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
    debugProjectionFrameSize.value = { width, height };
    tryAutoFitProjectionRect();
  }
  const ctx = canvas.getContext("2d", { alpha: false });
  if (!ctx) return;
  const yuv = frame.yuv;
  const image = ctx.createImageData(width, height);
  const out = image.data;
  const yLen = width * height;
  const uvWidth = width >> 1;
  const uvHeight = height >> 1;
  const uOffset = yLen;
  const vOffset = yLen + uvWidth * uvHeight;
  let p = 0;
  for (let j = 0; j < height; j += 1) {
    const uvRow = (j >> 1) * uvWidth;
    for (let i = 0; i < width; i += 1) {
      const y = yuv[j * width + i] || 0;
      const uvIndex = uvRow + (i >> 1);
      const u = (yuv[uOffset + uvIndex] || 128) - 128;
      const v = (yuv[vOffset + uvIndex] || 128) - 128;
      let r = y + 1.402 * v;
      let g = y - 0.344136 * u - 0.714136 * v;
      let b = y + 1.772 * u;
      if (r < 0) r = 0;
      if (r > 255) r = 255;
      if (g < 0) g = 0;
      if (g > 255) g = 255;
      if (b < 0) b = 0;
      if (b > 255) b = 255;
      out[p++] = r;
      out[p++] = g;
      out[p++] = b;
      out[p++] = 255;
    }
  }
  ctx.putImageData(image, 0, 0);
};

const closeDebugProjection = () => {
  if (debugProjectionRotationTimer != null) {
    window.clearInterval(debugProjectionRotationTimer);
    debugProjectionRotationTimer = null;
  }
  if (debugProjectionRotationRestartTimer != null) {
    window.clearTimeout(debugProjectionRotationRestartTimer);
    debugProjectionRotationRestartTimer = null;
  }
  try {
    if (debugProjectionWs) {
      debugProjectionWs.onopen = null;
      debugProjectionWs.onmessage = null;
      debugProjectionWs.onerror = null;
      debugProjectionWs.onclose = null;
      debugProjectionWs.close();
    }
  } catch {}
  debugProjectionWs = null;
  try {
    if (debugProjectionTouchWs) {
      debugProjectionTouchWs.onopen = null;
      debugProjectionTouchWs.onmessage = null;
      debugProjectionTouchWs.onerror = null;
      debugProjectionTouchWs.onclose = null;
      debugProjectionTouchWs.close();
    }
  } catch {}
  debugProjectionTouchWs = null;
  try {
    if (debugProjectionCommandWs) {
      debugProjectionCommandWs.onopen = null;
      debugProjectionCommandWs.onmessage = null;
      debugProjectionCommandWs.onerror = null;
      debugProjectionCommandWs.onclose = null;
      debugProjectionCommandWs.close();
    }
  } catch {}
  debugProjectionCommandWs = null;
  try {
    if (debugProjectionWorker) {
      debugProjectionWorker.postMessage({ t: "close" });
      debugProjectionWorker.terminate();
    }
  } catch {}
  debugProjectionWorker = null;
  try {
    if (debugProjectionWorkerUrl) URL.revokeObjectURL(debugProjectionWorkerUrl);
  } catch {}
  debugProjectionWorkerUrl = null;
  debugProjectionTouchDown = false;
  debugProjectionTouchSize = { width: 0, height: 0 };
  debugProjectionRotationCurrent = null;
  debugProjectionRotationInit = false;
  debugProjectionRectUserSized = false;
  debugProjectionAutoFitDone = false;
  debugProjectionCanvasViewSize.value = { width: 0, height: 0 };
  debugProjectionTouchReady.value = false;
  debugProjectionStatus.value = "idle";
};

const resolveProjectionTouchPoint = (event: PointerEvent) => {
  const canvas = debugProjectionCanvasRef.value;
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  const realW = debugProjectionTouchSize.width || debugProjectionFrameSize.value.width;
  const realH = debugProjectionTouchSize.height || debugProjectionFrameSize.value.height;
  if (!realW || !realH || !rect.width || !rect.height) return null;
  const px = Number(event.clientX);
  const py = Number(event.clientY);
  const localX = clampNum(px - rect.left, 0, Math.max(rect.width - 1, 0));
  const localY = clampNum(py - rect.top, 0, Math.max(rect.height - 1, 0));
  const x0 = Math.floor(localX * (realW / rect.width));
  const y0 = Math.floor(localY * (realH / rect.height));
  let x = x0;
  let y = y0;
  const rot = ((debugProjectionRotation.value % 4) + 4) % 4;
  if (rot === 1) {
    x = realH - y0;
    y = x0;
  } else if (rot === 2) {
    x = realW - x0;
    y = realH - y0;
  } else if (rot === 3) {
    x = y0;
    y = realW - x0;
  }
  return {
    x: clampNum(Math.round(x), 0, Math.max(realW - 1, 0)),
    y: clampNum(Math.round(y), 0, Math.max(realH - 1, 0)),
  };
};

const sendProjectionTouch = (payload: Record<string, unknown>) => {
  const ws = debugProjectionTouchWs;
  if (!ws || ws.readyState !== WebSocket.OPEN || !debugProjectionTouchReady.value) return false;
  ws.send(JSON.stringify(payload));
  return true;
};

const sendProjectionCommand = (command: string, data: unknown[]) => {
  const ws = debugProjectionCommandWs;
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  ws.send(
    JSON.stringify({
      command,
      data,
      correlation_id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    }),
  );
  return true;
};

const startDebugProjection = () => {
  if (typeof window === "undefined") return;
  const serverBase = getDebugDeviceServerBase();
  if (!serverBase) {
    showTip(t.value.scriptsPage.editorSelectDevice);
    return;
  }
  closeDebugProjection();
  debugProjectionOpen.value = true;
  debugProjectionStatus.value = "connecting";
  debugProjectionFrameSize.value = { width: 0, height: 0 };

  const projectionWsUrl = new URL(`${serverBase}/ws/screen/25@30/live`);
  projectionWsUrl.protocol = projectionWsUrl.protocol === "https:" ? "wss:" : "ws:";
  projectionWsUrl.searchParams.set("type", "h264");
  projectionWsUrl.searchParams.set("backend", "1");
  projectionWsUrl.searchParams.set("scale", "0.5");
  const touchWsUrl = new URL(`${serverBase}/ws/screen/touch`);
  touchWsUrl.protocol = touchWsUrl.protocol === "https:" ? "wss:" : "ws:";
  const cmdWsUrl = new URL(`${serverBase}/ws/command`);
  cmdWsUrl.protocol = cmdWsUrl.protocol === "https:" ? "wss:" : "ws:";

  try {
    const decoderUrl = new URL(`${serverBase}/static/js/decoder.js`).toString();
    const workerCode = `(function(){var window=self;self.window=self;var document=undefined;importScripts('${decoderUrl.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}');var decoder=null;function ensure(){if(!decoder){decoder=new H264Decoder();}}self.onmessage=function(e){var d=e.data;if(d&&d.t==='data'){ensure();var u8=new Uint8Array(d.b);try{if(decoder.decode(u8)===H264Decoder.PIC_RDY){var w=decoder.width;var h=decoder.height;var pic=decoder.pic;var out=new Uint8Array(pic.length);out.set(pic);try{self.postMessage({t:'frame',w:w,h:h,pic:out},[out.buffer]);}catch(_){self.postMessage({t:'frame',w:w,h:h,pic:out});}}}catch(_){ }return;}if(d&&d.t==='close'){try{self.close();}catch(_){ }}};})();`;
    const workerBlob = new Blob([workerCode], { type: "application/javascript" });
    const workerUrl = URL.createObjectURL(workerBlob);
    const worker = new Worker(workerUrl);
    debugProjectionWorker = worker;
    debugProjectionWorkerUrl = workerUrl;
    worker.onmessage = (ev) => {
      const d = ev.data;
      if (!d || d.t !== "frame") return;
      drawProjectionFrame({
        width: Number(d.w || 0),
        height: Number(d.h || 0),
        yuv: d.pic as Uint8Array,
      });
    };
  } catch {
    debugProjectionStatus.value = "error";
    return;
  }

  try {
    const screenWs = new WebSocket(projectionWsUrl.toString());
    screenWs.binaryType = "arraybuffer";
    debugProjectionWs = screenWs;
    screenWs.onopen = () => {
      debugProjectionStatus.value = "connected";
    };
    screenWs.onmessage = (ev) => {
      const worker = debugProjectionWorker;
      if (!worker) return;
      try {
        worker.postMessage({ t: "data", b: ev.data }, [ev.data]);
      } catch {
        worker.postMessage({ t: "data", b: ev.data });
      }
    };
    screenWs.onerror = () => {
      debugProjectionStatus.value = "error";
    };
    screenWs.onclose = () => {
      debugProjectionWs = null;
      debugProjectionStatus.value = debugProjectionStatus.value === "idle" ? debugProjectionStatus.value : "error";
    };
  } catch {
    debugProjectionStatus.value = "error";
  }

  try {
    const touchWs = new WebSocket(touchWsUrl.toString());
    debugProjectionTouchWs = touchWs;
    touchWs.onopen = () => {
      debugProjectionTouchReady.value = true;
      touchWs.send(JSON.stringify({ action: "reset" }));
    };
    touchWs.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data || "{}"));
        if (msg?.type === "OK") {
          const w = Number(msg?.w || 0);
          const h = Number(msg?.h || 0);
          debugProjectionTouchSize = {
            width: Number.isFinite(w) && w > 0 ? w : 0,
            height: Number.isFinite(h) && h > 0 ? h : 0,
          };
          tryAutoFitProjectionRect();
        }
      } catch {}
    };
    touchWs.onerror = () => {
      debugProjectionTouchReady.value = false;
    };
    touchWs.onclose = () => {
      debugProjectionTouchWs = null;
      debugProjectionTouchReady.value = false;
    };
  } catch {
    debugProjectionTouchReady.value = false;
  }

  try {
    const commandWs = new WebSocket(cmdWsUrl.toString());
    debugProjectionCommandWs = commandWs;
    commandWs.onclose = () => {
      debugProjectionCommandWs = null;
    };
    commandWs.onerror = () => {};
    commandWs.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data || "{}"));
        const applyRotation = (raw: unknown) => {
          const rot = Number(raw ?? 0);
          if (!Number.isFinite(rot)) return;
          const normalized = ((Math.round(rot) % 4) + 4) % 4;
          debugProjectionRotation.value = normalized;
          if (!debugProjectionRotationInit) {
            debugProjectionRotationInit = true;
            debugProjectionRotationCurrent = normalized;
            return;
          }
          if (debugProjectionRotationCurrent === normalized) return;
          debugProjectionRotationCurrent = normalized;
          if (debugProjectionRotationRestartTimer != null) {
            window.clearTimeout(debugProjectionRotationRestartTimer);
          }
          debugProjectionRotationRestartTimer = window.setTimeout(() => {
            debugProjectionRotationRestartTimer = null;
            // Keep overlay open, but recreate stream/touch sockets to match new display orientation.
            startDebugProjection();
          }, 420);
        };
        if (msg?.type === "device/info" && msg?.data) {
          applyRotation(msg.data.displayRotation);
        }
        if (msg?.type === "status" && msg?.data && Number.isFinite(Number(msg.data.displayRotation))) {
          applyRotation(msg.data.displayRotation);
        }
      } catch {}
    };
    commandWs.onopen = () => {
      sendProjectionCommand("device/info", []);
      debugProjectionRotationTimer = window.setInterval(() => {
        sendProjectionCommand("device/info", []);
      }, 2000);
    };
  } catch {}
};

const handleProjectionCanvasPointerDown = (event: PointerEvent) => {
  if (event.pointerType === "touch") event.preventDefault();
  const point = resolveProjectionTouchPoint(event);
  if (!point) return;
  debugProjectionTouchDown = true;
  (event.currentTarget as HTMLElement)?.setPointerCapture?.(event.pointerId);
  sendProjectionTouch({ action: "down", id: 0, x: point.x, y: point.y });
};

const handleProjectionCanvasPointerMove = (event: PointerEvent) => {
  if (!debugProjectionTouchDown) return;
  if (event.pointerType === "touch") event.preventDefault();
  const point = resolveProjectionTouchPoint(event);
  if (!point) return;
  sendProjectionTouch({ action: "move", id: 0, x: point.x, y: point.y });
};

const handleProjectionCanvasPointerUp = (event: PointerEvent) => {
  if (!debugProjectionTouchDown) return;
  if (event.pointerType === "touch") event.preventDefault();
  debugProjectionTouchDown = false;
  (event.currentTarget as HTMLElement)?.releasePointerCapture?.(event.pointerId);
  sendProjectionTouch({ action: "up", id: 0 });
};

const startProjectionMove = (event: PointerEvent) => {
  const host = debugProjectionHostRef.value;
  if (!host) return;
  event.preventDefault();
  const hostRect = host.getBoundingClientRect();
  const startRect = debugProjectionRect.value;
  const startX = event.clientX;
  const startY = event.clientY;
  const onMove = (ev: PointerEvent) => {
    const dx = ev.clientX - startX;
    const dy = ev.clientY - startY;
    const maxX = Math.max(0, hostRect.width - startRect.width);
    const maxY = Math.max(0, hostRect.height - startRect.height);
    debugProjectionRect.value = {
      ...debugProjectionRect.value,
      x: clampNum(startRect.x + dx, 0, maxX),
      y: clampNum(startRect.y + dy, 0, maxY),
    };
  };
  const onUp = () => {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
    window.removeEventListener("pointercancel", onUp);
  };
  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp);
  window.addEventListener("pointercancel", onUp);
};

const startProjectionResize = (event: PointerEvent, handle: "n" | "s" | "w" | "e" | "nw" | "ne" | "sw" | "se") => {
  const host = debugProjectionHostRef.value;
  if (!host) return;
  event.preventDefault();
  event.stopPropagation();
  debugProjectionRectUserSized = true;
  debugProjectionAutoFitDone = true;
  const hostRect = host.getBoundingClientRect();
  const startRect = debugProjectionRect.value;
  const startX = event.clientX;
  const startY = event.clientY;
  const onMove = (ev: PointerEvent) => {
    const dx = ev.clientX - startX;
    const dy = ev.clientY - startY;
    let nextX = startRect.x;
    let nextY = startRect.y;
    let nextW = startRect.width;
    let nextH = startRect.height;
    const moveLeft = handle.includes("w");
    const moveRight = handle.includes("e");
    const moveTop = handle.includes("n");
    const moveBottom = handle.includes("s");

    if (moveRight) {
      const maxW = Math.max(PROJECTION_MIN_WIDTH, hostRect.width - startRect.x);
      nextW = clampNum(startRect.width + dx, PROJECTION_MIN_WIDTH, maxW);
    }
    if (moveBottom) {
      const maxH = Math.max(PROJECTION_MIN_HEIGHT, hostRect.height - startRect.y);
      nextH = clampNum(startRect.height + dy, PROJECTION_MIN_HEIGHT, maxH);
    }
    if (moveLeft) {
      const maxX = startRect.x + startRect.width - PROJECTION_MIN_WIDTH;
      nextX = clampNum(startRect.x + dx, 0, Math.max(0, maxX));
      nextW = clampNum(startRect.width - (nextX - startRect.x), PROJECTION_MIN_WIDTH, hostRect.width - nextX);
    }
    if (moveTop) {
      const maxY = startRect.y + startRect.height - PROJECTION_MIN_HEIGHT;
      nextY = clampNum(startRect.y + dy, 0, Math.max(0, maxY));
      nextH = clampNum(startRect.height - (nextY - startRect.y), PROJECTION_MIN_HEIGHT, hostRect.height - nextY);
    }

    debugProjectionRect.value = {
      x: clampNum(nextX, 0, Math.max(0, hostRect.width - nextW)),
      y: clampNum(nextY, 0, Math.max(0, hostRect.height - nextH)),
      width: nextW,
      height: nextH,
    };
  };
  const onUp = () => {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
    window.removeEventListener("pointercancel", onUp);
  };
  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp);
  window.addEventListener("pointercancel", onUp);
};

const toggleDebugProjection = () => {
  if (debugProjectionOpen.value) {
    closeDebugProjection();
    debugProjectionOpen.value = false;
    return;
  }
  startDebugProjection();
};

watch(debugMode, (mode) => {
  if (mode) return;
  closeDebugProjection();
  debugProjectionOpen.value = false;
});

watch(debugProjectionOpen, (open, _prev, onCleanup) => {
  if (!open) return;
  const syncRect = () => {
    if (!debugProjectionRectUserSized && !debugProjectionAutoFitDone) {
      applyDefaultProjectionRect();
      return;
    }
    const host = debugProjectionHostRef.value;
    if (!host) return;
    const rect = host.getBoundingClientRect();
    const prev = debugProjectionRect.value;
    const maxW = Math.max(PROJECTION_MIN_WIDTH, rect.width);
    const maxH = Math.max(PROJECTION_MIN_HEIGHT, rect.height);
    const width = clampNum(prev.width, PROJECTION_MIN_WIDTH, maxW);
    const height = clampNum(prev.height, PROJECTION_MIN_HEIGHT, maxH);
    const x = clampNum(prev.x, 0, Math.max(0, rect.width - width));
    const y = clampNum(prev.y, 0, Math.max(0, rect.height - height));
    debugProjectionRect.value = { x, y, width, height };
  };
  syncRect();
  window.addEventListener("resize", syncRect);
  onCleanup(() => window.removeEventListener("resize", syncRect));
}, { flush: "post" });

watch([() => selectedDebugDevice.value?.domain, debugProjectionOpen], () => {
  const domain = String(selectedDebugDevice.value?.domain || "");
  if (debugProjectionDomain && debugProjectionDomain !== domain && debugProjectionOpen.value) {
    closeDebugProjection();
    debugProjectionOpen.value = false;
  }
  debugProjectionDomain = domain;
});

watch([() => debugProjectionFrameSize.value.width, () => debugProjectionFrameSize.value.height, debugProjectionOpen], (_values, _prev, onCleanup) => {
  if (!debugProjectionOpen.value) return;
  const viewport = debugProjectionViewportRef.value;
  if (!viewport) return;
  const update = () => {
    const rect = viewport.getBoundingClientRect();
    const frameW = Math.max(1, debugProjectionFrameSize.value.width || 0);
    const frameH = Math.max(1, debugProjectionFrameSize.value.height || 0);
    if (!rect.width || !rect.height || !frameW || !frameH) {
      debugProjectionCanvasViewSize.value = { width: 0, height: 0 };
      return;
    }
    const scale = Math.min(rect.width / frameW, rect.height / frameH);
    const width = Math.max(1, Math.floor(frameW * scale));
    const height = Math.max(1, Math.floor(frameH * scale));
    debugProjectionCanvasViewSize.value = { width, height };
  };
  update();
  const observer = new ResizeObserver(update);
  observer.observe(viewport);
  onCleanup(() => observer.disconnect());
}, { flush: "post" });

const applyDebugSourceDecorations = () => {
  const editor = debugSourceEditor;
  const monaco = debugSourceMonaco;
  if (!editor || !monaco) return;
  const next: any[] = [];
  if (debugStoppedLine.value && Number.isFinite(debugStoppedLine.value) && debugStoppedLine.value > 0) {
    next.push({
      range: new monaco.Range(debugStoppedLine.value, 1, debugStoppedLine.value, 1),
      options: {
        isWholeLine: true,
        className: "debug-source-active-line",
        linesDecorationsClassName: "debug-source-active-gutter",
        glyphMarginClassName: "debug-source-current-glyph",
      },
    });
  }
  for (const bp of debugBreakpoints.value) {
    if (!Number.isFinite(bp) || bp <= 0) continue;
    next.push({
      range: new monaco.Range(bp, 1, bp, 1),
      options: {
        isWholeLine: false,
        glyphMarginClassName: "debug-source-breakpoint-glyph",
      },
    });
  }
  debugSourceDecorations = editor.deltaDecorations(debugSourceDecorations, next);
};

const handleDebugSourceMount: OnMount = (editor, monaco) => {
  debugSourceEditor = editor;
  debugSourceMonaco = monaco;
  editor.onMouseDown((e: any) => {
    const t = e.target?.type;
    const isGutter =
      t === monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN ||
      t === monaco.editor.MouseTargetType.GUTTER_LINE_NUMBERS ||
      t === monaco.editor.MouseTargetType.GUTTER_LINE_DECORATIONS;
    // Disable source selection/caret behavior; keep only breakpoint toggle on gutter.
    e.event?.preventDefault?.();
    e.event?.stopPropagation?.();
    if (!isGutter) return;
    const lineNo = Number(e.target?.position?.lineNumber || 0);
    if (!Number.isFinite(lineNo) || lineNo <= 0) return;
    toggleDebugBreakpoint(lineNo);
  });
  editor.onDidChangeCursorSelection((ev: any) => {
    if (ev.selection && !ev.selection.isEmpty()) {
      const p = ev.selection.getStartPosition();
      editor.setSelection(new monaco.Selection(p.lineNumber, 1, p.lineNumber, 1));
    }
  });
  applyDebugSourceDecorations();
};

watch([debugStoppedLine, debugBreakpoints, debugSourceLines], () => {
  applyDebugSourceDecorations();
});

watch([debugStoppedLine, debugSourceLines], () => {
  const editor = debugSourceEditor;
  if (!editor || !debugStoppedLine.value || debugStoppedLine.value <= 0) return;
  // Ensure the paused line is always visible.
  editor.revealLineInCenterIfOutsideViewport(debugStoppedLine.value);
  editor.setPosition({ lineNumber: debugStoppedLine.value, column: 1 });
});

const getDraftStorageKey = (uid: number) => {
  if (!scriptId || !uid) return "";
  return `script:draft:${uid}:${scriptId}`;
};

const readDraft = (uid: number): ScriptDraft | null => {
  const key = getDraftStorageKey(uid);
  if (!key || typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (typeof parsed?.code !== "string") return null;
    return {
      versionId: parsed.versionId == null ? null : Number(parsed.versionId),
      code: parsed.code,
      savedAt: Number(parsed.savedAt || 0),
    };
  } catch {
    return null;
  }
};

const saveDraft = () => {
  const key = getDraftStorageKey(selfId.value);
  if (!key || typeof window === "undefined") return;
  const payload: ScriptDraft = {
    versionId: selectedVersionId.value ?? null,
    code: editorCode.value,
    savedAt: Date.now(),
  };
  window.localStorage.setItem(key, JSON.stringify(payload));
  showTip(t.value.scriptsPage.editorDraftSaved, "success");
};

const clearDraft = () => {
  const key = getDraftStorageKey(selfId.value);
  if (!key || typeof window === "undefined") return;
  window.localStorage.removeItem(key);
};

const runGuarded = (action: () => void | Promise<void>) => {
  if (isDirty.value) {
    promptUnsaved(action);
    return;
  }
  void action();
};

const handleEditorMount: OnMount = (editor, monaco) => {
  scriptEditor = editor;
  // Some global key handlers in the shell may swallow Space.
  // Force-insert a plain space to keep typing behavior stable in script editor.
  editor.addCommand(monaco.KeyCode.Space, () => {
    editor.trigger("keyboard", "type", { text: " " });
  });
};

const onUnsavedDialogOpenChange = (open: boolean) => {
  unsavedDialogOpenCurrent = open;
  unsavedDialogOpen.value = open;
  if (!open) {
    window.setTimeout(() => {
      pendingAction = null;
    }, 0);
  }
};

const continuePending = async (mode: "save" | "discard") => {
  const action = pendingAction;
  pendingAction = null;
  unsavedDialogOpenCurrent = false;
  unsavedDialogOpen.value = false;
  if (!action) return;
  if (mode === "save") saveDraft();
  if (mode === "discard") clearDraft();
  allowNextNavigation();
  const hashBefore = typeof window === "undefined" ? "" : window.location.hash;
  try {
    await action();
  } finally {
    if (typeof window !== "undefined" && window.location.hash === hashBefore) {
      restoreGuard();
    }
  }
};

const loadUsersForAlloc = async (keyword: string) => {
  if (!scriptId) return;
  usersLoading.value = true;
  try {
    const qs = new URLSearchParams({ page: "1", size: "20", sort: "id", order: "desc" });
    if (keyword.trim()) {
      qs.set("filter", JSON.stringify([{ field: "name", op: "like", value: keyword.trim() }]));
    }
    const res = await apiRequest<any>(`/api/v1/user?${qs.toString()}`, { cache: "no-store" });
    const list = Array.isArray(res.data?.data) ? res.data.data : [];
    candidateUsers.value = list
      .map((u: any) => ({
        id: Number(u?.id ?? 0),
        name: String(u?.name || ""),
        username: String(u?.username || ""),
        contact: String(u?.contact || ""),
      }))
      .filter((u: ScriptUser) => u.id > 0);
  } catch (error) {
    candidateUsers.value = [];
    showTip(formatApiError(error, t.value.scriptsPage.editorLoadUsersFailed));
  } finally {
    usersLoading.value = false;
  }
};

const loadSharedUsers = async () => {
  if (!scriptId) return;
  try {
    const res = await apiRequest<any>(`/api/v1/script/${scriptId}/alloc?page=1&size=200&sort=id&order=asc`, { cache: "no-store" });
    const list = Array.isArray(res.data?.data) ? res.data.data : [];
    sharedUsers.value = list
      .map((u: any) => ({
        id: Number(u?.id ?? 0),
        name: String(u?.name || ""),
        username: String(u?.username || ""),
        contact: String(u?.contact || ""),
      }))
      .filter((u: ScriptUser) => u.id > 0);
  } catch (error) {
    sharedUsers.value = [];
    showTip(formatApiError(error, t.value.scriptsPage.editorLoadUsersFailed));
  }
};

const fetchVersionCode = async (vid: number) => {
  if (!scriptId || !vid) return { code: "" };
  const res = await apiRequest<any>(`/api/v1/script/${scriptId}/${vid}?_ts=${Date.now()}`, { cache: "no-store" });
  const data = res.data || {};
  return { code: typeof data.code === "string" ? data.code : "" };
};

const loadVersionCode = async (vid: number) => {
  if (!scriptId || !vid) return;
  try {
    const { code } = await fetchVersionCode(vid);
    editorCode.value = code;
    baseEditorCode.value = code;
  } catch (error) {
    editorCode.value = "";
    baseEditorCode.value = "";
    showTip(formatApiError(error, t.value.scriptsPage.editorLoadVersionFailed));
  }
};

const loadDetail = async (viewerId: number) => {
  if (!scriptId) return;
  loading.value = true;
  try {
    const res = await apiRequest<any>(`/api/v1/script/${scriptId}`, { cache: "no-store" });
    const data = res.data || {};
    const mapped: ScriptDetail = {
      id: Number(data?.id || scriptId),
      name: String(data?.name || "-"),
      description: String(data?.description || ""),
      type: Number(data?.type ?? 0),
      entry: data?.entry ?? null,
      params: data?.params,
      create_time: Number(data?.create_time ?? 0),
      owner: data?.owner || {},
      versions: normalizeVersions(data?.versions),
    };
    const ownerId = Number(mapped.owner?.id ?? 0);
    const owner = viewerId > 0 && ownerId > 0 && viewerId === ownerId;
    detail.value = mapped;
    versions.value = mapped.versions;
    diffState.value = {
      enabled: false,
      originalVersionId: null,
      modifiedVersionId: null,
      originalCode: "",
      modifiedCode: "",
    };
    const initial = mapped.versions[0]?.id || null;
    selectedVersionId.value = initial;
    const routeVersionMatched = routeVersionId.value != null && mapped.versions.some((v) => v.id === routeVersionId.value);
    if (routeVersionMatched) {
      selectedVersionId.value = routeVersionId.value;
      await loadVersionCode(routeVersionId.value!);
    } else if (owner) {
      const draft = viewerId > 0 ? readDraft(viewerId) : null;
      if (draft && draft.versionId && mapped.versions.some((v) => v.id === draft.versionId)) {
        draftApplying.value = true;
        selectedVersionId.value = draft.versionId;
        await loadVersionCode(draft.versionId);
        editorCode.value = draft.code;
        draftApplying.value = false;
        showTip(t.value.scriptsPage.editorDraftLoaded, "info");
      } else if (draft && draft.versionId == null && !mapped.versions.length) {
        draftApplying.value = true;
        const paramSource = mapped.entry?.params ?? mapped.params;
        baseEditorCode.value = buildScriptTemplate(mapped.type, paramSource);
        editorCode.value = draft.code;
        draftApplying.value = false;
        showTip(t.value.scriptsPage.editorDraftLoaded, "info");
      } else if (initial) {
        await loadVersionCode(initial);
      } else {
        const paramSource = mapped.entry?.params ?? mapped.params;
        const tpl = buildScriptTemplate(mapped.type, paramSource);
        editorCode.value = tpl;
        baseEditorCode.value = tpl;
      }
    } else {
      editorCode.value = "";
      baseEditorCode.value = "";
    }
    await loadSharedUsers();
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.editorLoadFailed));
  } finally {
    loading.value = false;
  }
};

let bootRunId = 0;
const boot = async () => {
  const runId = ++bootRunId;
  const cancelled = () => runId !== bootRunId;
  try {
    const res = await apiRequest<any>("/api/v1/user/login", { cache: "no-store" });
    if (cancelled()) return;
    const uid = Number(res?.data?.id ?? 0);
    selfId.value = uid;
    await loadDetail(uid);
  } catch {
    if (!cancelled()) {
      selfId.value = 0;
      await loadDetail(0);
    }
  }
};

onMounted(() => {
  void boot();
});
watch(routeVersionId, () => {
  void boot();
});
onBeforeUnmount(() => {
  bootRunId += 1;
});

watch([loading, draftApplying, isOwner, () => diffState.value.enabled, selectedVersionId, editorCode], () => {
  if (loading.value || draftApplying.value) return;
  if (!isOwner.value || diffState.value.enabled || !selectedVersionId.value || editorCode.value) return;
  void loadVersionCode(selectedVersionId.value);
});

watch([usersOpen, usersSearch], () => {
  if (!usersOpen.value) return;
  void loadUsersForAlloc(usersSearch.value);
});

watch(publishOpen, (open) => {
  if (!open) return;
  publishVersion.value = "";
  publishChangeLog.value = "";
});

watch([debugDeviceOpen, debugDeviceKeyword], () => {
  if (!debugDeviceOpen.value) return;
  void loadIdleDevices(debugDeviceKeyword.value);
});

watch([debugDialogOpen, debugParams, isHybridScript], () => {
  if (!debugDialogOpen.value) return;
  const next: Record<string, string> = {};
  debugParams.value.forEach((param) => {
    const name = (param.name || "").trim();
    if (!name) return;
    next[name] = debugParamInputs.value[name] ?? "";
  });
  debugParamInputs.value = next;
  if (isHybridScript.value) {
    void loadDebugModels();
  }
});

watch([isOwner, isDirty], (_values, _prev, onCleanup) => {
  if (!isOwner.value) return;
  const handler = (event: BeforeUnloadEvent) => {
    if (!isDirty.value) return;
    event.preventDefault();
    event.returnValue = "";
  };
  window.addEventListener("beforeunload", handler);
  onCleanup(() => window.removeEventListener("beforeunload", handler));
});

watch([isOwner, isDirty], (_values, _prev, onCleanup) => {
  if (!isOwner.value || !isDirty.value) return;
  const onDocumentClick = (event: MouseEvent) => {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const target = event.target as HTMLElement | null;
    const anchor = target?.closest?.("a[href]") as HTMLAnchorElement | null;
    if (!anchor) return;
    if (anchor.target === "_blank" || anchor.hasAttribute("download")) return;
    const rawHref = anchor.getAttribute("href");
    if (!rawHref || rawHref.startsWith("javascript:")) return;

    let nextUrl: URL;
    try {
      nextUrl = new URL(rawHref, window.location.origin);
    } catch {
      return;
    }
    if (nextUrl.origin !== window.location.origin) return;

    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const next = `${nextUrl.pathname}${nextUrl.search}${nextUrl.hash}`;
    if (current === next) return;

    const hashPath = (nextUrl.hash || "").replace(/^#/, "");
    const nextHashPath = hashPath || `${nextUrl.pathname}${nextUrl.search}` || "/";

    event.preventDefault();
    event.stopPropagation();
    promptUnsaved(() => router.push(nextHashPath.startsWith("/") ? nextHashPath : `/${nextHashPath}`));
  };

  document.addEventListener("click", onDocumentClick, true);
  onCleanup(() => document.removeEventListener("click", onDocumentClick, true));
});

onBeforeUnmount(() => {
  closeDebugProjection();
  setRunLocked(false);
  debugAutoReconnect = false;
  if (debugReconnectTimer != null) {
    window.clearTimeout(debugReconnectTimer);
    debugReconnectTimer = null;
  }
  const ws = debugWs;
  if (!ws) return;
  ws.onopen = null;
  ws.onclose = null;
  ws.onerror = null;
  ws.onmessage = null;
  try {
    ws.close();
  } catch {}
  debugWs = null;
});

const handlePublish = async () => {
  if (!scriptId) return;
  const version = publishVersion.value.trim();
  if (!version) return showTip(t.value.scriptsPage.editorVersionRequired);
  if (version.length > VERSION_LEN_MAX) return showTip(t.value.scriptsPage.editorVersionTooLong);

  publishing.value = true;
  try {
    const body = new URLSearchParams({
      version,
      change_log: publishChangeLog.value.trim(),
      code: editorCode.value,
    });
    await apiRequest(`/api/v1/script/${scriptId}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    publishOpen.value = false;
    clearDraft();
    showTip(t.value.scriptsPage.editorPublishSuccess, "success");
    await loadDetail(selfId.value);
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.editorPublishFailed));
  } finally {
    publishing.value = false;
  }
};

const loadDebugModels = async () => {
  const reqId = ++debugModelReq;
  debugModelsLoading.value = true;
  try {
    const res = await apiRequest<any>("/api/v1/model?page=1&size=200&sort=id&order=desc", { cache: "no-store" });
    if (reqId !== debugModelReq) return;
    const list = Array.isArray(res.data?.data) ? res.data.data : [];
    const mapped: ModelOption[] = list
      .map((item: any) => ({
        id: String(item?.id ?? ""),
        label: String(item?.name || item?.model || `#${item?.id ?? ""}`),
        provider: String(item?.provider || "openai_compatible"),
        apiBase: String(item?.api_base || ""),
        apiKey: String(item?.api_key || ""),
        modelName: String(item?.model_name || item?.model || ""),
        visionMode: toBooleanLoose(item?.vision_mode, false),
        visionScale: toNumberLoose(item?.vision_scale, 0.5),
        temperature: toNumberLoose(item?.temperature, 0.2),
        maxTokens: Math.floor(toNumberLoose(item?.max_completion_tokens, 2048)),
        contextWindow: Math.floor(toNumberLoose(item?.context_window, 256000)),
        stepDelay: toNumberLoose(item?.step_delay, 0),
      }))
      .filter((item: ModelOption) => Boolean(item.id));
    debugModels.value = mapped;
    debugModelId.value = debugModelId.value && mapped.some((item) => item.id === debugModelId.value) ? debugModelId.value : "";
  } catch (error) {
    if (reqId !== debugModelReq) return;
    debugModels.value = [];
    showTip(formatApiError(error, t.value.scriptsPage.editorDebugLoadModelsFailed));
  } finally {
    if (reqId === debugModelReq) {
      debugModelsLoading.value = false;
    }
  }
};

const loadIdleDevices = async (keyword: string) => {
  const reqId = ++debugDeviceReq;
  debugDeviceLoading.value = true;
  try {
    const qs = new URLSearchParams({ page: "1", size: "200", sort: "id", order: "desc" });
    const q = keyword.trim();
    if (q) {
      qs.set("filter", JSON.stringify([{ field: "domain", op: "like", value: q }]));
    }
    const res = await apiRequest<any>(`/api/v1/device/idle?${qs.toString()}`, { cache: "no-store" });
    if (reqId !== debugDeviceReq) return;
    const list = Array.isArray(res.data?.data) ? res.data.data : [];
    const mapped: IdleDevice[] = list
      .map((item: any) => {
        const domain = String(item?.domain || "");
        const devId = String(item?.dev_id || item?.devId || "");
        return {
          key: domain || devId,
          domain,
          devId,
          brand: String(item?.brand || "-"),
          model: String(item?.model || "-"),
          deviceName: String(item?.device || ""),
          apiAvailable: Boolean(item?.api_available),
        };
      })
      .filter((item: IdleDevice) => Boolean(item.key));
    idleDevices.value = mapped;
    debugDeviceId.value = debugDeviceId.value && mapped.some((item) => item.key === debugDeviceId.value) ? debugDeviceId.value : "";
  } catch (error) {
    if (reqId !== debugDeviceReq) return;
    idleDevices.value = [];
    showTip(formatApiError(error, t.value.scriptsPage.editorLoadIdleDevicesFailed));
  } finally {
    if (reqId === debugDeviceReq) {
      debugDeviceLoading.value = false;
    }
  }
};

const disconnectDebugWs = (options?: { keepAutoReconnect?: boolean }) => {
  if (!options?.keepAutoReconnect) {
    debugAutoReconnect = false;
  }
  if (debugReconnectTimer != null) {
    window.clearTimeout(debugReconnectTimer);
    debugReconnectTimer = null;
  }
  const ws = debugWs;
  if (!ws) return;
  ws.onopen = null;
  ws.onclose = null;
  ws.onerror = null;
  ws.onmessage = null;
  try {
    ws.close();
  } catch {}
  debugWs = null;
  debugWsStatus.value = "disconnected";
  setRunLocked(false);
};

const connectDebugWs = (options?: { silent?: boolean }) => {
  if (typeof window === "undefined") return;
  if (!selectedDebugDevice.value) {
    if (!options?.silent) showTip(t.value.scriptsPage.editorSelectDevice);
    return;
  }
  const domain = String(selectedDebugDevice.value.domain || "").trim();
  if (!domain) {
    if (!options?.silent) showTip(t.value.scriptsPage.editorSelectDevice);
    return;
  }
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const nextUrl = `${proto}://${window.location.host}/d/${encodeURIComponent(domain)}/ws/debugee`;
  debugAutoReconnect = true;
  disconnectDebugWs({ keepAutoReconnect: true });
  debugWsStatus.value = "connecting";
  try {
    const ws = new WebSocket(nextUrl);
    debugWs = ws;
    ws.onopen = () => {
      debugWsStatus.value = "connected";
      if (debugReconnectTimer != null) {
        window.clearTimeout(debugReconnectTimer);
        debugReconnectTimer = null;
      }
    };
    ws.onclose = () => {
      if (debugWs === ws) debugWs = null;
      debugWsStatus.value = "disconnected";
      debugExecState.value = "idle";
      setRunLocked(false);
      if (debugAutoReconnect) {
        if (debugReconnectTimer != null) window.clearTimeout(debugReconnectTimer);
        debugReconnectTimer = window.setTimeout(() => {
          connectDebugWs({ silent: true });
        }, 1200);
      }
    };
    ws.onerror = () => {
      debugWsStatus.value = "error";
      debugExecState.value = "idle";
      setRunLocked(false);
    };
    ws.onmessage = (ev) => {
      let msg: any = null;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      const type = String(msg?.type || "");
      if (type === "hello") {
        const caps = msg?.capabilities || {};
        debugCapabilities.value = {
          cmd: Array.isArray(caps?.cmd) ? caps.cmd.map((item: unknown) => String(item)) : ["continue", "next", "out", "quit", "step"],
          bp: Array.isArray(caps?.bp) ? caps.bp.map((item: unknown) => String(item)) : ["toggle"],
          eval: caps?.eval !== false,
        };
        return;
      }
      if (type === "started") {
        const fallbackCode = debugRunCode || editorCode.value;
        const lines = Array.isArray(msg?.lines) ? msg.lines.map((line: unknown) => String(line ?? "")) : fallbackCode.split(/\r?\n/);
        debugSourceLines.value = lines;
        debugStoppedLine.value = null;
        debugBreakpoints.value = [];
        debugLocalsRaw.value = [];
        debugStackRaw.value = [];
        debugOutput.value = "";
        debugExecState.value = "running";
        setRunLocked(true);
        return;
      }
      if (type === "stopped") {
        const lineno = Number(msg?.lineno ?? 0);
        debugStoppedLine.value = Number.isFinite(lineno) && lineno > 0 ? lineno : null;
        if (Array.isArray(msg?.breakpoints)) {
          debugBreakpoints.value = msg.breakpoints.map((n: unknown) => Number(n)).filter((n: number) => Number.isFinite(n) && n > 0);
        }
        const localList = Array.isArray(msg?.locals)
          ? (msg.locals as any[]).map((item) => ({
              name: String(item?.name ?? ""),
              type: String(item?.type ?? ""),
            }))
          : [];
        debugLocalsRaw.value = localList;
        const stack = Array.isArray(msg?.stack) ? (msg.stack as DebugStackFrame[]) : [];
        debugStackRaw.value = stack;
        debugExecState.value = "paused";
        return;
      }
      if (type === "output") {
        const stream = String(msg?.stream || "stdout");
        const text = String(msg?.text || "");
        const body = text.trim();
        if (!body) return;
        if (stream === "stderr") {
          appendDebugOutput(body, true, "stderr");
          return;
        }
        if (stream === "stdout" || stream === "console") {
          appendDebugOutput(body, true, "stdout");
          return;
        }
        appendDebugOutput(body, true, "stdout");
        return;
      }
      if (type === "locals") {
        const localList = Array.isArray(msg?.locals)
          ? (msg.locals as any[]).map((item) => ({
              name: String(item?.name ?? ""),
              type: String(item?.type ?? ""),
            }))
          : [];
        debugLocalsRaw.value = localList;
        return;
      }
      if (type === "breakpoints") {
        if (Array.isArray(msg?.breakpoints)) {
          debugBreakpoints.value = msg.breakpoints.map((n: unknown) => Number(n)).filter((n: number) => Number.isFinite(n) && n > 0);
        }
        return;
      }
      if (type === "terminated") {
        const reason = String(msg?.reason || "").trim();
        if (reason) appendDebugOutput(`terminated: ${reason}`, true, "stdout");
        debugExecState.value = "idle";
        setRunLocked(false);
        return;
      }
      if (type === "error") {
        const message = String(msg?.message || "error");
        appendDebugOutput(message, true, "stderr");
        if (msg?.traceback) appendDebugOutput(String(msg.traceback), true, "stderr");
        // Backend execution/eval errors should not be treated as transport errors.
        // Connection status is tracked by WebSocket onerror/onclose only.
      }
    };
  } catch {
    debugWsStatus.value = "error";
    debugExecState.value = "idle";
    setRunLocked(false);
    if (!options?.silent) showTip(t.value.scriptsPage.debugWsConnectFailed);
    if (debugAutoReconnect) {
      if (debugReconnectTimer != null) window.clearTimeout(debugReconnectTimer);
      debugReconnectTimer = window.setTimeout(() => {
        connectDebugWs({ silent: true });
      }, 1200);
    }
  }
};

const handleDebug = () => {
  if (!selectedDebugDevice.value) return;
  if (!isHybridScript.value && debugParams.value.length === 0) {
    debugMode.value = true;
    debugConsoleCode.value = "";
    resetDebugConsole();
    const runCode = buildDebugRunCode();
    debugRunCode = runCode;
    debugSourceLines.value = runCode.split(/\r?\n/);
    connectDebugWs();
    showTip(t.value.scriptsPage.editorDebugReady, "success");
    return;
  }
  debugDialogOpen.value = true;
};

const buildDebugRunCode = () => {
  const typedDebugParams: Record<string, unknown> = {};
  for (const param of debugParams.value) {
    const name = String(param.name || "").trim();
    if (!name) continue;
    const raw = String(debugParamInputs.value[name] ?? "").trim();
    const paramType = normalizeParamType(param.type);
    if (paramType === "integer") {
      typedDebugParams[name] = Number.parseInt(raw || "0", 10);
    } else if (paramType === "float") {
      typedDebugParams[name] = Number(raw || "0");
    } else if (paramType === "boolean") {
      typedDebugParams[name] = toBooleanLoose(raw, false);
    } else if (paramType === "list" || paramType === "object") {
      try {
        typedDebugParams[name] = JSON.parse(raw || (paramType === "list" ? "[]" : "{}"));
      } catch {
        typedDebugParams[name] = paramType === "list" ? [] : {};
      }
    } else {
      typedDebugParams[name] = raw;
    }
  }

  const model = selectedDebugModel.value;
  const agentExpr = model
    ? `AnyLLMUiautomatorAgent(${toPythonLiteral(model.apiBase || "")}, ${toPythonLiteral(model.apiKey || "")}, ${toPythonLiteral(model.modelName || "")}, provider=${toPythonLiteral(model.provider || "openai_compatible")}, vision=${toPythonLiteral(Boolean(model.visionMode))}, scale=${toPythonLiteral(toNumberLoose(model.visionScale, 0.5))}, temperature=${toPythonLiteral(toNumberLoose(model.temperature, 0.2))}, max_completion_tokens=${toPythonLiteral(Math.floor(toNumberLoose(model.maxTokens, 2048)))}, context_window=${toPythonLiteral(Math.floor(toNumberLoose(model.contextWindow, 256000)))}, step_delay=${toPythonLiteral(toNumberLoose(model.stepDelay, 0))})`
    : "None";
  const confExpr = "{}";
  const kwargsExpr = Object.entries(typedDebugParams)
    .map(([key, value]) => `${key}=${toPythonLiteral(value)}`)
    .join(", ");
  const wrapperArgsExpr = kwargsExpr ? `, ${kwargsExpr}` : "";
  return `${editorCode.value}

# AUTO GENERATED DEBUG WRAPPER DO NOT MODIFY
if __name__ == "__main__":
    from lamda.executor import run
    FireRPATaskExecutor.agent  = ${agentExpr}
    FireRPATaskExecutor.config = ${confExpr}
    FireRPATaskExecutor.config["base"] = globals().get("FireRPABaseTaskExecutor")
    run(FireRPATaskExecutor${wrapperArgsExpr})
`;
};

const confirmDebugConfig = () => {
  if (isHybridScript.value && !debugModelId.value) {
    showTip(t.value.scriptsPage.editorDebugModelRequired);
    return;
  }
  for (const param of debugParams.value) {
    const name = (param.name || "").trim();
    if (!name) continue;
    const value = String(debugParamInputs.value[name] ?? "").trim();
    if (!value) {
      showTip(t.value.scriptsPage.editorDebugParamRequired.replace("{name}", name));
      return;
    }
    const type = normalizeParamType(param.type);
    if (type === "integer" && !Number.isInteger(Number(value))) {
      showTip(t.value.scriptsPage.editorDebugParamIntegerInvalid.replace("{name}", name));
      return;
    }
    if (type === "float" && !Number.isFinite(Number(value))) {
      showTip(t.value.scriptsPage.editorDebugParamFloatInvalid.replace("{name}", name));
      return;
    }
    if (type === "boolean" && !["true", "false", "1", "0", "yes", "no"].includes(value.toLowerCase())) {
      showTip(t.value.scriptsPage.editorDebugParamBooleanInvalid.replace("{name}", name));
      return;
    }
    if (type === "list") {
      try {
        const parsed = JSON.parse(value);
        if (!Array.isArray(parsed)) throw new Error("invalid list");
      } catch {
        showTip(t.value.scriptsPage.editorDebugParamListInvalid.replace("{name}", name));
        return;
      }
    }
    if (type === "object") {
      try {
        const parsed = JSON.parse(value);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid object");
      } catch {
        showTip(t.value.scriptsPage.editorDebugParamObjectInvalid.replace("{name}", name));
        return;
      }
    }
  }
  debugDialogOpen.value = false;
  debugMode.value = true;
  debugConsoleCode.value = "";
  resetDebugConsole();
  const runCode = buildDebugRunCode();
  debugRunCode = runCode;
  debugSourceLines.value = runCode.split(/\r?\n/);
  connectDebugWs();
  showTip(t.value.scriptsPage.editorDebugReady, "success");
};

const runDebugScript = () => {
  if (!debugCanRun.value || debugRunLock) return;
  if (!selectedDebugDevice.value) {
    showTip(t.value.scriptsPage.editorSelectDevice);
    return;
  }
  const runCode = debugRunCode || buildDebugRunCode();
  const context = {
    script_id: scriptId,
    device_id: selectedDebugDevice.value.devId || selectedDebugDevice.value.domain || "",
    domain: selectedDebugDevice.value.domain || "",
    model_id: debugModelId.value || "",
    params: debugParamInputs.value,
  };
  debugRunCode = runCode;
  // Synchronous lock to avoid double-click race before state commit.
  setRunLocked(true);
  const ok = sendDebugMessage({ type: "run", code: runCode, context });
  if (!ok) {
    debugRunCode = "";
    setRunLocked(false);
    return;
  }
  debugSourceLines.value = runCode.split(/\r?\n/);
  debugExecState.value = "starting";
};

const sendDebugCommand = (cmd: "step" | "next" | "out" | "continue" | "quit") => {
  if (!debugCapabilities.value.cmd.includes(cmd)) return;
  sendDebugMessage({ type: "cmd", cmd });
  if (cmd !== "quit") debugExecState.value = "running";
};

const quitDebugSession = () => {
  sendDebugMessage({ type: "cmd", cmd: "quit" });
  closeDebugProjection();
  debugProjectionOpen.value = false;
  resetDebugConsole();
  exitDebugMode();
};

const evalDebugConsole = () => {
  if (!debugCapabilities.value.eval) return;
  const code = debugConsoleCode.value.trim();
  if (!code) return;
  sendDebugMessage({ type: "eval", code });
  debugConsoleCode.value = "";
};

function toggleDebugBreakpoint(lineNo: number) {
  if (!debugCapabilities.value.bp.includes("toggle")) return;
  if (!Number.isFinite(lineNo) || lineNo <= 0) return;
  sendDebugMessage({ type: "bp", action: "toggle", lineno: lineNo });
}

const evalDebugLocal = (name: string) => {
  const expr = String(name || "").trim();
  if (!expr) return;
  sendDebugMessage({ type: "eval", code: expr });
};

const exitDebugMode = () => {
  closeDebugProjection();
  debugProjectionOpen.value = false;
  debugMode.value = false;
  disconnectDebugWs();
};

const handleAlloc = async (uid: number) => {
  if (!scriptId || !uid) return;
  allocBusy.value = true;
  try {
    await apiRequest(`/api/v1/script/${scriptId}/alloc`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id: String(uid) }).toString(),
    });
    showTip(t.value.scriptsPage.editorShareAdded, "success");
    await loadSharedUsers();
    usersOpen.value = false;
    usersSearch.value = "";
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.editorShareFailed));
  } finally {
    allocBusy.value = false;
  }
};

const handleRemoveAlloc = async (uid: number) => {
  if (!scriptId || !uid) return;
  allocBusy.value = true;
  try {
    await apiRequest(`/api/v1/script/${scriptId}/alloc?id=${uid}`, { method: "DELETE" });
    showTip(t.value.scriptsPage.editorShareRemoved, "success");
    await loadSharedUsers();
  } catch (error) {
    showTip(formatApiError(error, t.value.scriptsPage.editorShareFailed));
  } finally {
    allocBusy.value = false;
  }
};

const handleVersionClick = (e: MouseEvent, v: ScriptVersion) => {
  if (draftApplying.value) return;
  const useDiffMode = (e.metaKey || e.ctrlKey) && isOwner.value;
  if (useDiffMode && selectedVersionId.value && selectedVersionId.value !== v.id) {
    void (async () => {
      try {
        const [left, right] = await Promise.all([
          fetchVersionCode(selectedVersionId.value!),
          fetchVersionCode(v.id),
        ]);
        diffState.value = {
          enabled: true,
          originalVersionId: selectedVersionId.value,
          modifiedVersionId: v.id,
          originalCode: left.code,
          modifiedCode: right.code,
        };
        selectedVersionId.value = v.id;
      } catch (error) {
        showTip(formatApiError(error, t.value.scriptsPage.editorLoadVersionFailed));
      }
    })();
    return;
  }
  const switchVersion = async () => {
    diffState.value = {
      enabled: false,
      originalVersionId: null,
      modifiedVersionId: null,
      originalCode: "",
      modifiedCode: "",
    };
    selectedVersionId.value = v.id;
    if (isOwner.value) {
      await loadVersionCode(v.id);
    }
  };
  runGuarded(switchVersion);
};

const onDebugDeviceOpenChange = (open: boolean) => {
  debugDeviceOpen.value = open;
  if (!open) debugDeviceKeyword.value = "";
};

const debugParamName = (param: ParamItem) => (param.name || "").trim();
const debugParamType = (param: ParamItem) => normalizeParamType(param.type);
const isJsonParamType = (type: string) => type === "list" || type === "object";
</script>

<template>
  <div ref="debugProjectionHostRef" class="relative flex h-screen bg-[#f5f5f7]">
    <Sidebar />
    <main class="flex min-w-0 flex-1 flex-col overflow-hidden lg:ml-[220px]">
      <div class="flex h-14 shrink-0 items-center border-b border-gray-100 bg-white px-5">
        <div class="flex w-full min-w-0 items-center justify-between gap-3">
          <div class="flex min-w-0 items-center gap-2">
            <Button variant="ghost" size="icon" class="h-7 w-7 shrink-0" @click="runGuarded(() => router.push('/scripts'))">
              <ChevronLeft class="h-3.5 w-3.5" />
            </Button>
            <div class="min-w-0">
              <h1 class="truncate text-base font-semibold leading-tight">{{ detail?.name || t.scriptsPage.editorTitle }}</h1>
            </div>
          </div>
          <div class="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <FeedbackTip v-if="tip" :key="tip.id" :message="tip.text" :variant="tip.variant" compact truncate class="h-7 max-w-[min(100%,360px)] px-2 py-0" />
            <Button v-if="isOwner && isDirty" size="sm" variant="outline" class="h-8 gap-1.5 text-xs" @click="saveDraft">
              {{ t.scriptsPage.editorSaveDraft }}
            </Button>
            <Popover v-if="isOwner" :open="debugDeviceOpen" @update:open="onDebugDeviceOpenChange">
              <PopoverTrigger as-child>
                <Button variant="outline" size="sm" class="h-8 w-[260px] justify-between gap-1.5 px-2 text-xs">
                  <span class="flex min-w-0 flex-1 items-center gap-1.5">
                    <Smartphone class="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span class="truncate">
                      {{ selectedDebugDevice
                        ? `${selectedDebugDevice.brand} ${selectedDebugDevice.model} · ${selectedDebugDevice.domain || selectedDebugDevice.devId || "-"}`
                        : t.scriptsPage.editorSelectDevice }}
                    </span>
                  </span>
                  <span
                    v-if="selectedDebugDevice"
                    :class="cn('h-1.5 w-1.5 shrink-0 rounded-full', selectedDebugDevice.apiAvailable ? 'bg-emerald-500' : 'bg-red-500')"
                    aria-hidden
                  />
                  <ChevronsUpDown class="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" class="w-[var(--reka-popover-trigger-width)] p-0">
                <div class="p-2">
                  <div class="relative">
                    <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      class="h-8 pl-8 text-xs"
                      v-model="debugDeviceKeyword"
                      :placeholder="t.scriptsPage.editorSearchDevicePlaceholder"
                      autofocus
                    />
                  </div>
                </div>
                <div class="border-t border-border" />
                <div class="max-h-[260px] overflow-y-auto py-1">
                  <div v-if="debugDeviceLoading" class="flex items-center justify-center gap-2 px-3 py-8 text-xs text-muted-foreground">
                    <Loader2 class="h-3.5 w-3.5 animate-spin" />
                    {{ t.common.loading }}
                  </div>
                  <div v-else-if="idleDevices.length === 0" class="flex flex-col items-center justify-center gap-2 px-3 py-8 text-center text-xs text-muted-foreground">
                    <Inbox class="h-4 w-4" />
                    {{ t.scriptsPage.editorNoIdleDevice }}
                  </div>
                  <template v-else>
                    <button
                      v-for="item in idleDevices"
                      :key="item.key"
                      type="button"
                      class="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/60"
                      @click="debugDeviceId = item.key; debugDeviceOpen = false; debugDeviceKeyword = ''"
                    >
                      <span :class="cn('h-2.5 w-2.5 shrink-0 rounded-sm', item.apiAvailable ? 'bg-emerald-500/80' : 'bg-red-500/80')" />
                      <span class="min-w-0 flex-1">
                        <span class="block truncate text-xs font-medium">{{ item.brand }} {{ item.model }}</span>
                        <span class="block truncate text-[11px] text-muted-foreground">{{ item.domain || item.devId || "-" }}</span>
                      </span>
                    </button>
                  </template>
                </div>
              </PopoverContent>
            </Popover>
            <Button
              v-if="isOwner"
              size="sm"
              variant="outline"
              class="h-8 gap-1.5 text-xs"
              :disabled="!selectedDebugDevice"
              @click="handleDebug"
            >
              <Bug class="h-3.5 w-3.5" />
              {{ t.scriptsPage.editorDebug }}
            </Button>
            <Button v-if="isOwner" size="sm" class="h-8 gap-1.5 text-xs" @click="publishOpen = true">
              <Upload class="h-3.5 w-3.5" />
              {{ t.scriptsPage.editorPublish }}
            </Button>
            <span v-else class="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2 text-xs text-muted-foreground">
              <Share2 class="h-3 w-3 shrink-0" />
              {{ t.scriptsPage.editorReadonly }}
            </span>
            <Button
              variant="outline"
              size="sm"
              class="h-8 gap-1.5 text-xs"
              @click="runGuarded(() => loadDetail(selfId))"
              :disabled="loading"
            >
              <Loader2 v-if="loading" class="h-3.5 w-3.5 animate-spin" />
              <History v-else class="h-3.5 w-3.5" />
              {{ t.scriptsPage.refresh }}
            </Button>
          </div>
        </div>
      </div>

      <div class="min-h-0 flex-1 overflow-hidden p-3">
        <div :class="cn('grid h-full min-h-0 gap-3', isOwner && debugMode ? 'grid-cols-1' : 'grid-cols-[340px_1fr]')">
          <div v-if="!(isOwner && debugMode)" class="flex min-h-0 flex-col gap-3 overflow-hidden">
            <div class="rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
              <p class="mb-3 inline-flex items-center gap-1 text-xs font-semibold">
                <FileCode2 class="h-3.5 w-3.5 text-muted-foreground" />
                {{ t.scriptsPage.editorInfo }}
              </p>
              <div class="space-y-1.5 text-[11px]">
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><FileCode2 class="h-3 w-3" /></span>
                    {{ t.scriptsPage.formName }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ detail?.name || "-" }}</p>
                </div>
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><User class="h-3 w-3" /></span>
                    {{ t.scriptsPage.colOwner }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ ownerText(detail) }}</p>
                </div>
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><CalendarClock class="h-3 w-3" /></span>
                    {{ t.scriptsPage.colCreated }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ tsText(detail?.create_time) }}</p>
                </div>
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><Tag class="h-3 w-3" /></span>
                    {{ t.scriptsPage.formType }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ detail?.type === 1 ? t.scriptsPage.typePrompt : t.scriptsPage.typeCode }}</p>
                </div>
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><CalendarClock class="h-3 w-3" /></span>
                    {{ t.scriptsPage.editorLastUpdated }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ lastUpdated }}</p>
                </div>
                <div class="grid grid-cols-[88px_minmax(0,1fr)] items-start gap-2">
                  <p class="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                    <span class="text-muted-foreground"><Tag class="h-3 w-3" /></span>
                    {{ t.scriptsPage.editorLatestVersion }}
                  </p>
                  <p class="truncate text-[11px] font-medium">{{ latestVersion }}</p>
                </div>
              </div>
            </div>

            <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
              <p class="mb-3 inline-flex items-center gap-1 text-xs font-semibold">
                <History class="h-3.5 w-3.5 text-muted-foreground" />
                {{ t.scriptsPage.editorVersionHistory }}
              </p>
              <div class="min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
                <p v-if="versions.length === 0" class="px-2 py-3 text-center text-xs text-muted-foreground">{{ t.scriptsPage.editorNoVersion }}</p>
                <template v-else>
                  <Tooltip v-for="v in versions" :key="v.id" :delay-duration="180">
                    <TooltipTrigger as-child>
                      <button
                        type="button"
                        @click="(e: MouseEvent) => handleVersionClick(e, v)"
                        :class="cn(
                          'w-full rounded-md border px-2 py-2 text-left transition-colors',
                          v.id === selectedVersionId ? 'border-primary bg-primary/5' : 'border-border hover:bg-muted/40',
                        )"
                      >
                        <div class="flex items-center justify-between gap-2">
                          <span class="truncate text-xs font-medium">{{ v.version }}</span>
                          <span class="shrink-0 text-[10px] text-muted-foreground">{{ tsText(v.create_time) }}</span>
                        </div>
                        <p class="truncate pt-1 text-[11px] text-muted-foreground">{{ v.change_log || "-" }}</p>
                      </button>
                    </TooltipTrigger>
                    <TooltipContent side="right" align="start" class="max-w-[360px] text-[11px] leading-4">
                      <p class="whitespace-pre-wrap break-words">{{ v.change_log || "-" }}</p>
                      <p v-if="isOwner" class="pt-1 text-muted-foreground">{{ t.scriptsPage.editorDiffHint }}</p>
                    </TooltipContent>
                  </Tooltip>
                </template>
              </div>
            </div>

            <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
              <div class="mb-3 flex items-center justify-between gap-2">
                <p class="inline-flex items-center gap-1 text-xs font-semibold">
                  <UserRound class="h-3.5 w-3.5 text-muted-foreground" />
                  {{ t.scriptsPage.editorSharedUsers }}
                </p>
                <Popover v-if="isOwner" :open="usersOpen" @update:open="(v: boolean) => usersOpen = v">
                  <PopoverTrigger as-child>
                    <Button variant="ghost" size="icon" class="h-6 w-6">
                      <Plus class="h-3.5 w-3.5" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="end" class="w-[260px] p-0">
                    <div class="p-2">
                      <Input
                        class="h-8 text-xs"
                        :placeholder="t.scriptsPage.searchUserPlaceholder"
                        v-model="usersSearch"
                      />
                    </div>
                    <div class="border-t border-border" />
                    <div class="max-h-[220px] overflow-y-auto py-1">
                      <div v-if="usersLoading" class="flex items-center justify-center gap-2 px-3 py-8 text-xs text-muted-foreground">
                        <Loader2 class="h-3.5 w-3.5 animate-spin" />
                        {{ t.common.loading }}
                      </div>
                      <div v-else-if="candidateUsers.length === 0" class="flex flex-col items-center justify-center gap-2 px-3 py-8 text-center text-xs text-muted-foreground">
                        <Inbox class="h-4 w-4" />
                        {{ t.scriptsPage.noUsers }}
                      </div>
                      <template v-else>
                        <button
                          v-for="u in candidateUsers"
                          :key="u.id"
                          type="button"
                          :disabled="allocBusy"
                          @click="handleAlloc(u.id)"
                          class="flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-muted/50"
                        >
                          <span class="h-2.5 w-2.5 shrink-0 rounded-sm bg-blue-500/80" />
                          <span class="flex-1 truncate">{{ u.name || u.username || "-" }}</span>
                        </button>
                      </template>
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
              <div class="min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
                <p v-if="sharedUsers.length === 0" class="px-2 py-3 text-center text-xs text-muted-foreground">{{ t.scriptsPage.editorNoSharedUsers }}</p>
                <template v-else>
                  <div v-for="u in sharedUsers" :key="u.id" class="flex items-center gap-2 rounded-md border border-border px-2 py-2">
                    <span class="inline-flex h-5 w-5 shrink-0 items-center justify-center text-muted-foreground">
                      <UserRound class="h-3.5 w-3.5" />
                    </span>
                    <span class="min-w-0 flex-1 truncate text-xs font-medium text-foreground">{{ u.name || u.username || "-" }}</span>
                    <Button
                      v-if="isOwner"
                      type="button"
                      variant="ghost"
                      size="icon"
                      class="h-6 w-6 text-destructive hover:text-destructive"
                      :disabled="allocBusy"
                      @click="handleRemoveAlloc(u.id)"
                    >
                      <Trash2 class="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </template>
              </div>
            </div>
          </div>

          <div class="flex min-h-0 flex-col overflow-hidden rounded-lg border border-gray-100 bg-white p-3 shadow-sm">
            <div v-if="isOwner && debugMode" class="flex min-h-0 flex-1 flex-col gap-2">
              <div class="flex flex-wrap items-center gap-1 rounded-md border border-border px-2 py-1.5">
                <Button
                  size="sm"
                  :class="cn(
                    'h-7 gap-1 text-[11px] text-white',
                    debugRunning ? 'bg-rose-600 hover:bg-rose-700' : 'bg-sky-600 hover:bg-sky-700',
                  )"
                  @click="debugRunning ? quitDebugSession() : runDebugScript()"
                  :disabled="debugRunning ? !debugCanEnd : !debugCanRun"
                >
                  <Square v-if="debugRunning" class="h-3 w-3 fill-current" />
                  <Play v-else class="h-3 w-3" />
                  {{ debugRunning ? t.scriptsPage.debugTerminate : t.scriptsPage.debugRun }}
                </Button>
                <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="sendDebugCommand('step')" :disabled="!debugCanControl || !debugCapabilities.cmd.includes('step')">{{ t.scriptsPage.debugStep }}</Button>
                <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="sendDebugCommand('next')" :disabled="!debugCanControl || !debugCapabilities.cmd.includes('next')">{{ t.scriptsPage.debugNext }}</Button>
                <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="sendDebugCommand('out')" :disabled="!debugCanControl || !debugCapabilities.cmd.includes('out')">{{ t.scriptsPage.debugOut }}</Button>
                <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="sendDebugCommand('continue')" :disabled="!debugCanControl || !debugCapabilities.cmd.includes('continue')">{{ t.scriptsPage.debugContinue }}</Button>
                <Button variant="outline" size="sm" class="h-7 text-[11px]" @click="quitDebugSession" :disabled="!debugCapabilities.cmd.includes('quit')">{{ t.scriptsPage.debugQuit }}</Button>
                <span :class="cn('ml-1 rounded px-1.5 py-0.5 text-[10px] font-medium', debugWsStatus === 'connected' ? 'bg-emerald-500/15 text-emerald-600' : 'bg-muted text-muted-foreground')">
                  {{ debugWsStatus }}
                </span>
                <span :class="cn('rounded px-1.5 py-0.5 text-[10px] font-medium', debugExecState === 'paused' ? 'bg-amber-500/15 text-amber-700' : debugRunBusy ? 'bg-sky-500/15 text-sky-700' : 'bg-muted text-muted-foreground')">
                  {{ debugStatusText }}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  class="ml-auto h-7 gap-1 text-[11px]"
                  @click="toggleDebugProjection"
                  :disabled="debugWsStatus !== 'connected' || !selectedDebugDevice"
                >
                  <MonitorSmartphone class="h-3.5 w-3.5" />
                  {{ t.scriptsPage.debugProjection }}
                </Button>
              </div>

              <div class="grid min-h-0 flex-1 grid-cols-[minmax(0,2fr)_minmax(0,1fr)] gap-2">
                <div
                  ref="debugLeftSplitRef"
                  class="grid min-h-0 gap-2"
                  :style="{
                    gridTemplateRows: `${
                      debugSourceBlockHeight != null
                        ? `${debugSourceBlockHeight}px`
                        : `minmax(${DEBUG_MIN_SOURCE_BLOCK_HEIGHT}px,1fr)`
                    } ${DEBUG_CONSOLE_ROW_HEIGHT}px minmax(${DEBUG_MIN_OUTPUT_HEIGHT}px,1fr)`,
                  }"
                >
                  <div class="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-md border border-border">
                    <div class="border-b border-border px-2 py-1 text-[11px] text-muted-foreground">{{ t.scriptsPage.debugSource }}</div>
                    <div
                      class="debug-source-monaco min-h-0 overscroll-x-none"
                      @copy.prevent
                      @cut.prevent
                      @dragstart.prevent
                    >
                      <MonacoEditor
                        height="100%"
                        default-language="python"
                        :value="debugSourceLines.join('\n')"
                        @mount="handleDebugSourceMount"
                        :theme="resolvedTheme === 'dark' ? 'vs-dark' : 'light'"
                        :options="{
                          readOnly: true,
                          minimap: { enabled: true },
                          fontSize: 12,
                          lineNumbersMinChars: 4,
                          glyphMargin: true,
                          automaticLayout: true,
                          scrollBeyondLastLine: true,
                          wordWrap: 'off',
                          domReadOnly: true,
                          contextmenu: false,
                          selectOnLineNumbers: false,
                          selectionHighlight: false,
                          occurrencesHighlight: 'off',
                          cursorBlinking: 'hidden' as any,
                          cursorStyle: 'line-thin',
                        }"
                      />
                    </div>
                  </div>

                  <div class="grid min-h-0 grid-cols-[28px_minmax(0,1fr)] items-center rounded-md border border-border bg-muted/20 px-2">
                    <code class="text-xs text-muted-foreground">>>></code>
                    <Input
                      class="h-7 border-0 bg-transparent px-0 font-mono text-xs shadow-none focus-visible:ring-0"
                      :model-value="debugConsoleCode"
                      @update:model-value="(v: string) => debugConsoleCode = v.replace(/[\r\n]/g, '')"
                      @keydown="(e: KeyboardEvent) => { if (e.key !== 'Enter') return; e.preventDefault(); evalDebugConsole(); }"
                      :placeholder="t.scriptsPage.debugConsolePlaceholder"
                      :disabled="!debugCapabilities.eval"
                    />
                  </div>

                  <div
                    :class="cn('min-h-0', debugOutputResizeHot ? 'cursor-row-resize' : undefined)"
                    @mousemove="(e: MouseEvent) => debugOutputResizeHot = isNearOutputTopEdge(e)"
                    @mouseleave="debugOutputResizeHot = false"
                    @mousedown="(e: MouseEvent) => { if (!isNearOutputTopEdge(e)) return; startDebugVerticalResize(e); }"
                    :title="t.scriptsPage.debugResizeHint"
                  >
                    <div class="grid h-full min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-md border border-border">
                      <div class="border-b border-border px-2 py-1 text-[11px] text-muted-foreground">{{ t.scriptsPage.debugOutput }}</div>
                      <div
                        ref="debugOutputScrollRef"
                        :tabindex="0"
                        @scroll="handleDebugOutputScroll"
                        @focus="debugOutputFocused = true"
                        @blur="debugOutputFocused = false"
                        class="min-h-0 overflow-auto bg-muted/20 px-2 py-1.5 font-mono text-[11px] leading-5 focus:outline-none"
                      >
                        <div v-if="debugOutputRows.length === 0" class="flex h-full min-h-[96px] flex-col items-center justify-center gap-1 text-muted-foreground">
                          <Inbox class="h-4 w-4" />
                          <p class="text-[11px]">{{ t.scriptsPage.debugOutputEmpty }}</p>
                        </div>
                        <div v-else class="min-w-full w-max space-y-0.5">
                          <code v-for="(row, idx) in debugOutputRows" :key="`${row.ts}-${idx}`" class="flex items-start gap-2 whitespace-nowrap">
                            <span v-if="row.ts" class="text-zinc-500">{{ row.ts }}</span>
                            <span :class="streamTextOf(row.stream) === 'stderr' ? 'text-red-600' : 'text-zinc-600'">[{{ streamTextOf(row.stream) }}]</span>
                            <span class="text-foreground">{{ row.msg || "" }}</span>
                          </code>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="grid min-h-0 grid-rows-[minmax(0,1fr)_minmax(0,1fr)] gap-2 overflow-hidden">
                  <div class="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-md border border-border">
                    <div class="border-b border-border px-2 py-1 text-[11px] text-muted-foreground">{{ t.scriptsPage.debugLocals }}</div>
                    <div class="min-h-0 overflow-auto px-2 py-1.5 text-[11px]">
                      <div v-if="debugLocalsRaw.length === 0" class="flex h-full min-h-[96px] flex-col items-center justify-center gap-1 text-muted-foreground">
                        <Inbox class="h-4 w-4" />
                        <p class="text-[11px]">{{ t.scriptsPage.debugLocalsEmpty }}</p>
                      </div>
                      <div v-else class="space-y-1">
                        <button
                          v-for="(item, idx) in debugLocalsRaw"
                          :key="`${item.name || '-'}-${idx}`"
                          type="button"
                          class="w-full rounded border border-border/70 bg-muted/20 px-2 py-1 text-left hover:bg-muted/40"
                          @click="evalDebugLocal(item.name || '')"
                        >
                          <div class="grid grid-cols-[minmax(0,1fr)_90px] items-start gap-2">
                            <p class="truncate font-medium">{{ item.name || "-" }}</p>
                            <p class="truncate text-right text-[10px] text-muted-foreground">{{ item.type || "-" }}</p>
                          </div>
                        </button>
                      </div>
                    </div>
                  </div>
                  <div class="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-md border border-border">
                    <div class="border-b border-border px-2 py-1 text-[11px] text-muted-foreground">{{ t.scriptsPage.debugStack }}</div>
                    <div class="min-h-0 overflow-auto px-2 py-1.5 text-[11px]">
                      <div v-if="debugStackRaw.length === 0" class="flex h-full min-h-[96px] flex-col items-center justify-center gap-1 text-muted-foreground">
                        <Inbox class="h-4 w-4" />
                        <p class="text-[11px]">{{ t.scriptsPage.debugStackEmpty }}</p>
                      </div>
                      <div v-else class="space-y-1">
                        <div v-for="(frame, idx) in debugStackRaw" :key="`${frame.filename || '-'}-${frame.lineno || 0}-${idx}`" class="rounded border border-border/70 bg-muted/20 px-2 py-1">
                          <p class="font-medium">{{ frame.function || "-" }}</p>
                          <p class="font-mono text-[10px] text-muted-foreground whitespace-nowrap overflow-x-auto">
                            {{ frame.filename || "-" }}:{{ frame.lineno ?? "-" }}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div
              v-else
              class="min-h-0 flex-1 overflow-hidden overscroll-x-none rounded-md border border-border"
            >
              <template v-if="isOwner">
                <DiffEditor
                  v-if="diffState.enabled"
                  height="100%"
                  :original="diffState.originalCode"
                  :modified="diffState.modifiedCode"
                  language="python"
                  :theme="resolvedTheme === 'dark' ? 'vs-dark' : 'light'"
                  @mount="(editor: any) => diffEditor = editor"
                  :options="{
                    readOnly: true,
                    minimap: { enabled: true },
                    fontSize: 12,
                    lineNumbersMinChars: 4,
                    automaticLayout: true,
                    scrollBeyondLastLine: true,
                    wordWrap: 'off',
                    renderSideBySide: true,
                    useInlineViewWhenSpaceIsLimited: false,
                  }"
                />
                <MonacoEditor
                  v-else
                  height="100%"
                  default-language="python"
                  :value="editorCode"
                  @change="(v: string) => editorCode = v ?? ''"
                  @mount="handleEditorMount"
                  :theme="resolvedTheme === 'dark' ? 'vs-dark' : 'light'"
                  :options="{
                    readOnly: false,
                    minimap: { enabled: true },
                    fontSize: 12,
                    lineNumbersMinChars: 4,
                    automaticLayout: true,
                    scrollBeyondLastLine: true,
                    wordWrap: 'off',
                  }"
                />
              </template>
              <div v-else class="flex h-full items-center justify-center bg-muted/10">
                <div class="flex flex-col items-center gap-2 text-center">
                  <span class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background/80 text-muted-foreground">
                    <ShieldAlert class="h-5 w-5" />
                  </span>
                  <p class="text-xs text-muted-foreground">{{ t.scriptsPage.editorNoPermission }}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <div v-if="debugProjectionOpen" class="pointer-events-none absolute inset-0 z-40">
      <div
        class="pointer-events-auto absolute flex flex-col overflow-hidden rounded-md border border-border bg-card/95 shadow-xl backdrop-blur-sm"
        :style="{
          left: `${debugProjectionRect.x}px`,
          top: `${debugProjectionRect.y}px`,
          width: `${debugProjectionRect.width}px`,
          height: `${debugProjectionRect.height}px`,
        }"
      >
        <div
          class="flex h-8 min-w-0 shrink-0 cursor-move items-center justify-between gap-2 overflow-hidden border-b border-border px-2"
          @pointerdown="startProjectionMove"
        >
          <div class="flex min-w-0 flex-1 items-center gap-2 text-[11px] whitespace-nowrap">
            <MonitorSmartphone class="h-3.5 w-3.5 text-muted-foreground" />
            <span class="truncate font-medium">{{ t.scriptsPage.debugProjection }}</span>
            <span
              :class="cn(
                'shrink-0 rounded px-1 py-0.5 text-[10px]',
                debugProjectionStatus === 'connected'
                  ? 'bg-emerald-500/15 text-emerald-600'
                  : debugProjectionStatus === 'connecting'
                    ? 'bg-sky-500/15 text-sky-700'
                    : 'bg-muted text-muted-foreground',
              )"
            >
              {{ debugProjectionStatus }}
            </span>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            class="h-6 w-6 shrink-0"
            @click="closeDebugProjection(); debugProjectionOpen = false"
          >
            <X class="h-3.5 w-3.5" />
          </Button>
        </div>
        <div ref="debugProjectionViewportRef" class="relative flex min-h-0 flex-1 items-center justify-center bg-black">
          <canvas
            ref="debugProjectionCanvasRef"
            class="touch-none"
            @pointerdown="handleProjectionCanvasPointerDown"
            @pointermove="handleProjectionCanvasPointerMove"
            @pointerup="handleProjectionCanvasPointerUp"
            @pointercancel="handleProjectionCanvasPointerUp"
            @contextmenu.prevent
            :style="{
              width: `${debugProjectionCanvasViewSize.width || 1}px`,
              height: `${debugProjectionCanvasViewSize.height || 1}px`,
            }"
          />
          <div v-if="debugProjectionFrameSize.width <= 0 || debugProjectionFrameSize.height <= 0" class="pointer-events-none absolute inset-0 flex items-center justify-center text-[11px] text-zinc-300">
            {{ t.common.loading }}
          </div>
          <button type="button" class="absolute left-0 top-2 bottom-2 w-2 cursor-ew-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'w')" aria-label="resize-west" />
          <button type="button" class="absolute right-0 top-2 bottom-2 w-2 cursor-ew-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'e')" aria-label="resize-east" />
          <button type="button" class="absolute left-2 right-2 top-0 h-2 cursor-ns-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'n')" aria-label="resize-north" />
          <button type="button" class="absolute left-2 right-2 bottom-0 h-2 cursor-ns-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 's')" aria-label="resize-south" />
          <button type="button" class="absolute left-0 top-0 h-3 w-3 cursor-nwse-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'nw')" aria-label="resize-nw" />
          <button type="button" class="absolute right-0 top-0 h-3 w-3 cursor-nesw-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'ne')" aria-label="resize-ne" />
          <button type="button" class="absolute left-0 bottom-0 h-3 w-3 cursor-nesw-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'sw')" aria-label="resize-sw" />
          <button type="button" class="absolute right-0 bottom-0 h-3 w-3 cursor-nwse-resize bg-transparent" @pointerdown="(e: PointerEvent) => startProjectionResize(e, 'se')" aria-label="resize-se" />
        </div>
        <div class="grid h-8 shrink-0 grid-cols-3 border-t border-border">
          <Button
            type="button"
            variant="ghost"
            class="h-full w-full rounded-none"
            @click="sendProjectionCommand('device/input/key', [0, 'back'])"
          >
            <ChevronLeft class="h-4 w-4" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            class="h-full w-full rounded-none border-x border-border"
            @click="sendProjectionCommand('device/input/key', [0, 'home'])"
          >
            <svg
              class="h-3.5 w-3.5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <path d="M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
            </svg>
          </Button>
          <Button
            type="button"
            variant="ghost"
            class="h-full w-full rounded-none"
            @click="sendProjectionCommand('device/input/keycode', [0, 187])"
          >
            <Menu class="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </div>

    <Dialog :open="debugDialogOpen" @update:open="(v: boolean) => debugDialogOpen = v">
      <DialogContent class="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{{ t.scriptsPage.editorDebugConfigTitle }}</DialogTitle>
        </DialogHeader>
        <div class="space-y-4">
          <div v-if="isHybridScript" class="space-y-1">
            <p class="text-xs font-medium">{{ t.scriptsPage.editorDebugModel }}</p>
            <Select :model-value="debugModelId || undefined" @update:model-value="(v: string) => debugModelId = v">
              <SelectTrigger class="h-8 w-full text-xs">
                <SelectValue :placeholder="debugModelsLoading ? t.common.loading : t.scriptsPage.editorDebugSelectModel" />
              </SelectTrigger>
              <SelectContent>
                <div v-if="debugModels.length === 0" class="flex flex-col items-center justify-center gap-2 px-3 py-6 text-center text-xs text-muted-foreground">
                  <Inbox class="h-4 w-4" />
                  {{ t.jobsPage.executeNoModels }}
                </div>
                <template v-else>
                  <SelectItem v-for="m in debugModels" :key="m.id" :value="m.id">
                    {{ m.label }}
                  </SelectItem>
                </template>
              </SelectContent>
            </Select>
          </div>

          <div v-if="debugParams.length > 0" class="space-y-2">
            <p class="text-xs font-medium">{{ t.scriptsPage.editorDebugParams }}</p>
            <div class="max-h-[320px] space-y-2 overflow-y-auto pr-1">
              <div v-for="param in debugParams" :key="debugParamName(param)" class="rounded-md border border-border/70 bg-muted/20 p-2">
                <div class="grid grid-cols-[180px_minmax(0,1fr)] items-start gap-3">
                  <div class="min-w-0">
                    <p class="truncate text-xs font-medium text-foreground">{{ debugParamName(param) }}</p>
                    <p class="pt-0.5 text-[11px] leading-4 text-muted-foreground">
                      {{ param.description || `Type: ${debugParamType(param)}` }}
                    </p>
                  </div>
                  <div class="min-w-0">
                    <Textarea
                      v-if="isJsonParamType(debugParamType(param))"
                      class="min-h-16 text-xs"
                      :model-value="debugParamInputs[debugParamName(param)] ?? ''"
                      @update:model-value="(v: string) => debugParamInputs[debugParamName(param)] = v"
                      :placeholder='debugParamType(param) === "list" ? "[\"a\", 1]" : "{\"k\": \"v\"}"'
                    />
                    <Input
                      v-else
                      class="h-8 text-xs"
                      :model-value="debugParamInputs[debugParamName(param)] ?? ''"
                      @update:model-value="(v: string) => debugParamInputs[debugParamName(param)] = v"
                      :placeholder="`${debugParamName(param)} (${debugParamType(param)})`"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <p v-if="!isHybridScript && debugParams.length === 0" class="text-xs text-muted-foreground">{{ t.scriptsPage.editorDebugNoConfigRequired }}</p>
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" class="h-8 text-xs" @click="debugDialogOpen = false">
            {{ t.scriptsPage.cancel }}
          </Button>
          <Button size="sm" class="h-8 gap-1 text-xs" @click="confirmDebugConfig">
            <Bug class="h-3.5 w-3.5" />
            {{ t.scriptsPage.editorDebugConfirm }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="publishOpen" @update:open="(v: boolean) => publishOpen = v">
      <DialogContent class="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{{ t.scriptsPage.editorPublishTitle }}</DialogTitle>
        </DialogHeader>
        <div class="space-y-3">
          <div class="space-y-1">
            <p class="text-xs font-medium">{{ t.scriptsPage.editorVersion }}</p>
            <Input
              class="h-8 text-xs"
              v-model="publishVersion"
              :maxlength="VERSION_LEN_MAX"
              :placeholder="t.scriptsPage.editorVersionPlaceholder"
            />
          </div>

          <div class="space-y-1">
            <p class="text-xs font-medium">{{ t.scriptsPage.editorChangeLog }}</p>
            <Textarea
              class="min-h-24 text-xs"
              v-model="publishChangeLog"
              :placeholder="t.scriptsPage.editorChangeLogPlaceholder"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" class="h-8 text-xs" @click="publishOpen = false">
            {{ t.scriptsPage.cancel }}
          </Button>
          <Button size="sm" class="h-8 gap-1.5 text-xs" @click="handlePublish()" :disabled="publishing">
            <Loader2 v-if="publishing" class="h-3.5 w-3.5 animate-spin" />
            {{ t.scriptsPage.editorPublish }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <AlertDialog
      :open="unsavedDialogOpen"
      @update:open="onUnsavedDialogOpenChange"
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{{ t.scriptsPage.editorUnsavedTitle }}</AlertDialogTitle>
          <AlertDialogDescription>{{ t.scriptsPage.editorUnsavedDescription }}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{{ t.scriptsPage.cancel }}</AlertDialogCancel>
          <Button variant="outline" @click="continuePending('save')">
            {{ t.scriptsPage.editorSaveDraftAndContinue }}
          </Button>
          <AlertDialogAction
            class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            @click="continuePending('discard')"
          >
            {{ t.scriptsPage.editorDiscardAndContinue }}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>

<style>
.debug-source-active-line {
  background: rgba(245, 158, 11, 0.22) !important;
}
.debug-source-active-gutter {
  border-left: 2px solid rgba(245, 158, 11, 0.95);
}
.debug-source-current-glyph {
  background: rgba(245, 158, 11, 0.95);
  width: 6px !important;
  height: 18px !important;
  border-radius: 2px;
  margin-left: 8px;
  margin-top: 2px;
}
.debug-source-breakpoint-glyph {
  background: #ef4444;
  width: 8px !important;
  height: 8px !important;
  border-radius: 9999px;
  margin-left: 6px;
  margin-top: 4px;
}
.debug-source-monaco .view-lines,
.debug-source-monaco .view-line,
.debug-source-monaco .monaco-editor .inputarea {
  user-select: none !important;
  -webkit-user-select: none !important;
}
.debug-source-monaco .cursors-layer {
  display: none !important;
}
.monaco-editor,
.monaco-editor .monaco-scrollable-element,
.monaco-diff-editor {
  overscroll-behavior-x: none;
}
</style>
