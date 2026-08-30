<script setup lang="ts">
import { computed, ref, watch } from "vue";
import {
  Blocks,
  ChevronsUpDown,
  Gauge,
  Inbox,
  Play,
  Plus,
  RotateCw,
  Search,
  SlidersHorizontal,
  Trash2,
} from "lucide-vue-next";
import { Button } from "@/components/ui/button";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { DateTimePicker } from "@/components/ui/datetime-picker";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type Mode = "loop" | "count" | "per-device-count" | "deadline" | "crontab";
type ParamSource = "native" | "queue" | "callback";
type CronPartKey = "minute" | "hour" | "dayOfMonth" | "month" | "dayOfWeek";

type GroupOption = { id: string; name: string; count: number; color: string };
type ScriptOption = { id: string; name: string; type?: unknown };
type VersionOption = { id: string; label: string };
type ModelOption = { id: string; label: string };
type ScriptParam = { name: string; type?: string; description?: string };
type HeaderKV = { key: string; value: string };

const CRON_PART_CONFIG: Array<{ key: CronPartKey; min: number; max: number }> = [
  { key: "minute", min: 0, max: 59 },
  { key: "hour", min: 0, max: 23 },
  { key: "dayOfMonth", min: 1, max: 31 },
  { key: "month", min: 1, max: 12 },
  { key: "dayOfWeek", min: 0, max: 7 },
];

function autoName() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const yy = String(d.getFullYear()).slice(2);
  const rand = String(Math.floor(Math.random() * 10000)).padStart(4, "0");
  return `auto-${yy}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}-${pad(d.getHours())}-${pad(d.getMinutes())}-${rand}`;
}

function parseList<T>(data: any): T[] {
  if (Array.isArray(data)) return data as T[];
  if (Array.isArray(data?.data)) return data.data as T[];
  if (Array.isArray(data?.data?.data)) return data.data.data as T[];
  return [];
}

function parseScriptParams(raw: any): ScriptParam[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw as ScriptParam[];
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function normalizeParamType(raw?: string): "string" | "integer" | "float" | "boolean" | "list" | "object" {
  const t = String(raw || "").toLowerCase();
  if (["int", "integer"].includes(t)) return "integer";
  if (["float", "number"].includes(t)) return "float";
  if (["bool", "boolean"].includes(t)) return "boolean";
  if (["list", "array"].includes(t)) return "list";
  if (["object", "dict"].includes(t)) return "object";
  return "string";
}

function pickParamSource(raw: any) {
  return raw?.entry?.params ?? raw?.params ?? raw?.entry?.arguments ?? raw?.arguments ?? raw?.entry?.args ?? raw?.args;
}

function isValidHttpUrl(raw: string) {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidHeaderKey(key: string) {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(key);
}

function isHybridScriptType(raw: unknown) {
  if (raw === null || raw === undefined) return false;
  if (typeof raw === "number") return raw === 1;
  const text = String(raw).trim().toLowerCase();
  return text === "1" || text === "prompt" || text === "mixed" || text === "hybrid";
}

function generateQueueToken16() {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 16; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

type FormState = {
  name: string;
  description: string;
  groupId: string;
  scriptId: string;
  versionId: string;
  mode: Mode;
  count: number;
  endAt: string;
  interval: number;
  retries: number;
  softTimeout: number;
  hardTimeout: number;
  foreground: boolean;
  ignoreResult: boolean;
  priority: number;
  paramSource: ParamSource;
  modelId: string;
};

const props = withDefaults(
  defineProps<{
    onCancel?: () => void;
    onSuccess?: () => void;
    className?: string;
    compact?: boolean;
  }>(),
  { compact: false },
);

const { t } = useTranslation();

const labelClass = computed(() => (props.compact ? "text-xs" : ""));
const descClass = computed(() => (props.compact ? "text-[11px]" : ""));
const inputClass = computed(() => (props.compact ? "h-8 text-xs" : ""));
const selectTriggerClass = computed(() => (props.compact ? "h-8 text-xs" : ""));
const textareaClass = computed(() => (props.compact ? "min-h-14 text-xs" : ""));
const sectionClass = computed(() =>
  props.compact ? "rounded-md border border-border bg-card p-3" : "rounded-lg border border-border bg-card p-4",
);
const sectionTitleClass = computed(() => (props.compact ? "text-xs font-medium" : "text-sm font-semibold"));
const sectionIconClass = computed(() =>
  props.compact ? "h-3.5 w-3.5 text-muted-foreground" : "h-4 w-4 text-muted-foreground",
);

const form = ref<FormState>({
  name: autoName(),
  description: "",
  groupId: "",
  scriptId: "",
  versionId: "",
  mode: "loop",
  count: 0,
  endAt: "",
  interval: 0,
  retries: 0,
  softTimeout: 600,
  hardTimeout: 600,
  foreground: true,
  ignoreResult: false,
  priority: 50,
  paramSource: "native",
  modelId: "",
});

const groups = ref<GroupOption[]>([]);
const scripts = ref<ScriptOption[]>([]);
const versions = ref<VersionOption[]>([]);
const models = ref<ModelOption[]>([]);
const params = ref<ScriptParam[]>([]);
const paramInputs = ref<Record<string, any>>({});
const httpUrl = ref("");
const httpCallback = ref("");
const queueToken = ref("");
const httpHeaders = ref<HeaderKV[]>([]);
const loading = ref(false);
const loadingVersions = ref(false);
const groupLoading = ref(false);
const scriptLoading = ref(false);
const groupPickerOpen = ref(false);
const scriptPickerOpen = ref(false);
const groupSearch = ref("");
const scriptSearch = ref("");
const selectedGroupMeta = ref<{ name: string; color: string; count: number } | null>(null);
const selectedScriptName = ref("");
const selectedScriptType = ref<unknown>(undefined);
const miniTip = ref<{ id: number; text: string } | null>(null);
const cronParts = ref<Record<CronPartKey, string>>({
  minute: "*",
  hour: "*",
  dayOfMonth: "*",
  month: "*",
  dayOfWeek: "*",
});
const groupReqRef = ref(0);
const scriptReqRef = ref(0);

const selectedScript = computed(() => scripts.value.find((s) => s.id === form.value.scriptId));
const selectedGroup = computed(() => groups.value.find((g) => g.id === form.value.groupId));
const isPromptScript = computed(() => isHybridScriptType(selectedScriptType.value ?? selectedScript.value?.type));
const hasNativeParams = computed(() => params.value.length > 0);
const isCrontabMode = computed(() => form.value.mode === "crontab");

const update = <K extends keyof FormState>(key: K, value: FormState[K]) => {
  form.value = { ...form.value, [key]: value };
};
const updateCronPart = (key: CronPartKey, value: string) => {
  cronParts.value = { ...cronParts.value, [key]: value };
};
const showMiniTip = (text: string) => {
  miniTip.value = { id: Date.now() + Math.random(), text };
};
const addHeader = () => {
  httpHeaders.value = [...httpHeaders.value, { key: "", value: "" }];
};
const removeHeader = (idx: number) => {
  httpHeaders.value = httpHeaders.value.filter((_, i) => i !== idx);
};
const updateHeader = (idx: number, key: "key" | "value", value: string) => {
  httpHeaders.value = httpHeaders.value.map((h, i) => (i === idx ? { ...h, [key]: value } : h));
};
const setParamInput = (name: string, value: any) => {
  paramInputs.value = { ...paramInputs.value, [name]: value };
};

const buildValidatedHeaders = (): Record<string, string> | null => {
  const headers: Record<string, string> = {};
  const seen = new Set<string>();
  for (let i = 0; i < httpHeaders.value.length; i += 1) {
    const k = httpHeaders.value[i].key.trim();
    const v = httpHeaders.value[i].value.trim();
    if (!k && !v) continue;
    if (!k) return showMiniTip(t.value.jobsPage.executeHeaderMissing.replace("{row}", String(i + 1))), null;
    if (!isValidHeaderKey(k))
      return showMiniTip(t.value.jobsPage.executeHeaderInvalidKey.replace("{row}", String(i + 1))), null;
    if (v.includes("\n") || v.includes("\r"))
      return showMiniTip(t.value.jobsPage.executeHeaderInvalidValue.replace("{row}", String(i + 1))), null;
    const low = k.toLowerCase();
    if (seen.has(low))
      return showMiniTip(t.value.jobsPage.executeHeaderDuplicate.replace("{row}", String(i + 1))), null;
    seen.add(low);
    headers[k] = v;
  }
  return headers;
};

const buildParams = (): { param_source: ParamSource; params: Record<string, any>; model_id?: number } | null => {
  if (isPromptScript.value) {
    const id = Number(form.value.modelId || 0);
    if (!id) return showMiniTip(t.value.jobsPage.executeModelRequired), null;
  }
  if (form.value.paramSource === "queue") {
    const token = queueToken.value.trim();
    if (token.length < 12 || token.length > 32)
      return showMiniTip(t.value.jobsPage.executeParamTokenLengthInvalid), null;
    const callback = httpCallback.value.trim();
    if (callback && !isValidHttpUrl(callback))
      return showMiniTip(t.value.jobsPage.executeParamCallbackInvalid), null;
    const headers = buildValidatedHeaders();
    if (!headers) return null;
    return {
      param_source: "queue",
      params: { token, callback: callback || null, headers },
      model_id: isPromptScript.value ? Number(form.value.modelId || 0) : undefined,
    };
  }
  if (form.value.paramSource === "callback") {
    const url = httpUrl.value.trim();
    if (!url) return showMiniTip(t.value.jobsPage.executeParamUrlRequired), null;
    if (!isValidHttpUrl(url)) return showMiniTip(t.value.jobsPage.executeParamUrlInvalid), null;
    const callback = httpCallback.value.trim();
    if (callback && !isValidHttpUrl(callback))
      return showMiniTip(t.value.jobsPage.executeParamCallbackInvalid), null;
    const headers = buildValidatedHeaders();
    if (!headers) return null;
    return {
      param_source: "callback",
      params: { url, callback: callback || null, headers },
      model_id: isPromptScript.value ? Number(form.value.modelId || 0) : undefined,
    };
  }
  if (!hasNativeParams.value) {
    return {
      param_source: "native",
      params: {},
      model_id: isPromptScript.value ? Number(form.value.modelId || 0) : undefined,
    };
  }
  const out: Record<string, any> = {};
  for (let idx = 0; idx < params.value.length; idx += 1) {
    const p = params.value[idx];
    const name = p.name;
    const paramType = normalizeParamType(p.type);
    const raw = paramInputs.value[name];
    const empty = raw === undefined || raw === null || (typeof raw === "string" && raw.trim() === "");
    if (empty) {
      showMiniTip(t.value.jobsPage.executeParamRequired.replace("{name}", name));
      return null;
    }
    if (paramType === "boolean") {
      if (typeof raw === "boolean") out[name] = raw;
      else if (typeof raw === "string") {
        const low = raw.trim().toLowerCase();
        if (["true", "1", "yes", "y"].includes(low)) out[name] = true;
        else if (["false", "0", "no", "n"].includes(low)) out[name] = false;
        else return showMiniTip(t.value.jobsPage.executeParamBooleanInvalid.replace("{name}", name)), null;
      } else return showMiniTip(t.value.jobsPage.executeParamBooleanInvalid.replace("{name}", name)), null;
    } else if (paramType === "integer") {
      const n = Number(raw);
      if (!Number.isInteger(n))
        return showMiniTip(t.value.jobsPage.executeParamIntegerInvalid.replace("{name}", name)), null;
      out[name] = n;
    } else if (paramType === "float") {
      const n = Number(raw);
      if (!Number.isFinite(n))
        return showMiniTip(t.value.jobsPage.executeParamFloatInvalid.replace("{name}", name)), null;
      out[name] = n;
    } else if (paramType === "list") {
      try {
        const j = JSON.parse(String(raw));
        if (!Array.isArray(j)) throw new Error("bad");
        out[name] = j;
      } catch {
        return showMiniTip(t.value.jobsPage.executeParamListInvalid.replace("{name}", name)), null;
      }
    } else if (paramType === "object") {
      try {
        const j = JSON.parse(String(raw));
        if (!j || typeof j !== "object" || Array.isArray(j)) throw new Error("bad");
        out[name] = j;
      } catch {
        return showMiniTip(t.value.jobsPage.executeParamObjectInvalid.replace("{name}", name)), null;
      }
    } else out[name] = String(raw);
  }
  return {
    param_source: "native",
    params: out,
    model_id: isPromptScript.value ? Number(form.value.modelId || 0) : undefined,
  };
};

const getCronPartLabel = (key: CronPartKey) => {
  switch (key) {
    case "minute":
      return t.value.jobsPage.executeCrontabMinute;
    case "hour":
      return t.value.jobsPage.executeCrontabHour;
    case "dayOfMonth":
      return t.value.jobsPage.executeCrontabDayOfMonth;
    case "month":
      return t.value.jobsPage.executeCrontabMonth;
    case "dayOfWeek":
      return t.value.jobsPage.executeCrontabDayOfWeek;
    default:
      return key;
  }
};

const validateCronPart = (raw: string, key: CronPartKey, min: number, max: number): string | null => {
  const value = raw.trim();
  if (!value) return t.value.jobsPage.executeCrontabPartRequired.replace("{field}", getCronPartLabel(key));
  if (!/^[0-9*\/,\-]+$/.test(value)) {
    return t.value.jobsPage.executeCrontabPartInvalidChars.replace("{field}", getCronPartLabel(key));
  }
  const atoms = value.split(",");
  for (const atomRaw of atoms) {
    const atom = atomRaw.trim();
    if (!atom) return t.value.jobsPage.executeCrontabPartInvalid.replace("{field}", getCronPartLabel(key));
    const parts = atom.split("/");
    if (parts.length > 2 || parts.length === 0) {
      return t.value.jobsPage.executeCrontabPartInvalid.replace("{field}", getCronPartLabel(key));
    }
    const base = parts[0];
    const step = parts[1];
    if (step !== undefined) {
      if (!/^\d+$/.test(step) || Number(step) <= 0) {
        return t.value.jobsPage.executeCrontabPartInvalid.replace("{field}", getCronPartLabel(key));
      }
    }
    if (base === "*") continue;
    if (/^\d+$/.test(base)) {
      const n = Number(base);
      if (n < min || n > max) {
        return t.value.jobsPage.executeCrontabPartOutOfRange
          .replace("{field}", getCronPartLabel(key))
          .replace("{min}", String(min))
          .replace("{max}", String(max));
      }
      continue;
    }
    if (/^\d+-\d+$/.test(base)) {
      const [aStr, bStr] = base.split("-");
      const a = Number(aStr);
      const b = Number(bStr);
      if (a > b || a < min || b > max) {
        return t.value.jobsPage.executeCrontabPartOutOfRange
          .replace("{field}", getCronPartLabel(key))
          .replace("{min}", String(min))
          .replace("{max}", String(max));
      }
      continue;
    }
    return t.value.jobsPage.executeCrontabPartInvalid.replace("{field}", getCronPartLabel(key));
  }
  return null;
};

const loadGroupOptions = async (keyword: string) => {
  const reqId = ++groupReqRef.value;
  groupLoading.value = true;
  try {
    const query = new URLSearchParams();
    query.set("page", "1");
    query.set("size", "20");
    query.set("sort", "order");
    query.set("order", "asc");
    const q = keyword.trim();
    if (q) {
      query.set("filter", JSON.stringify([{ field: "name", op: "like", value: q }]));
    }
    const resp = await apiRequest<any>(`/api/v1/group?${query.toString()}`, { cache: "no-store" });
    if (reqId !== groupReqRef.value) return;
    const list = parseList<any>(resp.data)
      .map((x, idx) => ({
        id: String(x?.id ?? ""),
        name: String(x?.name || ""),
        count: Number(x?.count ?? x?.total ?? 0),
        color: String(x?.color || ["#22c55e", "#3b82f6", "#f59e0b", "#a855f7", "#06b6d4"][idx % 5]),
      }))
      .filter((x) => x.id && x.name);
    groups.value = list;
  } catch {
    if (reqId !== groupReqRef.value) return;
    groups.value = [];
  } finally {
    if (reqId === groupReqRef.value) groupLoading.value = false;
  }
};

const loadScriptOptions = async (keyword: string) => {
  const reqId = ++scriptReqRef.value;
  scriptLoading.value = true;
  try {
    const query = new URLSearchParams();
    query.set("page", "1");
    query.set("size", "20");
    query.set("sort", "id");
    query.set("order", "desc");
    const q = keyword.trim();
    if (q) {
      query.set("filter", JSON.stringify([{ field: "name", op: "like", value: q }]));
    }
    const resp = await apiRequest<any>(`/api/v1/script?${query.toString()}`, { cache: "no-store" });
    if (reqId !== scriptReqRef.value) return;
    const list = parseList<any>(resp.data)
      .map((x) => ({
        id: String(x?.id ?? ""),
        name: String(x?.name || ""),
        type: x?.type,
      }))
      .filter((x) => x.id && x.name);
    scripts.value = list;
  } catch {
    if (reqId !== scriptReqRef.value) return;
    scripts.value = [];
  } finally {
    if (reqId === scriptReqRef.value) scriptLoading.value = false;
  }
};

watch(
  [() => form.value.groupId, selectedGroup],
  () => {
    if (!form.value.groupId) {
      selectedGroupMeta.value = null;
      return;
    }
    if (selectedGroup.value) {
      selectedGroupMeta.value = {
        name: selectedGroup.value.name,
        color: selectedGroup.value.color,
        count: selectedGroup.value.count,
      };
    }
  },
  { immediate: true },
);

watch(
  [() => form.value.scriptId, selectedScript],
  () => {
    if (!form.value.scriptId) {
      selectedScriptName.value = "";
      return;
    }
    if (selectedScript.value?.name) {
      selectedScriptName.value = selectedScript.value.name;
    }
  },
  { immediate: true },
);

watch(
  () => t.value.jobsPage.executeInitFailed,
  (_value, _oldValue, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const loadInit = async () => {
      try {
        const modelRes = await apiRequest<any>("/api/v1/model?page=1&size=200&sort=id&order=desc", {
          cache: "no-store",
        });
        if (cancelled) return;
        const modelList = parseList<any>(modelRes.data)
          .map((x) => ({
            id: String(x?.id ?? ""),
            label: String(x?.name || x?.model || `#${x?.id ?? ""}`),
          }))
          .filter((x) => x.id);
        models.value = modelList;
      } catch {
        if (!cancelled) showMiniTip(t.value.jobsPage.executeInitFailed);
      }
    };
    void loadInit();
  },
  { immediate: true },
);

watch([groupPickerOpen, groupSearch], (_value, _oldValue, onCleanup) => {
  if (!groupPickerOpen.value) return;
  const timer = window.setTimeout(() => {
    void loadGroupOptions(groupSearch.value);
  }, 200);
  onCleanup(() => window.clearTimeout(timer));
});

watch([scriptPickerOpen, scriptSearch], (_value, _oldValue, onCleanup) => {
  if (!scriptPickerOpen.value) return;
  const timer = window.setTimeout(() => {
    void loadScriptOptions(scriptSearch.value);
  }, 200);
  onCleanup(() => window.clearTimeout(timer));
});

watch(
  () => form.value.scriptId,
  (_value, _oldValue, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const loadScriptDetail = async () => {
      if (!form.value.scriptId) {
        versions.value = [];
        params.value = [];
        paramInputs.value = {};
        selectedScriptType.value = undefined;
        selectedScriptName.value = "";
        form.value = { ...form.value, versionId: "", modelId: "" };
        return;
      }
      loadingVersions.value = true;
      try {
        const detailRes = await apiRequest<any>(`/api/v1/script/${encodeURIComponent(form.value.scriptId)}`, {
          cache: "no-store",
        });
        if (cancelled) return;
        const detail = detailRes.data || {};
        if (detail?.name) {
          selectedScriptName.value = String(detail.name);
        }
        if (detail?.type !== undefined && detail?.type !== null) {
          selectedScriptType.value = detail.type;
        }
        const v = Array.isArray(detail?.versions) ? detail.versions : [];
        const sorted = [...v].sort((a: any, b: any) => Number(b?.id || 0) - Number(a?.id || 0));
        versions.value = sorted
          .map((item: any) => ({
            id: String(item?.id ?? ""),
            label: String(item?.version || `#${item?.id ?? ""}`),
          }))
          .filter((item: VersionOption) => item.id);
        const p = pickParamSource(detail);
        const parsed = parseScriptParams(p);
        const normalized = parsed
          .map((x) => ({ name: String(x?.name || "").trim(), type: x?.type, description: x?.description }))
          .filter((x) => x.name);
        params.value = normalized;
        const next: Record<string, any> = {};
        for (const it of normalized) {
          if (paramInputs.value[it.name] !== undefined) next[it.name] = paramInputs.value[it.name];
          else next[it.name] = "";
        }
        paramInputs.value = next;
      } catch {
        if (!cancelled) {
          versions.value = [];
          params.value = [];
          paramInputs.value = {};
        }
      } finally {
        if (!cancelled) loadingVersions.value = false;
      }
    };
    void loadScriptDetail();
  },
  { immediate: true },
);

watch(
  [() => form.value.scriptId, () => form.value.versionId],
  (_value, _oldValue, onCleanup) => {
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const loadVersionParams = async () => {
      if (!form.value.scriptId || !form.value.versionId) return;
      try {
        const res = await apiRequest<any>(
          `/api/v1/script/${encodeURIComponent(form.value.scriptId)}/${encodeURIComponent(form.value.versionId)}`,
          {
            cache: "no-store",
          },
        );
        if (cancelled) return;
        const data = res.data || {};
        const src = pickParamSource(data);
        if (src === undefined || src === null) return;
        const parsed = parseScriptParams(src);
        const normalized = parsed
          .map((x) => ({ name: String(x?.name || "").trim(), type: x?.type, description: x?.description }))
          .filter((x) => x.name);
        params.value = normalized;
        const next: Record<string, any> = {};
        for (const it of normalized) {
          if (paramInputs.value[it.name] !== undefined) next[it.name] = paramInputs.value[it.name];
          else next[it.name] = "";
        }
        paramInputs.value = next;
      } catch {
        // ignore
      }
    };
    void loadVersionParams();
  },
  { immediate: true },
);

watch(
  [() => form.value.mode, () => form.value.endAt],
  () => {
    if (form.value.mode === "deadline" && !form.value.endAt) {
      const d = new Date(Date.now() + 2 * 60 * 1000);
      const local = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}T${String(
        d.getHours(),
      ).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
      form.value = { ...form.value, endAt: local };
    }
  },
  { immediate: true },
);

watch(
  isCrontabMode,
  () => {
    if (!isCrontabMode.value) return;
    if (form.value.interval === 0 && form.value.priority === 50) return;
    form.value = { ...form.value, interval: 0, priority: 50 };
  },
  { immediate: true },
);

watch(
  [() => form.value.hardTimeout, () => form.value.softTimeout],
  () => {
    if (form.value.softTimeout > form.value.hardTimeout) {
      form.value = { ...form.value, softTimeout: Math.max(0, form.value.hardTimeout) };
    }
  },
  { immediate: true },
);

watch(
  () => form.value.paramSource,
  () => {
    if (form.value.paramSource !== "queue") return;
    if (!queueToken.value) queueToken.value = generateQueueToken16();
  },
  { immediate: true },
);

const onGroupPickerOpenChange = (open: boolean) => {
  groupPickerOpen.value = open;
  if (!open) groupSearch.value = "";
};

const onScriptPickerOpenChange = (open: boolean) => {
  scriptPickerOpen.value = open;
  if (!open) scriptSearch.value = "";
};

const selectGroup = (group: GroupOption) => {
  update("groupId", group.id);
  selectedGroupMeta.value = { name: group.name, color: group.color, count: group.count };
  groupPickerOpen.value = false;
  groupSearch.value = "";
};

const selectScript = (script: ScriptOption) => {
  update("scriptId", script.id);
  selectedScriptName.value = script.name;
  selectedScriptType.value = script.type;
  scriptPickerOpen.value = false;
  scriptSearch.value = "";
};

const onModeChange = (v: string) => update("mode", v as Mode);
const onParamSourceChange = (v: string) => update("paramSource", v as ParamSource);

const onSubmit = async () => {
  miniTip.value = null;
  const name = form.value.name.trim();
  if (!name) return showMiniTip(t.value.jobsPage.executeNameRequired);
  if (!form.value.groupId) return showMiniTip(t.value.jobsPage.executeGroupRequired);
  if (!form.value.scriptId) return showMiniTip(t.value.jobsPage.executeScriptRequired);
  if (!form.value.versionId) return showMiniTip(t.value.jobsPage.executeVersionRequired);

  let payloadCount = 0;
  let payloadCrontab = "";
  if (form.value.mode === "count" || form.value.mode === "per-device-count") {
    const c = Number(form.value.count || 0);
    if (c <= 0) return showMiniTip(t.value.jobsPage.executeCountInvalidMin);
    if (c > 100000) return showMiniTip(t.value.jobsPage.executeCountInvalidMax);
    payloadCount = Math.floor(c);
  } else if (form.value.mode === "deadline") {
    const ts = Math.floor(new Date(form.value.endAt).getTime() / 1000);
    const now = Math.floor(Date.now() / 1000);
    const diff = ts - now;
    if (!ts || Number.isNaN(ts)) return showMiniTip(t.value.jobsPage.executeEndTimeRequired);
    if (diff <= 0) return showMiniTip(t.value.jobsPage.executeEndTimeAfterNow);
    if (diff < 120) return showMiniTip(t.value.jobsPage.executeEndTimeMinGap);
    payloadCount = diff;
  } else if (form.value.mode === "crontab") {
    for (const item of CRON_PART_CONFIG) {
      const msg = validateCronPart(cronParts.value[item.key], item.key, item.min, item.max);
      if (msg) return showMiniTip(msg);
    }
    payloadCrontab = CRON_PART_CONFIG.map((item) => cronParts.value[item.key].trim()).join(" ");
  }
  const hard = Number(form.value.hardTimeout || 0);
  const soft = Number(form.value.softTimeout || 0);
  if (soft > hard) return showMiniTip(t.value.jobsPage.executeValidationTimeout);
  const paramsObj = buildParams();
  if (!paramsObj) return;

  const payload: Record<string, any> = {
    name,
    description: form.value.description.trim(),
    script_id: form.value.scriptId,
    script_version_id: form.value.versionId,
    mode: form.value.mode,
    count: payloadCount,
    crontab: payloadCrontab,
    interval: isCrontabMode.value ? 0 : Math.max(0, Number(form.value.interval) || 0),
    retries: Math.max(0, Number(form.value.retries) || 0),
    time_limit: Math.max(0, hard || 600),
    soft_time_limit: Math.max(0, soft || 600),
    foreground: form.value.foreground ? 1 : 0,
    ignore_result: form.value.ignoreResult ? 1 : 0,
    priority: isCrontabMode.value ? 50 : Math.min(100, Math.max(1, Math.round(Number(form.value.priority) || 50))),
    group_id: form.value.groupId,
    param_source: paramsObj.param_source,
    params: JSON.stringify(paramsObj.params || {}),
  };
  if (paramsObj.model_id) payload.model_id = paramsObj.model_id;

  loading.value = true;
  try {
    await apiRequest("/api/v1/job", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(payload as Record<string, string>).toString(),
      errorMessage: t.value.jobsPage.executeFailed,
    });
    props.onSuccess?.();
  } catch (error) {
    showMiniTip(formatApiError(error, t.value.jobsPage.executeFailed));
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <div :class="cn('relative flex min-h-0 flex-1 flex-col', className)">
    <div :class="cn('flex-1 overflow-y-auto', compact ? 'px-4 py-4' : 'px-6 py-6')">
      <div :class="cn('mx-auto', compact ? 'max-w-none space-y-3' : 'max-w-5xl space-y-4')">
        <div :class="sectionClass">
          <div class="mb-3 flex items-center gap-2">
            <Blocks :class="sectionIconClass" />
            <p :class="sectionTitleClass">{{ t.jobsPage.executeTitle }}</p>
          </div>
          <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeJobName }} <span class="text-destructive">*</span></FieldLabel>
              <Input :class="inputClass" :model-value="form.name" @update:model-value="update('name', $event)" />
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeDeviceGroup }} <span class="text-destructive">*</span></FieldLabel>
              <Popover :open="groupPickerOpen" @update:open="onGroupPickerOpenChange">
                <PopoverTrigger as-child>
                  <Button
                    type="button"
                    variant="outline"
                    :class="cn('w-full justify-between', compact ? 'h-8 px-2.5 text-xs font-normal' : 'h-9 px-3 text-sm font-normal')"
                  >
                    <span class="flex min-w-0 items-center gap-2">
                      <span
                        v-if="selectedGroupMeta"
                        class="h-2.5 w-2.5 shrink-0 rounded-sm"
                        :style="{ backgroundColor: selectedGroupMeta.color }"
                      />
                      <span class="truncate">
                        {{ selectedGroupMeta?.name || t.jobsPage.executeSelectDeviceGroup }}
                      </span>
                    </span>
                    <span class="ml-2 flex items-center gap-1 text-[11px] text-muted-foreground">
                      {{ selectedGroupMeta ? selectedGroupMeta.count : "" }}
                      <ChevronsUpDown class="h-3.5 w-3.5" />
                    </span>
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="start" class="w-[var(--reka-popover-trigger-width)] p-0">
                  <div class="p-2">
                    <div class="relative">
                      <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        v-model="groupSearch"
                        :placeholder="t.devices.searchGroupPlaceholder"
                        class="h-8 pl-8 text-xs"
                        autofocus
                      />
                    </div>
                  </div>
                  <div class="border-t border-border" />
                  <div class="max-h-[240px] overflow-y-auto py-1">
                    <div
                      v-if="groupLoading"
                      class="flex items-center justify-center gap-2 px-4 py-8 text-xs text-muted-foreground"
                    >
                      <RotateCw class="h-3.5 w-3.5 animate-spin" />
                      {{ t.common.loading }}
                    </div>
                    <div
                      v-else-if="groups.length === 0"
                      class="flex flex-col items-center justify-center gap-2 px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      <Inbox class="h-4 w-4" />
                      {{ t.devices.noGroupFound }}
                    </div>
                    <template v-else>
                      <button
                        v-for="group in groups"
                        :key="group.id"
                        type="button"
                        class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/60"
                        @click="selectGroup(group)"
                      >
                        <span class="h-2.5 w-2.5 shrink-0 rounded-sm" :style="{ backgroundColor: group.color }" />
                        <span class="flex-1 truncate">{{ group.name }}</span>
                        <span class="text-xs text-muted-foreground tabular-nums">{{ group.count ?? 0 }}</span>
                      </button>
                    </template>
                  </div>
                </PopoverContent>
              </Popover>
            </Field>
          </div>
          <Field class="mt-3">
            <FieldLabel :class="labelClass">{{ t.jobsPage.executeDescription }}</FieldLabel>
            <Textarea
              :class="textareaClass"
              :model-value="form.description"
              @update:model-value="update('description', $event)"
              :rows="2"
              :placeholder="t.jobsPage.executeDescriptionPlaceholder"
            />
          </Field>
          <div class="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeScript }} <span class="text-destructive">*</span></FieldLabel>
              <Popover :open="scriptPickerOpen" @update:open="onScriptPickerOpenChange">
                <PopoverTrigger as-child>
                  <Button
                    type="button"
                    variant="outline"
                    :class="cn('w-full justify-between', compact ? 'h-8 px-2.5 text-xs font-normal' : 'h-9 px-3 text-sm font-normal')"
                  >
                    <span class="truncate text-left">
                      {{ selectedScriptName || t.jobsPage.executeSelectScript }}
                    </span>
                    <ChevronsUpDown class="h-3.5 w-3.5 text-muted-foreground" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="start" class="w-[var(--reka-popover-trigger-width)] p-0">
                  <div class="p-2">
                    <div class="relative">
                      <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        v-model="scriptSearch"
                        :placeholder="t.jobsPage.executeSearchScriptPlaceholder"
                        class="h-8 pl-8 text-xs"
                        autofocus
                      />
                    </div>
                  </div>
                  <div class="border-t border-border" />
                  <div class="max-h-[240px] overflow-y-auto py-1">
                    <div
                      v-if="scriptLoading"
                      class="flex items-center justify-center gap-2 px-4 py-8 text-xs text-muted-foreground"
                    >
                      <RotateCw class="h-3.5 w-3.5 animate-spin" />
                      {{ t.common.loading }}
                    </div>
                    <div
                      v-else-if="scripts.length === 0"
                      class="flex flex-col items-center justify-center gap-2 px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      <Inbox class="h-4 w-4" />
                      {{ t.jobsPage.executeNoScriptFound }}
                    </div>
                    <template v-else>
                      <button
                        v-for="script in scripts"
                        :key="script.id"
                        type="button"
                        class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/60"
                        @click="selectScript(script)"
                      >
                        <span class="h-2.5 w-2.5 shrink-0 rounded-sm bg-sky-500" />
                        <span class="flex-1 truncate">{{ script.name }}</span>
                      </button>
                    </template>
                  </div>
                </PopoverContent>
              </Popover>
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeVersion }} <span class="text-destructive">*</span></FieldLabel>
              <Select
                :model-value="form.versionId || undefined"
                @update:model-value="update('versionId', $event)"
                :disabled="!form.scriptId"
              >
                <SelectTrigger :class="selectTriggerClass" :size="compact ? 'sm' : 'default'">
                  <SelectValue :placeholder="loadingVersions ? t.jobsPage.loadingVersions : t.jobsPage.executeSelectVersion" />
                </SelectTrigger>
                <SelectContent class="max-h-64">
                  <div
                    v-if="versions.length === 0"
                    class="flex flex-col items-center justify-center gap-2 px-3 py-6 text-center text-xs text-muted-foreground"
                  >
                    <Inbox class="h-4 w-4" />
                    {{ t.jobsPage.executeNoVersionFound }}
                  </div>
                  <template v-else>
                    <SelectItem v-for="v in versions" :class="compact ? 'text-xs' : ''" :key="v.id" :value="v.id">
                      {{ v.label }}
                    </SelectItem>
                  </template>
                </SelectContent>
              </Select>
            </Field>
          </div>
        </div>

        <div :class="sectionClass">
          <div class="mb-3 flex items-center gap-2">
            <Gauge :class="sectionIconClass" />
            <p :class="sectionTitleClass">{{ t.jobsPage.executeMode }}</p>
          </div>
          <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeMode }}</FieldLabel>
              <Select :model-value="form.mode" @update:model-value="onModeChange">
                <SelectTrigger :class="selectTriggerClass" :size="compact ? 'sm' : 'default'"><SelectValue /></SelectTrigger>
                <SelectContent class="max-h-64">
                  <SelectItem :class="compact ? 'text-xs' : ''" value="loop">{{ t.jobsPage.executeModeLoop }}</SelectItem>
                  <SelectItem :class="compact ? 'text-xs' : ''" value="count">{{ t.jobsPage.executeModeCount }}</SelectItem>
                  <SelectItem :class="compact ? 'text-xs' : ''" value="per-device-count">{{ t.jobsPage.executeModePerDeviceCount }}</SelectItem>
                  <SelectItem :class="compact ? 'text-xs' : ''" value="deadline">{{ t.jobsPage.executeModeTime }}</SelectItem>
                  <SelectItem :class="compact ? 'text-xs' : ''" value="crontab">{{ t.jobsPage.executeModeCrontab }}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field v-if="form.mode === 'count' || form.mode === 'per-device-count'">
              <FieldLabel :class="labelClass">{{ form.mode === 'count' ? t.jobsPage.executeCount : t.jobsPage.executeCountPerDevice }}</FieldLabel>
              <Input
                :class="inputClass"
                type="number"
                min="0"
                :model-value="form.count"
                @update:model-value="update('count', parseInt($event, 10) || 0)"
              />
            </Field>
            <Field v-if="form.mode === 'deadline'">
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeEndTime }}</FieldLabel>
              <DateTimePicker :class-name="inputClass" :model-value="form.endAt" @update:model-value="update('endAt', $event)" />
            </Field>
            <Field v-if="form.mode === 'crontab'">
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeCrontab }}</FieldLabel>
              <div class="mt-0.5 flex w-full flex-nowrap items-center gap-1 overflow-x-auto">
                <div v-for="item in CRON_PART_CONFIG" :key="item.key" class="flex shrink-0 items-center gap-1">
                  <p :class="cn('text-muted-foreground tabular-nums', compact ? 'text-[10px]' : 'text-[11px]')">
                    {{ item.key === 'minute' ? 'MI' : item.key === 'hour' ? 'H' : item.key === 'dayOfMonth' ? 'D' : item.key === 'month' ? 'MO' : 'W' }}
                  </p>
                  <Input
                    :class="cn(inputClass, 'h-7 w-[40px] px-1.5 text-xs')"
                    :model-value="cronParts[item.key]"
                    @update:model-value="updateCronPart(item.key, $event)"
                    placeholder="*"
                  />
                </div>
              </div>
            </Field>
          </div>

          <div class="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeMinInterval }}</FieldLabel>
              <Input
                :class="inputClass"
                type="number"
                min="0"
                :model-value="form.interval"
                :disabled="isCrontabMode"
                @update:model-value="update('interval', parseInt($event, 10) || 0)"
              />
              <FieldDescription :class="descClass">{{ t.jobsPage.executeMinIntervalHint }}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeRetryCount }}</FieldLabel>
              <Input
                :class="inputClass"
                type="number"
                min="0"
                :model-value="form.retries"
                @update:model-value="update('retries', parseInt($event, 10) || 0)"
              />
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeIgnoreResult }}</FieldLabel>
              <div :class="cn('border-input rounded-md border px-3', compact ? 'h-8 py-0.5' : 'h-9 py-1')">
                <div class="flex h-full items-center justify-end">
                  <Switch :checked="form.ignoreResult" @update:checked="update('ignoreResult', $event)" />
                </div>
              </div>
            </Field>
          </div>
          <div class="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeSoftTimeout }}</FieldLabel>
              <Input
                :class="inputClass"
                type="number"
                min="0"
                :model-value="form.softTimeout"
                @update:model-value="update('softTimeout', parseInt($event, 10) || 0)"
              />
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeHardTimeout }}</FieldLabel>
              <Input
                :class="inputClass"
                type="number"
                min="0"
                :model-value="form.hardTimeout"
                @update:model-value="update('hardTimeout', parseInt($event, 10) || 0)"
              />
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeForegroundTask }}</FieldLabel>
              <div :class="cn('border-input rounded-md border px-3', compact ? 'h-8 py-0.5' : 'h-9 py-1')">
                <div class="flex h-full items-center justify-end">
                  <Switch :checked="form.foreground" @update:checked="update('foreground', $event)" />
                </div>
              </div>
            </Field>
          </div>
          <Field class="mt-3">
            <div class="flex items-center justify-between">
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeWeight }}</FieldLabel>
              <span :class="cn('rounded bg-muted px-2 py-0.5 font-medium tabular-nums', compact ? 'text-xs' : 'text-sm')">{{ form.priority }}</span>
            </div>
            <Slider
              :disabled="isCrontabMode"
              :model-value="[form.priority]"
              @update:model-value="update('priority', $event[0])"
              :max="100"
              :min="1"
              :step="1"
            />
            <FieldDescription :class="descClass">{{ t.jobsPage.executeWeightHint }}</FieldDescription>
          </Field>
        </div>

        <div v-if="isPromptScript" :class="sectionClass">
          <div class="mb-3 flex items-center gap-2">
            <SlidersHorizontal :class="sectionIconClass" />
            <p :class="sectionTitleClass">{{ t.jobsPage.executeModel }}</p>
          </div>
          <Field>
            <Select :model-value="form.modelId || undefined" @update:model-value="update('modelId', $event)">
              <SelectTrigger :class="selectTriggerClass" :size="compact ? 'sm' : 'default'">
                <SelectValue :placeholder="t.jobsPage.executeSelectModel" />
              </SelectTrigger>
              <SelectContent class="max-h-64">
                <div
                  v-if="models.length === 0"
                  class="flex flex-col items-center justify-center gap-2 px-3 py-6 text-center text-xs text-muted-foreground"
                >
                  <Inbox class="h-4 w-4" />
                  {{ t.jobsPage.executeNoModels }}
                </div>
                <template v-else>
                  <SelectItem v-for="m in models" :class="compact ? 'text-xs' : ''" :key="m.id" :value="m.id">
                    {{ m.label }}
                  </SelectItem>
                </template>
              </SelectContent>
            </Select>
          </Field>
        </div>

        <div :class="sectionClass">
          <div class="mb-3 flex items-center gap-2">
            <SlidersHorizontal :class="sectionIconClass" />
            <p :class="sectionTitleClass">{{ t.jobsPage.executeParamSource }}</p>
          </div>

          <Field>
            <FieldLabel :class="labelClass">{{ t.jobsPage.executeParamSource }}</FieldLabel>
            <Select :model-value="form.paramSource" @update:model-value="onParamSourceChange">
              <SelectTrigger :class="selectTriggerClass" :size="compact ? 'sm' : 'default'"><SelectValue /></SelectTrigger>
              <SelectContent class="max-h-64">
                <SelectItem :class="compact ? 'text-xs' : ''" value="native">{{ t.jobsPage.executeParamSourceNative }}</SelectItem>
                <SelectItem :class="compact ? 'text-xs' : ''" value="queue">{{ t.jobsPage.executeParamSourceQueue }}</SelectItem>
                <SelectItem :class="compact ? 'text-xs' : ''" value="callback">{{ t.jobsPage.executeParamSourceHttp }}</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription :class="descClass">
              {{ form.paramSource === 'callback' ? t.jobsPage.executeParamSourceHttpDesc : form.paramSource === 'queue' ? t.jobsPage.executeParamSourceQueueDesc : t.jobsPage.executeParamSourceNativeDesc }}
            </FieldDescription>
          </Field>

          <template v-if="form.paramSource === 'native'">
            <div v-if="hasNativeParams" class="mt-3 space-y-3">
              <div v-for="(p, idx) in params" :key="p.name" class="rounded-md border border-border/70 bg-muted/20 p-2">
                <div class="grid grid-cols-[180px_minmax(0,1fr)] items-start gap-3">
                  <div class="min-w-0">
                    <p :class="cn('truncate font-medium text-foreground', compact ? 'text-xs' : 'text-sm')">{{ p.name }}</p>
                    <p :class="cn('pt-0.5 text-muted-foreground', compact ? 'text-[11px] leading-4' : 'text-xs leading-4')">
                      {{ String(p.description || '').trim() || `Type: ${normalizeParamType(p.type)}` }}
                    </p>
                  </div>
                  <div class="min-w-0">
                    <Input
                      v-if="normalizeParamType(p.type) === 'integer' || normalizeParamType(p.type) === 'float'"
                      :data-exec-param-index="idx"
                      :class="inputClass"
                      type="number"
                      :model-value="paramInputs[p.name] ?? ''"
                      @update:model-value="setParamInput(p.name, $event)"
                      :placeholder="t.jobsPage.executeParamInputHint.replace('{name}', p.name)"
                    />
                    <Textarea
                      v-else-if="normalizeParamType(p.type) === 'list' || normalizeParamType(p.type) === 'object'"
                      :data-exec-param-index="idx"
                      :class="textareaClass"
                      :model-value="paramInputs[p.name] ?? ''"
                      :rows="4"
                      @update:model-value="setParamInput(p.name, $event)"
                      :placeholder="normalizeParamType(p.type) === 'list' ? t.jobsPage.executeParamListHint : t.jobsPage.executeParamObjectHint"
                    />
                    <Input
                      v-else
                      :data-exec-param-index="idx"
                      :class="inputClass"
                      :model-value="paramInputs[p.name] ?? ''"
                      @update:model-value="setParamInput(p.name, $event)"
                      :placeholder="normalizeParamType(p.type) === 'boolean' ? 'true / false' : t.jobsPage.executeParamInputHint.replace('{name}', p.name)"
                    />
                  </div>
                </div>
              </div>
            </div>
            <p v-else class="mt-3 text-xs text-muted-foreground">{{ t.jobsPage.executeNoNativeParams }}</p>
          </template>
          <div v-else-if="form.paramSource === 'callback' || form.paramSource === 'queue'" class="mt-3 space-y-3">
            <Field v-if="form.paramSource === 'queue'">
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeParamToken }}</FieldLabel>
              <Input
                :class="inputClass"
                v-model="queueToken"
                minlength="12"
                maxlength="32"
                :placeholder="t.jobsPage.executeParamTokenPlaceholder"
              />
              <FieldDescription :class="descClass">{{ t.jobsPage.executeParamTokenHint }}</FieldDescription>
            </Field>
            <Field v-if="form.paramSource === 'callback'">
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeParamUrl }}</FieldLabel>
              <Input :class="inputClass" v-model="httpUrl" :placeholder="t.jobsPage.executeParamUrlPlaceholder" />
            </Field>
            <Field>
              <FieldLabel :class="labelClass">{{ t.jobsPage.executeParamCallback }}</FieldLabel>
              <Input :class="inputClass" v-model="httpCallback" :placeholder="t.jobsPage.executeParamCallbackPlaceholder" />
            </Field>
            <Field>
              <div class="mb-2 flex items-center justify-between">
                <FieldLabel :class="labelClass">{{ t.jobsPage.executeHeaders }}</FieldLabel>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  :class="cn('h-7 gap-1 text-xs', compact && 'h-6 px-2.5 text-[11px]')"
                  @click="addHeader"
                >
                  <Plus class="h-3.5 w-3.5" /> {{ t.jobsPage.executeHeaderAdd }}
                </Button>
              </div>
              <div class="space-y-2">
                <div v-for="(h, idx) in httpHeaders" :key="`${idx}-${h.key}`" class="grid grid-cols-[1fr_1fr_auto] gap-2">
                  <Input
                    :class="inputClass"
                    :model-value="h.key"
                    :placeholder="t.jobsPage.executeHeaderName"
                    @update:model-value="updateHeader(idx, 'key', $event)"
                  />
                  <Input
                    :class="inputClass"
                    :model-value="h.value"
                    :placeholder="t.jobsPage.executeHeaderValue"
                    @update:model-value="updateHeader(idx, 'value', $event)"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    :class="cn('h-9 w-9', compact && 'h-8 w-8')"
                    @click="removeHeader(idx)"
                  >
                    <Trash2 :class="cn('h-4 w-4', compact && 'h-3.5 w-3.5')" />
                  </Button>
                </div>
              </div>
            </Field>
          </div>
        </div>
      </div>
    </div>

    <div class="sticky bottom-0 border-t border-border bg-background/95 px-4 py-3 backdrop-blur md:px-6">
      <div :class="cn('mx-auto flex gap-2', compact ? 'max-w-none' : 'max-w-5xl')">
        <Button :size="compact ? 'sm' : 'default'" variant="outline" @click="props.onCancel?.()">
          {{ t.jobsPage.cancelExecute }}
        </Button>
        <Button :size="compact ? 'sm' : 'default'" @click="onSubmit" :disabled="loading">
          <Play :class="cn('mr-1.5', compact ? 'h-3.5 w-3.5' : 'h-4 w-4')" />
          {{ loading ? t.jobsPage.executingJob : t.jobsPage.executeNow }}
        </Button>
        <FeedbackTip
          v-if="miniTip"
          :key="miniTip.id"
          :toast-id="miniTip.id"
          :message="miniTip.text"
          variant="error"
          truncate
          class-name="max-w-[420px]"
        />
      </div>
    </div>
  </div>
</template>
