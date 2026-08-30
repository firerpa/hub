<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { Minus, Plus } from "lucide-vue-next";
import { Button } from "@/components/ui/button";
import { showFeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type ScriptType = "code" | "prompt";
type ParamType = "object" | "integer" | "float" | "boolean" | "array" | "string";

type ParamItem = {
  name: string;
  type: ParamType;
  description: string;
};

const paramTypeOptions: ParamType[] = ["object", "integer", "float", "boolean", "array", "string"];

function buildDefaultParam(): ParamItem {
  return { name: "", type: "string", description: "" };
}

function pyIdentValid(v: string) {
  return /^[A-Za-z_一-龥][A-Za-z0-9_一-龥]*$/u.test(v);
}

function buildScriptEntry(now = Date.now()) {
  const hex = ((now & 0xffffffff) >>> 0).toString(16).padStart(8, "0");
  return `script.${hex}.Main`;
}

function generatedEntryValid(v: string) {
  return /^script\.[0-9a-f]{8}\.Main$/.test(v);
}

const props = withDefaults(
  defineProps<{
    compact?: boolean;
    open?: boolean;
    onCancel?: () => void;
    onSuccess?: () => void;
    onError?: (msg: string) => void;
    className?: string;
  }>(),
  {
    compact: false,
    open: true,
  },
);

const { t } = useTranslation();
const scriptType = ref<ScriptType>("code");
const name = ref("");
const description = ref("");
const entry = ref(buildScriptEntry());
const params = ref<ParamItem[]>([buildDefaultParam()]);
const submitting = ref(false);

watch(
  () => props.open,
  (open) => {
    if (open) entry.value = buildScriptEntry();
  },
  { immediate: true },
);

const inputClass = computed(() => (props.compact ? "h-8 text-xs" : ""));
const selectClass = computed(() => (props.compact ? "text-xs" : ""));
const labelClass = computed(() => (props.compact ? "text-xs font-medium" : "text-sm font-medium"));
const selectSize = computed(() => (props.compact ? "sm" : "default"));

const currentTypeNumber = computed(() => (scriptType.value === "prompt" ? 1 : 0));

const addParam = () => {
  params.value = [...params.value, buildDefaultParam()];
};
const removeParam = (index: number) => {
  params.value = params.value.filter((_, i) => i !== index);
};
const patchParam = (index: number, patch: Partial<ParamItem>) => {
  params.value = params.value.map((p, i) => (i === index ? { ...p, ...patch } : p));
};

const onScriptTypeChange = (v: string) => {
  scriptType.value = v as ScriptType;
};
const onParamTypeChange = (index: number, v: string) => {
  patchParam(index, { type: v as ParamType });
};

const fail = (msg: string) => {
  showFeedbackTip(msg, "error");
  props.onError?.(msg);
};

const handleCreate = async () => {
  const scriptName = name.value.trim();
  if (!scriptName) return fail(t.value.scriptsPage.formNameRequired);
  if (!pyIdentValid(scriptName)) return fail(t.value.scriptsPage.formNameInvalid);

  const finalEntry = buildScriptEntry();
  entry.value = finalEntry;
  if (!generatedEntryValid(finalEntry)) return fail(t.value.scriptsPage.formEntryInvalid);

  const cleaned = params.value
    .map((p) => ({
      name: p.name.trim(),
      type: p.type,
      description: p.description.trim(),
    }))
    .filter((p) => p.name);

  const invalid = cleaned.find((p) => !pyIdentValid(p.name));
  if (invalid) return fail(t.value.scriptsPage.formParamInvalid.replace("{name}", invalid.name));

  const seen = new Set<string>();
  const dup = cleaned.find((p) => {
    if (seen.has(p.name)) return true;
    seen.add(p.name);
    return false;
  });
  if (dup) return fail(t.value.scriptsPage.formParamDuplicate.replace("{name}", dup.name));

  submitting.value = true;
  try {
    const body = new URLSearchParams({
      name: scriptName,
      description: description.value.trim(),
      type: String(currentTypeNumber.value),
      entry: finalEntry,
      params: JSON.stringify(cleaned),
    });
    await apiRequest("/api/v1/script", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    props.onSuccess?.();
    name.value = "";
    description.value = "";
    entry.value = buildScriptEntry();
    params.value = [buildDefaultParam()];
    scriptType.value = "code";
  } catch (error) {
    fail(formatApiError(error, t.value.scriptsPage.createFailed));
  } finally {
    submitting.value = false;
  }
};
</script>

<template>
  <div :class="cn('flex h-full min-h-0 flex-col', className)">
    <div class="min-h-0 flex-1 overflow-y-auto px-4 py-3">
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1">
            <p :class="labelClass">{{ t.scriptsPage.formName }}</p>
            <Input :class="cn(inputClass, 'w-full')" v-model="name" :placeholder="t.scriptsPage.formNamePlaceholder" />
          </div>
          <div class="space-y-1">
            <p :class="labelClass">{{ t.scriptsPage.formType }}</p>
            <Select :model-value="scriptType" @update:model-value="onScriptTypeChange">
              <SelectTrigger :size="selectSize" :class="cn(selectClass, 'w-full')">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="code">{{ t.scriptsPage.typeCode }}</SelectItem>
                <SelectItem value="prompt">{{ t.scriptsPage.typePrompt }}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div class="space-y-1">
          <p :class="labelClass">{{ t.scriptsPage.formDescription }}</p>
          <Textarea :class="compact ? 'min-h-16 text-xs' : ''" v-model="description" :placeholder="t.scriptsPage.formDescriptionPlaceholder" />
        </div>

        <div class="space-y-1">
          <p :class="labelClass">{{ t.scriptsPage.formEntry }}</p>
          <Input :class="inputClass" :model-value="entry" readonly disabled />
        </div>

        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <p :class="labelClass">{{ t.scriptsPage.formParams }}</p>
            <Button type="button" variant="outline" size="sm" class="h-7 text-xs" @click="addParam">
              <Plus class="mr-1 h-3.5 w-3.5" />
              {{ t.scriptsPage.formAddParam }}
            </Button>
          </div>
          <div class="space-y-2">
            <div v-for="(param, index) in params" :key="index" class="grid grid-cols-12 gap-2">
              <Input
                :class="cn(inputClass, 'col-span-4')"
                :model-value="param.name"
                @update:model-value="patchParam(index, { name: $event })"
                :placeholder="t.scriptsPage.formParamName"
              />
              <Select :model-value="param.type" @update:model-value="onParamTypeChange(index, $event)">
                <SelectTrigger :size="selectSize" :class="cn(selectClass, 'col-span-3')">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="opt in paramTypeOptions" :key="opt" :value="opt">{{ opt }}</SelectItem>
                </SelectContent>
              </Select>
              <Input
                :class="cn(inputClass, 'col-span-4')"
                :model-value="param.description"
                @update:model-value="patchParam(index, { description: $event })"
                :placeholder="t.scriptsPage.formParamDesc"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                class="col-span-1 h-8 w-8"
                :disabled="params.length <= 1"
                @click="removeParam(index)"
              >
                <Minus class="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="shrink-0 border-t border-border px-4 py-3">
      <div class="flex items-center gap-2">
        <Button variant="outline" class="h-8 text-xs" @click="onCancel?.()">
          {{ t.scriptsPage.cancel }}
        </Button>
        <Button class="h-8 text-xs" :disabled="submitting" @click="void handleCreate()">
          {{ t.scriptsPage.confirmCreate }}
        </Button>
      </div>
    </div>
  </div>
</template>
