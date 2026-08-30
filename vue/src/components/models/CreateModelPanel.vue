<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { Button } from "@/components/ui/button";
import { showFeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import {
  DEFAULT_CONTEXT_LENGTH,
  catalogMaxOutputTokens,
  findCatalogModel,
  formatContextLength,
  loadModelCatalog,
  matchCatalogContextLength,
  suggestCatalogModelNames,
  type CatalogNameSuggestion,
  type ModelCatalogEntry,
} from "@/lib/model-catalog";
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    compact?: boolean;
    onCancel?: () => void;
    onSuccess?: () => void;
    onError?: (msg: string) => void;
  }>(),
  { compact: false },
);

const { t } = useTranslation();
const name = ref("");
const provider = ref("openai-compatible");
const apiBase = ref("");
const modelName = ref("");
const modelSuggestOpen = ref(false);
const modelSuggestIndex = ref(0);
const suggestListRef = ref<HTMLDivElement | null>(null);
const contextLength = ref(DEFAULT_CONTEXT_LENGTH);
const catalogModels = ref<ModelCatalogEntry[]>([]);
const apiKey = ref("");
const visionMode = ref(false);
const scale = ref(0);
const maxTokens = ref(4096);
const temperature = ref(0.2);
const stepDelay = ref(0);
const submitting = ref(false);

const modelSuggestions = computed(() => suggestCatalogModelNames(catalogModels.value, modelName.value));
const modelSuggestVisible = computed(() => modelSuggestOpen.value && modelSuggestions.value.length > 0);
const matchedCatalog = computed(() => findCatalogModel(catalogModels.value, modelName.value));
const highlightedSuggestion = computed(() =>
  modelSuggestVisible.value ? (modelSuggestions.value[modelSuggestIndex.value] ?? null) : null,
);
const chatBlocked = computed(
  () => matchedCatalog.value != null && matchedCatalog.value.supports_chat_completion !== true,
);
const visionAllowed = computed(
  () => matchedCatalog.value == null || matchedCatalog.value.supports_vision === true,
);
const catalogMaxOutput = computed(() => catalogMaxOutputTokens(matchedCatalog.value));
const capabilityHint = computed(() =>
  highlightedSuggestion.value
    ? highlightedSuggestion.value.supportsChatCompletion
      ? ""
      : t.value.modelsPage.formChatUnsupported
    : chatBlocked.value
      ? t.value.modelsPage.formChatUnsupported
      : "",
);

let catalogCancelled = false;
onMounted(() => {
  void loadModelCatalog().then((models) => {
    if (!catalogCancelled) catalogModels.value = models;
  });
});
onUnmounted(() => {
  catalogCancelled = true;
});

watch([catalogModels, modelName], () => {
  const next = matchCatalogContextLength(catalogModels.value, modelName.value);
  if (next != null) contextLength.value = next;
});

watch([catalogMaxOutput, maxTokens], () => {
  if (catalogMaxOutput.value != null && maxTokens.value > catalogMaxOutput.value) {
    maxTokens.value = catalogMaxOutput.value;
  }
});

watch([visionAllowed, visionMode], () => {
  if (!visionAllowed.value && visionMode.value) {
    visionMode.value = false;
    scale.value = 0;
  }
});

watch(
  [modelSuggestIndex, modelSuggestVisible],
  () => {
    const root = suggestListRef.value;
    if (!root) return;
    const active = root.querySelector<HTMLElement>(`[data-suggest-index="${modelSuggestIndex.value}"]`);
    if (!active) return;
    const rootRect = root.getBoundingClientRect();
    const activeRect = active.getBoundingClientRect();
    if (activeRect.bottom > rootRect.bottom) {
      root.scrollTop += activeRect.bottom - rootRect.bottom;
    } else if (activeRect.top < rootRect.top) {
      root.scrollTop -= rootRect.top - activeRect.top;
    }
  },
  { flush: "post" },
);

const labelClass = computed(() => (props.compact ? "text-xs font-medium" : "text-sm font-medium"));
const inputClass = computed(() => (props.compact ? "h-8 text-xs" : ""));
const providerOptions = computed(() => [
  { value: "openai-compatible", label: t.value.modelsPage.formProviderOpenAICompatible },
  { value: "openai", label: t.value.modelsPage.formProviderOpenAI },
  { value: "anthropic", label: t.value.modelsPage.formProviderAnthropic },
  { value: "ollama", label: t.value.modelsPage.formProviderOllama },
]);

const fail = (msg: string) => {
  showFeedbackTip(msg, "error");
  props.onError?.(msg);
};

const applySuggestion = (item: CatalogNameSuggestion) => {
  modelName.value = item.value;
  if (item.contextLength != null) contextLength.value = item.contextLength;
  if (item.maxOutputTokens != null) {
    maxTokens.value = Math.min(maxTokens.value, item.maxOutputTokens as number);
  }
  modelSuggestOpen.value = false;
  if (!item.supportsChatCompletion) fail(t.value.modelsPage.formChatUnsupported);
};

const onModelNameKeydown = (e: KeyboardEvent) => {
  if (!modelSuggestions.value.length) return;
  if (e.key === "ArrowDown") {
    e.preventDefault();
    modelSuggestOpen.value = true;
    modelSuggestIndex.value = (modelSuggestIndex.value + 1) % modelSuggestions.value.length;
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    modelSuggestOpen.value = true;
    modelSuggestIndex.value =
      (modelSuggestIndex.value - 1 + modelSuggestions.value.length) % modelSuggestions.value.length;
  } else if (e.key === "Enter") {
    const hit = modelSuggestions.value[modelSuggestIndex.value];
    if (modelSuggestVisible.value && hit) {
      e.preventDefault();
      applySuggestion(hit);
    }
  } else if (e.key === "Escape") {
    modelSuggestOpen.value = false;
  }
};

const onModelNameBlur = () => {
  window.setTimeout(() => (modelSuggestOpen.value = false), 120);
};

const onVisionChecked = (checked: boolean) => {
  if (!visionAllowed.value) return fail(t.value.modelsPage.formVisionUnsupported);
  visionMode.value = checked;
};

const handleCreate = async () => {
  const n = name.value.trim();
  const apiBaseValue = apiBase.value.trim();
  const mn = modelName.value.trim();
  const key = apiKey.value.trim();
  if (!n) return fail(t.value.modelsPage.formNameRequired);
  if (!apiBaseValue) return fail(t.value.modelsPage.formEndpointRequired);
  if (!mn) return fail(t.value.modelsPage.formModelRequired);
  const catalogHit = findCatalogModel(catalogModels.value, mn);
  if (catalogHit && catalogHit.supports_chat_completion !== true)
    return fail(t.value.modelsPage.formChatUnsupported);
  if (catalogHit && visionMode.value && catalogHit.supports_vision !== true)
    return fail(t.value.modelsPage.formVisionUnsupported);
  if (catalogHit) {
    if (!Number.isFinite(contextLength.value) || contextLength.value < 128000)
      return fail(t.value.modelsPage.formContextLengthRequired);
  } else if (!Number.isFinite(contextLength.value) || contextLength.value < 1) {
    return fail(t.value.modelsPage.formContextLengthInvalid);
  }
  if (!key) return fail(t.value.modelsPage.formKeyRequired);
  const outputCap = catalogMaxOutputTokens(catalogHit);
  if (!Number.isFinite(maxTokens.value) || maxTokens.value < 1)
    return fail(t.value.modelsPage.formMaxTokensInvalid);
  if (outputCap != null && maxTokens.value > outputCap) {
    return fail(t.value.modelsPage.formMaxTokensExceedsModel.replace("{max}", String(outputCap)));
  }
  if (outputCap == null && maxTokens.value < 1024) return fail(t.value.modelsPage.formMaxTokensInvalid);
  submitting.value = true;
  try {
    await apiRequest("/api/v1/model", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        name: n,
        provider: provider.value,
        api_base: apiBaseValue,
        model: mn,
        context_window: String(Math.floor(contextLength.value)),
        api_key: key,
        mode: visionMode.value ? "vision" : "text",
        scale: visionMode.value ? String(scale.value) : "0",
        temperature: String(temperature.value),
        step_delay: String(stepDelay.value),
        max_completion_tokens: String(Math.floor(maxTokens.value)),
      }).toString(),
    });
    props.onSuccess?.();
    name.value = "";
    provider.value = "openai-compatible";
    apiBase.value = "";
    modelName.value = "";
    contextLength.value = DEFAULT_CONTEXT_LENGTH;
    apiKey.value = "";
    visionMode.value = false;
    scale.value = 0;
    maxTokens.value = 4096;
    temperature.value = 0.2;
    stepDelay.value = 0;
  } catch (error) {
    fail(formatApiError(error, t.value.modelsPage.createFailed));
  } finally {
    submitting.value = false;
  }
};
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="min-h-0 flex-1 overflow-y-auto px-4 py-3">
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1">
            <p :class="labelClass">{{ t.modelsPage.formName }}</p>
            <Input :class="inputClass" v-model="name" :placeholder="t.modelsPage.formNamePlaceholder" />
          </div>
          <div class="space-y-1">
            <p :class="labelClass">{{ t.modelsPage.formProvider }}</p>
            <Select v-model="provider">
              <SelectTrigger size="sm" :class="cn(inputClass, 'w-full')">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="item in providerOptions" :key="item.value" :value="item.value" class="text-xs">
                  {{ item.label }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div class="space-y-1">
          <p :class="labelClass">{{ t.modelsPage.formEndpoint }}</p>
          <Input :class="inputClass" v-model="apiBase" :placeholder="t.modelsPage.formEndpointPlaceholder" />
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div class="grid min-w-0 grid-cols-3 gap-3">
            <div class="col-span-2 space-y-1">
              <p :class="labelClass">{{ t.modelsPage.formModel }}</p>
              <div class="relative">
                <Input
                  :class="inputClass"
                  :model-value="modelName"
                  autocomplete="off"
                  :spellcheck="false"
                  :placeholder="t.modelsPage.formModelPlaceholder"
                  @update:model-value="
                    (v) => {
                      modelName = v;
                      modelSuggestIndex = 0;
                      modelSuggestOpen = true;
                    }
                  "
                  @focus="modelSuggestOpen = true"
                  @blur="onModelNameBlur"
                  @keydown="onModelNameKeydown"
                />
                <div
                  v-if="modelSuggestVisible"
                  ref="suggestListRef"
                  class="absolute top-full z-50 mt-1 max-h-56 w-full overflow-y-scroll overscroll-contain rounded-md border bg-popover p-1 shadow-md"
                  @mousedown.prevent
                  @wheel.stop
                >
                  <button
                    v-for="(item, index) in modelSuggestions"
                    :key="`${item.source}:${item.value}`"
                    type="button"
                    :data-suggest-index="index"
                    :class="
                      cn(
                        'flex w-full items-center justify-between gap-2 rounded-sm px-2 py-1.5 text-left text-xs',
                        index === modelSuggestIndex ? 'bg-accent text-accent-foreground' : 'hover:bg-accent/60',
                        !item.supportsChatCompletion && 'opacity-60',
                      )
                    "
                    @mouseenter="modelSuggestIndex = index"
                    @click="applySuggestion(item)"
                  >
                    <span class="min-w-0 truncate font-medium">{{ item.value }}</span>
                    <span
                      v-if="item.source === 'alias' && item.modelId && item.modelId !== item.value"
                      class="shrink-0 text-[10px] text-muted-foreground"
                    >
                      {{ item.modelId }}
                    </span>
                  </button>
                </div>
              </div>
              <p v-if="capabilityHint" class="text-[11px] leading-4 text-destructive">{{ capabilityHint }}</p>
            </div>
            <div class="space-y-1">
              <p :class="labelClass">{{ t.modelsPage.formContextLength }}</p>
              <Input
                v-if="matchedCatalog"
                :class="inputClass"
                readonly
                disabled
                :model-value="formatContextLength(contextLength)"
                :title="String(contextLength)"
              />
              <Input
                v-else
                :class="inputClass"
                type="number"
                :min="1"
                :model-value="contextLength"
                :placeholder="t.modelsPage.formContextLengthInputPlaceholder"
                @update:model-value="(v) => (contextLength = Number(v || 0))"
              />
            </div>
          </div>
          <div class="space-y-1">
            <p :class="labelClass">{{ t.modelsPage.formKey }}</p>
            <Input :class="inputClass" v-model="apiKey" :placeholder="t.modelsPage.formKeyPlaceholder" />
          </div>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div class="flex items-start justify-between">
            <Tooltip>
              <TooltipTrigger as-child>
                <div class="space-y-1">
                  <p :class="cn(labelClass, !visionAllowed && 'text-muted-foreground')">
                    {{ t.modelsPage.formVision }}
                  </p>
                  <div class="flex h-8 items-center">
                    <Switch :checked="visionMode" :disabled="!visionAllowed" @update:checked="onVisionChecked" />
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent side="bottom" class="max-w-xs text-pretty">
                {{ visionAllowed ? t.modelsPage.formVisionTooltip : t.modelsPage.formVisionUnsupported }}
              </TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger as-child>
                <div class="space-y-1">
                  <p :class="cn(labelClass, !visionMode && 'text-muted-foreground')">
                    {{ t.modelsPage.formScale }}
                  </p>
                  <Input
                    class="h-8 text-xs w-24"
                    type="number"
                    :min="0"
                    :max="4096"
                    :step="2"
                    :disabled="!visionMode"
                    :model-value="scale"
                    @update:model-value="
                      (v) => {
                        const raw = Math.max(0, Math.min(4096, Number(v || 0)));
                        scale = raw === 0 ? 0 : Math.round(raw / 2) * 2;
                      }
                    "
                  />
                </div>
              </TooltipTrigger>
              <TooltipContent side="bottom" class="max-w-xs text-pretty">
                {{ t.modelsPage.formScaleTooltip }}
              </TooltipContent>
            </Tooltip>
          </div>
          <div class="space-y-1">
            <p :class="labelClass">{{ t.modelsPage.formMaxTokens }}</p>
            <Input
              :class="inputClass"
              type="number"
              :min="catalogMaxOutput != null ? 1 : 1024"
              :max="catalogMaxOutput ?? undefined"
              :model-value="maxTokens"
              @update:model-value="
                (v) => {
                  const raw = Number(v || 0);
                  maxTokens = catalogMaxOutput != null ? Math.min(raw, catalogMaxOutput) : raw;
                }
              "
            />
          </div>
        </div>
        <div class="space-y-1">
          <p :class="labelClass">{{ t.modelsPage.formTemperature }}</p>
          <div class="flex items-center gap-3">
            <Slider
              :model-value="[temperature]"
              :min="0"
              :max="1"
              :step="0.01"
              @update:model-value="(v) => (temperature = Number(v[0] || 0))"
            />
            <Input
              :class="inputClass"
              type="number"
              :min="0"
              :max="1"
              :step="0.01"
              :model-value="temperature"
              @update:model-value="(v) => (temperature = Number(v || 0))"
            />
          </div>
        </div>
        <div class="space-y-1">
          <p :class="labelClass">{{ t.modelsPage.formStepDelay }}</p>
          <div class="flex items-center gap-3">
            <Slider
              :model-value="[stepDelay]"
              :min="0"
              :max="60"
              :step="0.1"
              @update:model-value="(v) => (stepDelay = Number(v[0] || 0))"
            />
            <Input
              :class="inputClass"
              type="number"
              :min="0"
              :max="60"
              :step="0.1"
              :model-value="stepDelay"
              @update:model-value="(v) => (stepDelay = Number(v || 0))"
            />
          </div>
        </div>
      </div>
    </div>
    <div class="shrink-0 border-t border-border px-4 py-3">
      <div class="flex items-center gap-2">
        <Button variant="outline" class="h-8 text-xs" @click="props.onCancel?.()">
          {{ t.modelsPage.cancel }}
        </Button>
        <Button class="h-8 text-xs" :disabled="submitting || chatBlocked" @click="handleCreate()">
          {{ t.modelsPage.confirmCreate }}
        </Button>
        <p v-if="chatBlocked" class="text-[11px] text-destructive">{{ t.modelsPage.formChatUnsupported }}</p>
      </div>
    </div>
  </div>
</template>
