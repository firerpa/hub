<script setup lang="ts">
import { computed, ref } from "vue";
import { Button } from "@/components/ui/button";
import { showFeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { apiRequest, formatApiError } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";

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
const password = ref("");
const contact = ref("");
const submitting = ref(false);

const labelClass = computed(() => (props.compact ? "text-xs font-medium" : "text-sm font-medium"));
const inputClass = computed(() => (props.compact ? "h-8 text-xs" : ""));

const fail = (msg: string) => {
  showFeedbackTip(msg, "error");
  props.onError?.(msg);
};

const handleCreate = async () => {
  const n = name.value.trim();
  const p = password.value.trim();
  const c = contact.value.trim();
  if (!n || !p) return fail(t.value.usersPage.formRequired);
  submitting.value = true;
  try {
    await apiRequest("/api/v1/user", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        name: n,
        password: p,
        contact: c,
      }).toString(),
    });
    props.onSuccess?.();
    name.value = "";
    password.value = "";
    contact.value = "";
  } catch (error) {
    fail(formatApiError(error, t.value.usersPage.createFailed));
  } finally {
    submitting.value = false;
  }
};
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="min-h-0 flex-1 overflow-y-auto px-4 py-3">
      <div class="space-y-3">
        <div class="space-y-1">
          <p :class="labelClass">{{ t.usersPage.formName }}</p>
          <Input :class="inputClass" v-model="name" :placeholder="t.usersPage.formNamePlaceholder" />
        </div>
        <div class="space-y-1">
          <p :class="labelClass">{{ t.usersPage.formPassword }}</p>
          <Input
            :class="inputClass"
            type="password"
            v-model="password"
            :placeholder="t.usersPage.formPasswordPlaceholder"
          />
        </div>
        <div class="space-y-1">
          <p :class="labelClass">{{ t.usersPage.formContact }}</p>
          <Input :class="inputClass" v-model="contact" :placeholder="t.usersPage.formContactPlaceholder" />
        </div>
      </div>
    </div>
    <div class="shrink-0 border-t border-border px-4 py-3">
      <div class="flex items-center gap-2">
        <Button variant="outline" class="h-8 text-xs" @click="props.onCancel?.()">
          {{ t.usersPage.cancel }}
        </Button>
        <Button class="h-8 text-xs" :disabled="submitting" @click="handleCreate()">
          {{ t.usersPage.confirmCreate }}
        </Button>
      </div>
    </div>
  </div>
</template>
