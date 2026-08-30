<script setup lang="ts">
import { computed, ref } from "vue";
import { cn } from "@/lib/utils";
import { useTranslation, type Locale } from "@/lib/i18n";
import { apiRequest, formatApiError } from "@/lib/api";
import { toHashHref, useHashPathname, useHashRouter } from "@/lib/hash-router";
import {
  Monitor,
  Globe,
  ClipboardList,
  Code2,
  Box,
  Users,
  Sun,
  Moon,
  Languages,
  LogOut,
  KeyRound,
  Loader2,
} from "lucide-vue-next";
import { useTheme } from "@/lib/theme";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { FeedbackTip, type FeedbackTipVariant } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";

const { t, locale, setLocale } = useTranslation();
const pathname = useHashPathname();
const router = useHashRouter();
const { resolvedTheme, setTheme } = useTheme();
const loggingOut = ref(false);
const changePwdOpen = ref(false);
const savingPwd = ref(false);
const newPassword = ref("");
const confirmPassword = ref("");
const tip = ref<{ id: number; text: string; variant: FeedbackTipVariant } | null>(null);
const isDark = computed(() => resolvedTheme.value === "dark");

const mainNav = computed(() => [
  { label: t.value.nav.devices, icon: Monitor, href: "/devices" },
  { label: t.value.nav.monitor, icon: Globe, href: "/overview" },
  { label: t.value.nav.jobs, icon: ClipboardList, href: "/jobs" },
]);

const toolsNav = computed(() => [
  { label: t.value.nav.scripts, icon: Code2, href: "/scripts" },
  { label: t.value.nav.models, icon: Box, href: "/models" },
  { label: t.value.nav.users, icon: Users, href: "/users" },
]);

const isActive = (href: string) => {
  if (href === "#") return false;
  if (href === "/") return pathname.value === "/";
  return pathname.value === href || pathname.value.startsWith(`${href}/`);
};

const navItemClass = (href: string) => {
  const active = isActive(href);
  return cn(
    "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
    active
      ? "bg-orange-500/10 font-medium text-orange-600 dark:text-orange-400"
      : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
  );
};

const navIconClass = (href: string) => {
  const active = isActive(href);
  return cn(
    "h-4 w-4 shrink-0",
    active ? "text-orange-500 dark:text-orange-400" : "text-muted-foreground",
  );
};

const handleLogout = async () => {
  if (loggingOut.value) return;
  loggingOut.value = true;
  try {
    await apiRequest("/api/v1/user/login", { method: "DELETE" });
    router.replace("/login");
    router.refresh();
  } catch {
    loggingOut.value = false;
  }
};

const showTip = (text: string, variant: FeedbackTipVariant = "error") => {
  tip.value = { id: Date.now() + Math.random(), text, variant };
};

const resetChangePwdDialog = () => {
  newPassword.value = "";
  confirmPassword.value = "";
  tip.value = null;
  savingPwd.value = false;
};

const handleChangePassword = async () => {
  if (savingPwd.value) return;
  const pwd = newPassword.value.trim();
  const confirm = confirmPassword.value.trim();
  if (!pwd || !confirm) {
    showTip(t.value.user.changePasswordRequired);
    return;
  }
  if (pwd !== confirm) {
    showTip(t.value.user.changePasswordMismatch);
    return;
  }

  savingPwd.value = true;
  try {
    const me = await apiRequest<{ id: number }>("/api/v1/user/login", { cache: "no-store" });
    const uid = Number(me?.data?.id || 0);
    if (!uid) throw new Error(t.value.user.changePasswordLoadUserFailed);
    await apiRequest(`/api/v1/user/${uid}/credentials`, {
      method: "PUT",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: pwd }).toString(),
    });
    showTip(t.value.user.changePasswordSuccess, "success");
    changePwdOpen.value = false;
    resetChangePwdDialog();
  } catch (error) {
    showTip(formatApiError(error, t.value.user.changePasswordFailed));
    savingPwd.value = false;
  }
};

const onChangePwdOpenChange = (open: boolean) => {
  if (!savingPwd.value) {
    changePwdOpen.value = open;
    if (!open) resetChangePwdDialog();
  }
};
</script>

<template>
  <aside
    class="fixed inset-y-0 left-0 z-30 hidden h-screen w-[220px] shrink-0 border-r border-border bg-background lg:flex lg:flex-col"
  >
    <!-- Logo -->
    <div class="flex items-center gap-2.5 px-2 py-4">
      <div class="flex w-full items-center gap-2">
        <img src="/logo.svg" alt="FIRERPA" width="32" height="32" class="shrink-0 rounded-md" />
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline gap-0.5">
            <span class="brand-rounded text-sm font-bold text-foreground">FIRERPA</span>
            <span class="brand-rounded text-sm font-bold text-orange-500">{{ t.common.pigeonBrand }}</span>
          </div>
          <p class="mt-0.5 truncate text-[10px] text-muted-foreground">{{ t.common.manageDeviceAnywhere }}</p>
        </div>
      </div>
    </div>

    <!-- Nav -->
    <div class="flex-1 overflow-y-auto px-3 py-3">
      <div class="space-y-4">
        <div>
          <p class="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {{ t.nav.home }}
          </p>
          <div class="space-y-0.5">
            <template v-for="item in mainNav" :key="item.href">
              <button v-if="item.href === '#'" type="button" :class="navItemClass(item.href)">
                <component :is="item.icon" :class="navIconClass(item.href)" />
                <span class="truncate">{{ item.label }}</span>
              </button>
              <a v-else :href="toHashHref(item.href)" :class="navItemClass(item.href)">
                <component :is="item.icon" :class="navIconClass(item.href)" />
                <span class="truncate">{{ item.label }}</span>
              </a>
            </template>
          </div>
        </div>

        <div>
          <p class="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {{ t.nav.resources }}
          </p>
          <div class="space-y-0.5">
            <template v-for="item in toolsNav" :key="item.href">
              <button v-if="item.href === '#'" type="button" :class="navItemClass(item.href)">
                <component :is="item.icon" :class="navIconClass(item.href)" />
                <span class="truncate">{{ item.label }}</span>
              </button>
              <a v-else :href="toHashHref(item.href)" :class="navItemClass(item.href)">
                <component :is="item.icon" :class="navIconClass(item.href)" />
                <span class="truncate">{{ item.label }}</span>
              </a>
            </template>
          </div>
        </div>
      </div>
    </div>

    <!-- Footer - User Menu -->
    <div class="border-t border-border px-3 py-3">
      <DropdownMenu>
        <DropdownMenuTrigger as-child>
          <button
            type="button"
            class="flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left transition-colors hover:bg-muted/50"
          >
            <div
              class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground text-xs font-semibold text-background"
            >
              A
            </div>
            <div class="min-w-0 flex-1">
              <p class="truncate text-xs font-medium text-foreground">admin</p>
              <p class="mt-0.5 truncate text-[10px] text-muted-foreground">{{ t.user.superAdmin }}</p>
            </div>
          </button>
        </DropdownMenuTrigger>

        <DropdownMenuContent side="top" align="start" class="w-[200px]">
          <DropdownMenuLabel class="text-xs">{{ t.user.account }}</DropdownMenuLabel>

          <DropdownMenuItem @click="setLocale((locale === 'zh' ? 'en' : 'zh') as Locale)">
            <Languages class="h-4 w-4 mr-2" />
            <span>{{ locale === 'zh' ? t.user.switchToEnglish : t.user.switchToChinese }}</span>
          </DropdownMenuItem>

          <DropdownMenuItem @click="setTheme(isDark ? 'light' : 'dark')">
            <template v-if="isDark">
              <Sun class="h-4 w-4 mr-2" />
              <span>{{ t.user.lightMode }}</span>
            </template>
            <template v-else>
              <Moon class="h-4 w-4 mr-2" />
              <span>{{ t.user.darkMode }}</span>
            </template>
          </DropdownMenuItem>
          <DropdownMenuItem
            @click="
              resetChangePwdDialog();
              changePwdOpen = true;
            "
          >
            <KeyRound class="h-4 w-4 mr-2" />
            <span>{{ t.user.changePassword }}</span>
          </DropdownMenuItem>

          <DropdownMenuSeparator />

          <DropdownMenuItem
            class="text-destructive focus:text-destructive"
            :disabled="loggingOut"
            @click="handleLogout()"
          >
            <LogOut class="h-4 w-4 mr-2" />
            <span>{{ t.user.signOut }}</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>

    <Dialog :open="changePwdOpen" @update:open="onChangePwdOpenChange">
      <DialogContent class="sm:max-w-[420px]">
        <DialogHeader>
          <DialogTitle>{{ t.user.changePassword }}</DialogTitle>
        </DialogHeader>

        <div class="space-y-3">
          <div>
            <p class="mb-1.5 text-xs font-medium text-foreground">{{ t.user.newPassword }}</p>
            <Input
              type="password"
              v-model="newPassword"
              :placeholder="t.user.newPasswordPlaceholder"
              :disabled="savingPwd"
            />
          </div>
          <div>
            <p class="mb-1.5 text-xs font-medium text-foreground">{{ t.user.confirmPassword }}</p>
            <Input
              type="password"
              v-model="confirmPassword"
              :placeholder="t.user.confirmPasswordPlaceholder"
              :disabled="savingPwd"
            />
          </div>
        </div>

        <DialogFooter class="flex w-full items-center justify-between gap-3 sm:justify-between">
          <div class="min-h-8 flex flex-1 items-center">
            <FeedbackTip
              v-if="tip"
              :key="tip.id"
              :message="tip.text"
              :variant="tip.variant"
              truncate
              class="max-w-[220px]"
            />
          </div>
          <div class="flex items-center gap-2">
            <Button variant="outline" :disabled="savingPwd" @click="changePwdOpen = false">
              {{ t.devices.actions.cancel }}
            </Button>
            <Button :disabled="savingPwd" @click="handleChangePassword()">
              <Loader2 v-if="savingPwd" class="mr-2 h-4 w-4 animate-spin" />
              {{ t.user.changePasswordSubmit }}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </aside>
</template>
