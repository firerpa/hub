<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { Toaster } from "vue-sonner";
import LoginPage from "@/pages/LoginPage.vue";
import OverviewPage from "@/pages/OverviewPage.vue";
import DevicesPage from "@/pages/DevicesPage.vue";
import PushPage from "@/pages/devices/PushPage.vue";
import PullPage from "@/pages/devices/PullPage.vue";
import BatchCommandPage from "@/pages/devices/BatchCommandPage.vue";
import JobsPage from "@/pages/JobsPage.vue";
import ExecuteJobPage from "@/pages/jobs/ExecuteJobPage.vue";
import ScriptsPage from "@/pages/ScriptsPage.vue";
import ModelsPage from "@/pages/ModelsPage.vue";
import UsersPage from "@/pages/UsersPage.vue";
import DeviceDetailPage from "@/components/routes/DeviceDetailPage.vue";
import JobDetailPage from "@/components/routes/JobDetailPage.vue";
import ScriptDetailPage from "@/components/routes/ScriptDetailPage.vue";
import { apiRequest } from "@/lib/api";
import { useHashLocation, useHashRouter } from "@/lib/hash-router";
import { provideI18n } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";

provideI18n("zh");
const { resolvedTheme } = useTheme();

const location = useHashLocation();
const router = useHashRouter();
const authState = ref<"checking" | "in" | "out">("checking");

const pathname = computed(() => location.value.pathname);
const search = computed(() => location.value.search);

function isLoginRoute(path: string) {
  return path === "/login";
}

function isProtectedRoute(path: string) {
  return !isLoginRoute(path);
}

onMounted(async () => {
  try {
    await apiRequest("/api/v1/user/login", { cache: "no-store" });
    authState.value = "in";
  } catch {
    authState.value = "out";
  }
});

watch([authState, pathname, search], ([auth, path, s]) => {
  if (auth === "in" && isLoginRoute(path)) {
    router.replace("/devices");
    return;
  }
  if (auth === "out" && isProtectedRoute(path)) {
    const next = encodeURIComponent(`${path}${s}`);
    router.replace(`/login?next=${next}`);
  }
});

const rendered = computed(() => {
  const path = pathname.value;
  if (isLoginRoute(path)) return { component: LoginPage, key: "login" };
  if (authState.value !== "in") return { component: null, key: "loading" };

  if (path === "/") return { component: DevicesPage, key: "/" };
  if (path === "/overview") return { component: OverviewPage, key: path };
  if (path === "/devices") return { component: DevicesPage, key: path };
  if (path === "/devices/push") return { component: PushPage, key: path };
  if (path === "/devices/pull") return { component: PullPage, key: path };
  if (path === "/devices/batch-command") return { component: BatchCommandPage, key: path };
  if (path === "/jobs") return { component: JobsPage, key: path };
  if (path === "/jobs/execute") return { component: ExecuteJobPage, key: path };
  if (path === "/scripts") return { component: ScriptsPage, key: path };
  if (path === "/models") return { component: ModelsPage, key: path };
  if (path === "/users") return { component: UsersPage, key: path };
  if (/^\/devices\/[^/]+$/.test(path)) return { component: DeviceDetailPage, key: path };
  if (/^\/jobs\/[^/]+$/.test(path)) return { component: JobDetailPage, key: path };
  if (/^\/scripts\/[^/]+$/.test(path)) return { component: ScriptDetailPage, key: path };

  return { component: DevicesPage, key: "fallback" };
});
</script>

<template>
  <div
    v-if="!rendered.component"
    class="flex min-h-screen items-center justify-center text-sm text-muted-foreground"
  >
    Loading...
  </div>
  <component :is="rendered.component" v-else :key="rendered.key" />
  <Toaster
    :theme="resolvedTheme"
    class="toaster group"
    position="bottom-center"
    :duration="3000"
    :toast-options="{ class: 'max-w-[min(90vw,560px)] shadow-xl' }"
  />
</template>
