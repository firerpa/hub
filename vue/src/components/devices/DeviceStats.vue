<script setup lang="ts">
import { computed } from "vue";
import { Activity, Monitor, Wifi, WifiOff } from "lucide-vue-next";
import { useTranslation } from "@/lib/i18n";

const props = defineProps<{
  total: number;
  usable: number;
  working: number;
  offline: number;
}>();

const { t } = useTranslation();

const cards = computed(() => {
  const safeTotal = Math.max(0, props.total || 0);
  const safeUsable = Math.max(0, props.usable || 0);
  const safeWorking = Math.max(0, props.working || 0);
  const safeOffline = Math.max(0, props.offline || 0);
  const percent = (n: number) => (safeTotal > 0 ? Math.round((n / safeTotal) * 100) : 0);

  return [
    {
      label: t.value.stats.totalDevices,
      sublabel: t.value.stats.totalDevicesDesc,
      value: safeTotal,
      percentText: "",
      icon: Monitor,
      iconBg: "bg-orange-50",
      iconColor: "text-orange-500",
      valueColor: "text-gray-900",
      accent: "border-l-orange-500",
    },
    {
      label: t.value.stats.availableDevices,
      sublabel: t.value.stats.availableDevicesDesc,
      value: safeUsable,
      percentText: `${percent(safeUsable)}%`,
      icon: Wifi,
      iconBg: "bg-green-50",
      iconColor: "text-green-500",
      valueColor: "text-green-600",
      accent: "border-l-green-500",
    },
    {
      label: t.value.stats.busyDevices,
      sublabel: t.value.stats.busyDevicesDesc,
      value: safeWorking,
      percentText: `${percent(safeWorking)}%`,
      icon: Activity,
      iconBg: "bg-amber-50",
      iconColor: "text-amber-500",
      valueColor: "text-amber-600",
      accent: "border-l-amber-500",
    },
    {
      label: t.value.stats.offlineDevices,
      sublabel: t.value.stats.offlineDevicesDesc,
      value: safeOffline,
      percentText: `${percent(safeOffline)}%`,
      icon: WifiOff,
      iconBg: "bg-gray-50",
      iconColor: "text-gray-400",
      valueColor: "text-gray-500",
      accent: "border-l-gray-400",
    },
  ];
});
</script>

<template>
  <div class="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
    <div
      v-for="card in cards"
      :key="card.label"
      :class="`flex items-center gap-3 rounded-lg border border-gray-100 border-l-2 bg-white px-4 py-3 shadow-sm ${card.accent}`"
    >
      <div :class="`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${card.iconBg}`">
        <component :is="card.icon" :class="`h-[18px] w-[18px] ${card.iconColor}`" :stroke-width="1.8" />
      </div>
      <div class="min-w-0 flex-1">
        <div class="flex items-baseline gap-2">
          <span :class="`text-2xl font-bold leading-none ${card.valueColor}`">{{ card.value }}</span>
          <span v-if="card.percentText" class="text-xs font-medium text-gray-400">{{ card.percentText }}</span>
        </div>
        <div class="mt-1">
          <div class="truncate text-xs font-medium leading-none text-gray-700">{{ card.label }}</div>
          <div class="mt-0.5 truncate text-[11px] leading-none text-gray-400">{{ card.sublabel }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
