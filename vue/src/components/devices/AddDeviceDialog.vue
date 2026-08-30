<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ArrowRightLeft, Link2, RotateCw, Wifi } from "lucide-vue-next";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";

type ConnectionMode = "direct" | "p2p" | "forward";
type AddressMode = "fixed" | "segment";

type ScanStatus = "found" | "connected" | "failed";
type ScanItem = { ip: string; port: number; status: ScanStatus };

const props = defineProps<{
  open: boolean;
  onConfirm: (data: any) => Promise<any>;
}>();

const emit = defineEmits<{
  "update:open": [open: boolean];
}>();

function parseIPv4(input: string): [number, number, number, number] | null {
  const value = input.trim();
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((x) => Number(x));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return [nums[0], nums[1], nums[2], nums[3]];
}

function ipv4ToInt(ip: [number, number, number, number]) {
  return (
    ((ip[0] & 0xff) << 24) |
    ((ip[1] & 0xff) << 16) |
    ((ip[2] & 0xff) << 8) |
    (ip[3] & 0xff)
  ) >>> 0;
}

function intToIpv4(value: number) {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

function maskToLength(mask: [number, number, number, number]) {
  const m = ipv4ToInt(mask);
  let seenZero = false;
  let len = 0;
  for (let i = 31; i >= 0; i -= 1) {
    const bit = (m >>> i) & 1;
    if (bit === 1) {
      if (seenZero) return null;
      len += 1;
    } else {
      seenZero = true;
    }
  }
  return len;
}

const { t } = useTranslation();
const mode = ref<ConnectionMode>("direct");
const addressMode = ref<AddressMode>("fixed");
const loading = ref(false);
const tip = ref<{ id: number; text: string; variant: "success" | "error" | "info" } | null>(null);

// 直连 - 固定地址
const directFixedIp = ref("");
const directFixedPort = ref("65000");
const directFixedRemark = ref("");

// 直连 - 网段扫描
const directSegmentIp = ref("");
const directSegmentMask = ref("");
const directSegmentStart = ref("");
const directSegmentEnd = ref("");
const directSegmentPort = ref("65000");

// P2P模式
const p2pRemark = ref("");

// 转发模式
const forwardRemark = ref("");

// 二阶扫描结果弹窗
const scanResultOpen = ref(false);
const scanList = ref<ScanItem[]>([]);
const scanSelectedIps = ref<Set<string>>(new Set());
const scanBatchLoading = ref(false);
const scanTip = ref<{ id: number; text: string; variant: "success" | "error" | "info" } | null>(null);

const scanStatusText = computed(() => ({
  found: t.value.devices.addDevice_scanFound,
  connected: t.value.devices.addDevice_scanConnected,
  failed: t.value.devices.addDevice_scanFailed,
}));

const scanStatusClass = (status: ScanStatus) => {
  if (status === "connected") return "text-[var(--status-online)]";
  if (status === "failed") return "text-destructive";
  return "text-muted-foreground";
};

const sanitizeIpv4 = (value: string) => value.replace(/[^0-9.]/g, "");

const clearForm = () => {
  mode.value = "direct";
  addressMode.value = "fixed";
  loading.value = false;
  tip.value = null;
  directFixedIp.value = "";
  directFixedPort.value = "65000";
  directFixedRemark.value = "";
  directSegmentIp.value = "";
  directSegmentMask.value = "";
  directSegmentStart.value = "";
  directSegmentEnd.value = "";
  directSegmentPort.value = "65000";
  p2pRemark.value = "";
  forwardRemark.value = "";
  scanResultOpen.value = false;
  scanList.value = [];
  scanSelectedIps.value = new Set();
  scanBatchLoading.value = false;
  scanTip.value = null;
};

watch(
  () => props.open,
  (open) => {
    if (!open) {
      clearForm();
    }
  },
);

watch([mode, addressMode, directSegmentIp, directSegmentMask], () => {
  if (mode.value !== "direct" || addressMode.value !== "segment") return;
  const seg = parseIPv4(directSegmentIp.value);
  const mask = parseIPv4(directSegmentMask.value);
  if (!seg || !mask) return;
  const ipInt = ipv4ToInt(seg);
  const maskInt = ipv4ToInt(mask);
  const networkInt = ipInt & maskInt;
  const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;
  directSegmentStart.value = intToIpv4(networkInt);
  directSegmentEnd.value = intToIpv4(broadcastInt);
});

const handleConfirm = async () => {
  try {
    tip.value = null;
    loading.value = true;

    if (mode.value === "direct" && addressMode.value === "fixed") {
      const ip = directFixedIp.value.trim();
      const port = directFixedPort.value.trim();
      if (!ip) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_ipRequired, variant: "error" };
        return;
      }
      if (!port) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_portRequired, variant: "error" };
        return;
      }
    }

    if (mode.value === "direct" && addressMode.value === "segment") {
      const seg = parseIPv4(directSegmentIp.value);
      const mask = parseIPv4(directSegmentMask.value);
      if (!seg) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_segmentInvalid, variant: "error" };
        return;
      }
      if (!mask) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_maskInvalid, variant: "error" };
        return;
      }
      const maskLen = maskToLength(mask);
      if (maskLen === null) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_maskNotContinuous, variant: "error" };
        return;
      }
      const startIp = parseIPv4(directSegmentStart.value);
      const endIp = parseIPv4(directSegmentEnd.value);
      if (!startIp) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_startRequired, variant: "error" };
        return;
      }
      if (!endIp) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_endRequired, variant: "error" };
        return;
      }
      const segInt = ipv4ToInt(seg);
      const maskInt = ipv4ToInt(mask);
      const networkInt = segInt & maskInt;
      const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;
      const startInt = ipv4ToInt(startIp);
      const endInt = ipv4ToInt(endIp);
      if (startInt < networkInt || endInt > broadcastInt) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_rangeOutOfSubnet, variant: "error" };
        return;
      }
      if (startInt > endInt) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_startGreaterThanEnd, variant: "error" };
        return;
      }
      const port = directSegmentPort.value.trim();
      if (!port) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_portRequired, variant: "error" };
        return;
      }
    }

    const payload = {
      mode: mode.value,
      addressMode: mode.value === "direct" ? addressMode.value : null,
      ...(mode.value === "direct"
        ? addressMode.value === "fixed"
          ? {
              ip: directFixedIp.value.trim(),
              port: directFixedPort.value.trim(),
              remark: directFixedRemark.value.trim(),
            }
          : {
              segmentIp: directSegmentIp.value.trim(),
              segmentMask: directSegmentMask.value.trim(),
              rangeStart: directSegmentStart.value.trim(),
              rangeEnd: directSegmentEnd.value.trim(),
              port: directSegmentPort.value.trim(),
            }
        : mode.value === "forward"
        ? { remark: forwardRemark.value.trim() }
        : { remark: p2pRemark.value.trim() }),
    };

    const result = await props.onConfirm(payload);
    if (mode.value === "direct" && addressMode.value === "segment") {
      const listRaw = Array.isArray(result?.data) ? result.data : [];
      const list: ScanItem[] = listRaw
        .map((item: any) => ({
          ip: String(item?.ip || "").trim(),
          port: Number(item?.port || 65000),
          status: "found" as const,
        }))
        .filter((item: ScanItem) => item.ip);
      scanList.value = list;
      scanSelectedIps.value = new Set(list.map((item) => item.ip));
      if (!list.length) {
        tip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_scanNoResult, variant: "info" };
        return;
      }
      scanTip.value = null;
      scanResultOpen.value = true;
      return;
    }

    emit("update:open", false);
  } catch (err: any) {
    tip.value = { id: Date.now() + Math.random(), text: err?.message || "Failed to add device", variant: "error" };
  } finally {
    loading.value = false;
  }
};

const onToggleSelectAllScan = (checked: boolean) => {
  if (checked) {
    scanSelectedIps.value = new Set(scanList.value.map((item) => item.ip));
  } else {
    scanSelectedIps.value = new Set();
  }
};

const onToggleScanIp = (ip: string, checked: boolean) => {
  const next = new Set(scanSelectedIps.value);
  if (checked) next.add(ip);
  else next.delete(ip);
  scanSelectedIps.value = next;
};

const handleBatchConnect = async () => {
  if (!scanSelectedIps.value.size) {
    scanTip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_selectScannedFirst, variant: "error" };
    return;
  }
  scanBatchLoading.value = true;
  scanTip.value = null;
  let success = 0;
  let failed = 0;
  try {
    for (const item of scanList.value) {
      if (!scanSelectedIps.value.has(item.ip)) continue;
      try {
        await props.onConfirm({
          mode: "direct",
          addressMode: "fixed",
          ip: item.ip,
          port: String(item.port || 65000),
          remark: item.ip,
        });
        success += 1;
        item.status = "connected";
      } catch {
        failed += 1;
        item.status = "failed";
      }
    }
    scanList.value = [...scanList.value];
    if (failed > 0) {
      scanTip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_batchConnectPartial.replace("{ok}", String(success)).replace("{failed}", String(failed)), variant: "error" };
    } else {
      scanTip.value = { id: Date.now() + Math.random(), text: t.value.devices.addDevice_batchConnectSuccess.replace("{ok}", String(success)), variant: "success" };
      scanResultOpen.value = false;
      emit("update:open", false);
    }
  } finally {
    scanBatchLoading.value = false;
  }
};

const allScanSelected = computed(() => scanList.value.length > 0 && scanSelectedIps.value.size === scanList.value.length);
const partialScanSelected = computed(() => scanSelectedIps.value.size > 0 && !allScanSelected.value);

const onScanResultOpenChange = (next: boolean) => {
  if (!scanBatchLoading.value) scanResultOpen.value = next;
  if (!next) scanTip.value = null;
};
</script>

<template>
  <Dialog :open="open" @update:open="emit('update:open', $event)">
    <DialogContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{{ t.devices.addDialogTitle }}</DialogTitle>
      </DialogHeader>

      <div class="space-y-6 py-4">
        <!-- Connection Mode Selection - Card Style -->
        <div class="grid grid-cols-3 gap-3">
          <!-- Direct Connection Card -->
          <button
            @click="mode = 'direct'"
            :class="cn(
              'rounded-lg border-2 p-4 transition-all duration-200 text-left',
              mode === 'direct'
                ? 'border-primary bg-primary/5'
                : 'border-border bg-muted/30 hover:border-muted-foreground/50'
            )"
          >
            <div class="flex items-start gap-3">
              <Wifi :class="cn(
                'h-5 w-5 mt-0.5 shrink-0',
                mode === 'direct' ? 'text-primary' : 'text-muted-foreground'
              )" />
              <div>
                <p class="font-semibold text-sm">{{ t.devices.addDevice_direct }}</p>
              </div>
            </div>
          </button>

          <!-- P2P Connection Card -->
          <button
            @click="mode = 'p2p'"
            :class="cn(
              'rounded-lg border-2 p-4 transition-all duration-200 text-left',
              mode === 'p2p'
                ? 'border-primary bg-primary/5'
                : 'border-border bg-muted/30 hover:border-muted-foreground/50'
            )"
          >
            <div class="flex items-start gap-3">
              <Link2 :class="cn(
                'h-5 w-5 mt-0.5 shrink-0',
                mode === 'p2p' ? 'text-primary' : 'text-muted-foreground'
              )" />
              <div>
                <p class="font-semibold text-sm">{{ t.devices.addDevice_p2p }}</p>
              </div>
            </div>
          </button>
          <!-- Forward Connection Card -->
          <button
            @click="mode = 'forward'"
            :class="cn(
              'rounded-lg border-2 p-4 transition-all duration-200 text-left',
              mode === 'forward'
                ? 'border-primary bg-primary/5'
                : 'border-border bg-muted/30 hover:border-muted-foreground/50'
            )"
          >
            <div class="flex items-start gap-3">
              <ArrowRightLeft :class="cn(
                'h-5 w-5 mt-0.5 shrink-0',
                mode === 'forward' ? 'text-primary' : 'text-muted-foreground'
              )" />
              <div>
                <p class="font-semibold text-sm">{{ t.devices.addDevice_forward }}</p>
              </div>
            </div>
          </button>
        </div>

        <!-- Mode description hint -->
        <p class="text-xs text-muted-foreground leading-relaxed -mt-2 px-0.5">
          {{ mode === 'direct'
            ? t.devices.addDevice_directHint
            : mode === 'p2p'
            ? t.devices.addDevice_p2pHint
            : t.devices.addDevice_forwardHint }}
        </p>

        <!-- Content based on mode -->
        <div v-if="mode === 'direct'" class="space-y-4 pt-2">
          <!-- Address Mode Tabs -->
          <Tabs
            :model-value="addressMode"
            @update:model-value="addressMode = $event as AddressMode"
          >
            <TabsList class="grid w-full grid-cols-2 bg-muted/50">
              <TabsTrigger value="fixed" class="text-xs">
                {{ t.devices.addDevice_fixed }}
              </TabsTrigger>
              <TabsTrigger value="segment" class="text-xs">
                {{ t.devices.addDevice_segment }}
              </TabsTrigger>
            </TabsList>

            <!-- Fixed Address Tab -->
            <TabsContent value="fixed" class="space-y-3 mt-4">
              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_ip }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <Input
                  :placeholder="t.devices.addDevice_ipPlaceholder"
                  v-model="directFixedIp"
                  class="font-mono text-xs h-9"
                />
              </div>

              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_port }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <Input
                  placeholder="65000"
                  v-model="directFixedPort"
                  type="number"
                  class="font-mono text-xs h-9"
                />
              </div>

              <div class="space-y-2">
                <Label class="text-xs font-semibold text-muted-foreground">
                  {{ t.devices.addDevice_remark }}
                </Label>
                <Input
                  :placeholder="t.devices.addDevice_remarkPlaceholder"
                  v-model="directFixedRemark"
                  class="text-xs h-9"
                />
              </div>
            </TabsContent>

            <!-- Segment Scan Tab -->
            <TabsContent value="segment" class="space-y-3 mt-4">
              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_segmentIp }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <Input
                  :placeholder="t.devices.addDevice_segmentIpPlaceholder"
                  :model-value="directSegmentIp"
                  @update:model-value="directSegmentIp = sanitizeIpv4($event)"
                  class="font-mono text-xs h-9"
                />
              </div>

              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_mask }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <Input
                  :placeholder="t.devices.addDevice_maskPlaceholder"
                  :model-value="directSegmentMask"
                  @update:model-value="directSegmentMask = sanitizeIpv4($event)"
                  class="font-mono text-xs h-9"
                />
              </div>

              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_addressRange }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <div class="flex items-center gap-2">
                  <Input
                    :placeholder="t.devices.addDevice_rangeStart"
                    :model-value="directSegmentStart"
                    @update:model-value="directSegmentStart = sanitizeIpv4($event)"
                    class="font-mono text-xs h-9 flex-1"
                  />
                  <span class="text-xs text-muted-foreground px-2">
                    {{ t.devices.addDevice_to }}
                  </span>
                  <Input
                    :placeholder="t.devices.addDevice_rangeEnd"
                    :model-value="directSegmentEnd"
                    @update:model-value="directSegmentEnd = sanitizeIpv4($event)"
                    class="font-mono text-xs h-9 flex-1"
                  />
                </div>
              </div>

              <div class="space-y-2">
                <Label class="text-xs font-semibold">
                  {{ t.devices.addDevice_port }}
                  <span class="text-destructive ml-1">*</span>
                </Label>
                <Input
                  placeholder="65000"
                  v-model="directSegmentPort"
                  type="number"
                  class="font-mono text-xs h-9"
                />
              </div>
            </TabsContent>
          </Tabs>
        </div>
        <!-- P2P Connection Content -->
        <div v-else-if="mode === 'p2p'" class="space-y-3 pt-2">
          <div class="space-y-2">
            <Label class="text-xs font-semibold text-muted-foreground">
              {{ t.devices.addDevice_remark }}
            </Label>
            <Input
              :placeholder="t.devices.addDevice_remarkPlaceholder"
              v-model="p2pRemark"
              class="text-xs h-9"
            />
          </div>
        </div>
        <!-- Forward Connection Content -->
        <div v-else class="space-y-3 pt-2">
          <div class="space-y-2">
            <Label class="text-xs font-semibold text-muted-foreground">
              {{ t.devices.addDevice_remark }}
            </Label>
            <Input
              :placeholder="t.devices.addDevice_remarkPlaceholder"
              v-model="forwardRemark"
              class="text-xs h-9"
            />
          </div>
        </div>
      </div>

      <!-- Footer Actions -->
      <div class="flex w-full items-center justify-between gap-3 pt-2">
        <div class="min-h-5">
          <FeedbackTip v-if="tip" :key="tip.id" :toast-id="tip.id" :message="tip.text" :variant="tip.variant" compact class-name="max-w-[360px]" truncate />
        </div>
        <div class="flex items-center gap-2">
          <Button
            variant="outline"
            @click="emit('update:open', false)"
            :disabled="loading"
            size="sm"
          >
            {{ t.devices.actions.cancel }}
          </Button>
          <Button @click="handleConfirm" :disabled="loading" size="sm">
            {{ loading ? t.devices.addDevice_scanning : t.devices.actions.confirmAdd }}
          </Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
  <Dialog :open="scanResultOpen" @update:open="onScanResultOpenChange">
    <DialogContent class="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{{ t.devices.addDevice_scanResultTitle }}</DialogTitle>
      </DialogHeader>
      <div class="space-y-3">
        <div class="flex items-center justify-between text-xs text-muted-foreground">
          <span>{{ t.devices.addDevice_scanResultDesc }}</span>
          <span>{{ t.devices.addDevice_scanResultCount.replace("{n}", String(scanList.length)) }}</span>
        </div>
        <div class="rounded-md border border-border">
          <div class="grid grid-cols-[36px_1fr_100px] items-center border-b border-border bg-muted/30 px-3 py-2 text-xs font-medium text-muted-foreground">
            <Checkbox
              :checked="allScanSelected ? true : partialScanSelected ? 'indeterminate' : false"
              @update:checked="onToggleSelectAllScan($event)"
            />
            <span>{{ t.devices.addDevice_ip }}</span>
            <span class="text-right">{{ t.devices.table.status }}</span>
          </div>
          <ScrollArea class="max-h-[320px]">
            <div class="divide-y divide-border/60">
              <label v-for="item in scanList" :key="item.ip" class="grid cursor-pointer grid-cols-[36px_1fr_100px] items-center px-3 py-2 text-xs hover:bg-muted/30">
                <Checkbox
                  :checked="scanSelectedIps.has(item.ip)"
                  @update:checked="onToggleScanIp(item.ip, $event)"
                />
                <span class="font-mono">{{ item.ip }}:{{ item.port }}</span>
                <span :class="cn('text-right', scanStatusClass(item.status))">{{ scanStatusText[item.status] }}</span>
              </label>
            </div>
          </ScrollArea>
        </div>
      </div>
      <DialogFooter>
        <div class="flex w-full items-center justify-between gap-3">
          <div class="min-h-5">
            <FeedbackTip v-if="scanTip" :key="scanTip.id" :toast-id="scanTip.id" :message="scanTip.text" :variant="scanTip.variant" compact class-name="max-w-[320px]" truncate />
          </div>
          <div class="flex items-center gap-2">
            <Button variant="outline" size="sm" class="h-8 text-xs" @click="scanResultOpen = false" :disabled="scanBatchLoading">
              {{ t.devices.actions.cancel }}
            </Button>
            <Button size="sm" class="h-8 text-xs" @click="void handleBatchConnect()" :disabled="scanBatchLoading || scanSelectedIps.size === 0">
              <RotateCw v-if="scanBatchLoading" class="mr-1 h-3.5 w-3.5 animate-spin" />
              {{ t.devices.addDevice_connectSelected }}
            </Button>
          </div>
        </div>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
