<script setup lang="ts">
import { onBeforeUnmount, watch } from "vue";

const props = defineProps<{
  deviceId: string;
  active: boolean;
  placeholder: string;
}>();

let cleanup: (() => void) | null = null;
let canvasEl: HTMLCanvasElement | null = null;

const stopPreview = () => {
  cleanup?.();
  cleanup = null;
};

const startPreview = (canvas: HTMLCanvasElement, deviceId: string) => {
  stopPreview();
  if (!deviceId) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/d/${encodeURIComponent(deviceId)}/ws/screen/10@25/live?scale=0.4&type=mjpeg&backend=0`;
  const ws = new WebSocket(wsUrl);
  ws.binaryType = "blob";

  const img = new Image();
  let closed = false;

  ws.onmessage = (evt) => {
    if (closed) return;
    const blob = evt.data instanceof Blob ? evt.data : new Blob([evt.data], { type: "image/jpeg" });
    const url = URL.createObjectURL(blob);
    img.onload = () => {
      if (!closed) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      }
      URL.revokeObjectURL(url);
    };
    img.onerror = () => URL.revokeObjectURL(url);
    img.src = url;
  };

  cleanup = () => {
    closed = true;
    ws.close();
  };
};

const bindPreview = () => {
  stopPreview();
  if (!canvasEl || !props.active || !props.deviceId) return;
  startPreview(canvasEl, props.deviceId);
};

const setCanvasRef = (el: Element | null) => {
  if (!el) {
    canvasEl = null;
    stopPreview();
    return;
  }
  canvasEl = el as HTMLCanvasElement;
  bindPreview();
};

watch([() => props.deviceId, () => props.active], bindPreview);

onBeforeUnmount(stopPreview);
</script>

<template>
  <span v-if="!active" class="text-xs text-muted-foreground">{{ placeholder }}</span>
  <canvas v-else :ref="setCanvasRef" width="540" height="960" class="h-full w-full" />
</template>
