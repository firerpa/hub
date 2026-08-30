<script setup lang="ts">
import { computed, ref, watch } from "vue";

const props = withDefaults(defineProps<{ color?: string }>(), { color: "#ff0000" });
const emit = defineEmits<{ change: [color: string] }>();

type Hsv = { h: number; s: number; v: number };

function hexToHsv(hex: string): Hsv {
  let clean = hex.replace("#", "");
  if (clean.length === 3) clean = clean.split("").map((c) => c + c).join("");
  const num = parseInt(clean, 16);
  const r = ((num >> 16) & 255) / 255;
  const g = ((num >> 8) & 255) / 255;
  const b = (num & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  let h = 0;
  if (d !== 0) {
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h *= 60;
    if (h < 0) h += 360;
  }
  const s = max === 0 ? 0 : d / max;
  return { h, s, v: max };
}

function hsvToHex({ h, s, v }: Hsv): string {
  const c = v * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = v - c;
  let r = 0, g = 0, b = 0;
  if (h < 60) [r, g, b] = [c, x, 0];
  else if (h < 120) [r, g, b] = [x, c, 0];
  else if (h < 180) [r, g, b] = [0, c, x];
  else if (h < 240) [r, g, b] = [0, x, c];
  else if (h < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  const to = (n: number) => Math.round((n + m) * 255).toString(16).padStart(2, "0");
  return `#${to(r)}${to(g)}${to(b)}`;
}

function equalColor(a: string, b: string) {
  return a.toLowerCase() === b.toLowerCase();
}

const hsv = ref<Hsv>(hexToHsv(props.color));

watch(
  () => props.color,
  (next) => {
    if (!equalColor(next, hsvToHex(hsv.value))) {
      hsv.value = hexToHsv(next);
    }
  },
);

function updateHsv(next: Partial<Hsv>) {
  hsv.value = { ...hsv.value, ...next };
  const hex = hsvToHex(hsv.value);
  if (!equalColor(hex, props.color)) emit("change", hex);
}

const saturationEl = ref<HTMLDivElement | null>(null);
const hueEl = ref<HTMLDivElement | null>(null);

function clamp01(n: number) {
  return Math.min(1, Math.max(0, n));
}

function handleSaturation(e: PointerEvent) {
  const el = saturationEl.value;
  if (!el) return;
  const rect = el.getBoundingClientRect();
  const s = clamp01((e.clientX - rect.left) / rect.width);
  const v = 1 - clamp01((e.clientY - rect.top) / rect.height);
  updateHsv({ s: s * 100, v: v * 100 });
}

function handleHue(e: PointerEvent) {
  const el = hueEl.value;
  if (!el) return;
  const rect = el.getBoundingClientRect();
  const h = clamp01((e.clientX - rect.left) / rect.width) * 360;
  updateHsv({ h });
}

function track(e: PointerEvent, el: HTMLDivElement | null, move: (ev: PointerEvent) => void) {
  if (!el || e.buttons === 0) return;
  if (e.type === "pointerdown") el.setPointerCapture(e.pointerId);
  move(e);
}

const hexColor = computed(() => hsvToHex(hsv.value));
const hueColor = computed(() => `hsl(${Math.round(hsv.value.h)}, 100%, 50%)`);
</script>

<template>
  <div class="react-colorful">
    <div class="react-colorful__saturation" :style="{ backgroundColor: hueColor }">
      <div
        ref="saturationEl"
        class="react-colorful__interactive"
        @pointerdown="(e: PointerEvent) => track(e, saturationEl, handleSaturation)"
        @pointermove="(e: PointerEvent) => e.buttons === 1 && handleSaturation(e)"
      >
        <div
          class="react-colorful__pointer react-colorful__saturation-pointer"
          :style="{
            top: `${100 - hsv.v}%`,
            left: `${hsv.s}%`,
            backgroundColor: hexColor,
          }"
        />
      </div>
    </div>
    <div class="react-colorful__hue react-colorful__last-control">
      <div
        ref="hueEl"
        class="react-colorful__interactive"
        @pointerdown="(e: PointerEvent) => track(e, hueEl, handleHue)"
        @pointermove="(e: PointerEvent) => e.buttons === 1 && handleHue(e)"
      >
        <div
          class="react-colorful__pointer react-colorful__hue-pointer"
          :style="{ left: `${(hsv.h / 360) * 100}%`, backgroundColor: hueColor }"
        />
      </div>
    </div>
  </div>
</template>

<style>
.react-colorful {
  position: relative;
  display: flex;
  flex-direction: column;
  width: 200px;
  height: 200px;
  user-select: none;
  cursor: default;
}
.react-colorful__saturation {
  position: relative;
  flex-grow: 1;
  border-color: transparent;
  border-bottom: 6px solid transparent;
  border-radius: 8px 8px 0 0;
  background-image: linear-gradient(to top, #000, rgba(0, 0, 0, 0)),
    linear-gradient(to right, #fff, rgba(255, 255, 255, 0));
  box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.05);
}
.react-colorful__hue {
  position: relative;
  height: 24px;
  background: linear-gradient(
    to right,
    #f00 0%,
    #ff0 17%,
    #0f0 33%,
    #0ff 50%,
    #00f 67%,
    #f0f 83%,
    #f00 100%
  );
}
.react-colorful__last-control {
  border-radius: 0 0 8px 8px;
}
.react-colorful__interactive {
  position: absolute;
  left: 0;
  top: 0;
  right: 0;
  bottom: 0;
  border-radius: inherit;
  outline: none;
  touch-action: none;
}
.react-colorful__pointer {
  position: absolute;
  z-index: 1;
  box-sizing: border-box;
  width: 28px;
  height: 28px;
  transform: translate(-50%, -50%);
  background-color: #fff;
  border: 2px solid #fff;
  border-radius: 50%;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}
.react-colorful__interactive:focus .react-colorful__pointer {
  transform: translate(-50%, -50%) scale(1.1);
}
.react-colorful__saturation-pointer {
  z-index: 3;
}
.react-colorful__hue-pointer {
  z-index: 2;
}
</style>
