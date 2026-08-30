<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { setupMonaco, monaco } from "./env";

const props = withDefaults(
  defineProps<{
    modelValue?: string;
    value?: string;
    height?: string;
    defaultLanguage?: string;
    language?: string;
    theme?: string;
    options?: monaco.editor.IStandaloneEditorConstructionOptions;
    defaultValue?: string;
  }>(),
  { height: "100%", defaultLanguage: "python", theme: "light" },
);

const emit = defineEmits<{
  "update:modelValue": [value: string];
  change: [value: string];
  mount: [editor: monaco.editor.IStandaloneCodeEditor, monacoInstance: typeof monaco];
}>();

const containerRef = ref<HTMLDivElement | null>(null);
let editor: monaco.editor.IStandaloneCodeEditor | null = null;
let suppressChange = false;

onMounted(() => {
  if (!containerRef.value) return;
  const monacoInstance = setupMonaco();
  editor = monacoInstance.editor.create(containerRef.value, {
    value: props.value ?? props.modelValue ?? props.defaultValue ?? "",
    language: props.language ?? props.defaultLanguage,
    theme: props.theme,
    ...(props.options || {}),
  });

  editor.onDidChangeModelContent(() => {
    if (suppressChange || !editor) return;
    const v = editor.getValue();
    emit("update:modelValue", v);
    emit("change", v);
  });

  emit("mount", editor, monacoInstance);
});

watch(
  () => props.value ?? props.modelValue,
  (next) => {
    if (!editor || next == null) return;
    if (editor.getValue() !== next) {
      suppressChange = true;
      editor.setValue(next);
      suppressChange = false;
    }
  },
);

watch(
  () => props.theme,
  (next) => {
    if (next) setupMonaco().editor.setTheme(next);
  },
);

onBeforeUnmount(() => {
  editor?.dispose();
  editor = null;
});
</script>

<template>
  <div ref="containerRef" :style="{ height, width: '100%' }" />
</template>
