<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { setupMonaco, monaco } from "./env";

const props = withDefaults(
  defineProps<{
    original?: string;
    modified?: string;
    height?: string;
    language?: string;
    theme?: string;
    options?: monaco.editor.IDiffEditorConstructionOptions;
  }>(),
  { height: "100%", language: "python", theme: "light" },
);

const emit = defineEmits<{
  mount: [editor: monaco.editor.IStandaloneDiffEditor, monacoInstance: typeof monaco];
}>();

const containerRef = ref<HTMLDivElement | null>(null);
let editor: monaco.editor.IStandaloneDiffEditor | null = null;

onMounted(() => {
  if (!containerRef.value) return;
  const monacoInstance = setupMonaco();
  editor = monacoInstance.editor.createDiffEditor(containerRef.value, {
    theme: props.theme,
    ...(props.options || {}),
  });
  editor.setModel({
    original: monacoInstance.editor.createModel(props.original ?? "", props.language),
    modified: monacoInstance.editor.createModel(props.modified ?? "", props.language),
  });
  emit("mount", editor, monacoInstance);
});

watch(
  () => [props.original, props.modified],
  ([original, modified]) => {
    if (!editor) return;
    const monacoInstance = setupMonaco();
    const model = editor.getModel();
    if (model) {
      if (model.original.getValue() !== (original ?? "")) model.original.setValue(original ?? "");
      if (model.modified.getValue() !== (modified ?? "")) model.modified.setValue(modified ?? "");
    } else {
      editor.setModel({
        original: monacoInstance.editor.createModel(original ?? "", props.language),
        modified: monacoInstance.editor.createModel(modified ?? "", props.language),
      });
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
  const model = editor?.getModel();
  editor?.dispose();
  model?.original.dispose();
  model?.modified.dispose();
  editor = null;
});
</script>

<template>
  <div ref="containerRef" :style="{ height, width: '100%' }" />
</template>
