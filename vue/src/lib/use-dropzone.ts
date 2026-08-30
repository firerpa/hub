import { computed, ref, type CSSProperties, type Ref } from "vue";

export interface FileError {
  message: string;
  code: string;
}

export interface FileRejection {
  file: File;
  errors: FileError[];
}

export interface UseDropzoneOptions {
  maxSize?: number;
  minSize?: number;
  multiple?: boolean;
  disabled?: Ref<boolean> | boolean;
  accept?: Record<string, string[]>;
  onDrop?: (acceptedFiles: File[], fileRejections: FileRejection[]) => void;
  onDropAccepted?: (acceptedFiles: File[]) => void;
  onDropRejected?: (fileRejections: FileRejection[]) => void;
}

function isDisabled(disabled: UseDropzoneOptions["disabled"]) {
  if (disabled && typeof disabled === "object" && "value" in disabled) return Boolean(disabled.value);
  return Boolean(disabled);
}

export function useDropzone(options: UseDropzoneOptions = {}) {
  const isDragActive = ref(false);
  const inputRef = ref<HTMLInputElement | null>(null);
  let dragCounter = 0;

  const validateFile = (file: File): FileError[] => {
    const errors: FileError[] = [];
    if (options.maxSize != null && file.size > options.maxSize) {
      errors.push({
        code: "file-too-large",
        message: `File is larger than ${options.maxSize} bytes`,
      });
    }
    if (options.minSize != null && file.size < options.minSize) {
      errors.push({
        code: "file-too-small",
        message: `File is smaller than ${options.minSize} bytes`,
      });
    }
    return errors;
  };

  const handleFiles = (fileList: FileList | File[] | null | undefined) => {
    if (isDisabled(options.disabled) || !fileList) return;
    let files = Array.from(fileList);
    if (options.multiple === false) files = files.slice(0, 1);

    const accepted: File[] = [];
    const rejected: FileRejection[] = [];
    for (const file of files) {
      const errors = validateFile(file);
      if (errors.length) rejected.push({ file, errors });
      else accepted.push(file);
    }

    options.onDrop?.(accepted, rejected);
    if (accepted.length) options.onDropAccepted?.(accepted);
    if (rejected.length) options.onDropRejected?.(rejected);
  };

  const openFileDialog = () => {
    if (isDisabled(options.disabled)) return;
    inputRef.value?.click();
  };

  const getRootProps = () => ({
    role: "button" as const,
    tabindex: isDisabled(options.disabled) ? -1 : 0,
    onClick: openFileDialog,
    onKeydown: (e: KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openFileDialog();
      }
    },
    onDragenter: (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (isDisabled(options.disabled)) return;
      dragCounter += 1;
      isDragActive.value = true;
    },
    onDragover: (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
    },
    onDragleave: (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounter -= 1;
      if (dragCounter <= 0) {
        dragCounter = 0;
        isDragActive.value = false;
      }
    },
    onDrop: (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounter = 0;
      isDragActive.value = false;
      handleFiles(e.dataTransfer?.files);
    },
  });

  const getInputProps = () => ({
    type: "file" as const,
    multiple: options.multiple !== false,
    style: { display: "none" } as CSSProperties,
    tabindex: -1,
    onChange: (e: Event) => {
      const input = e.target as HTMLInputElement;
      handleFiles(input.files);
      input.value = "";
    },
  });

  const setInputRef = (el: unknown) => {
    inputRef.value = (el as HTMLInputElement | null) ?? null;
  };

  return {
    getRootProps,
    getInputProps,
    isDragActive,
    open: openFileDialog,
    inputRef,
    setInputRef,
  };
}
