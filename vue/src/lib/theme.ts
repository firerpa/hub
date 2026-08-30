import { computed, ref } from "vue";

export type Theme = "light" | "dark";

const STORAGE_KEY = "theme";
const DEFAULT_THEME: Theme = "light";

const theme = ref<Theme>(readStoredTheme());
let applied = false;

function readStoredTheme(): Theme {
  if (typeof window === "undefined") return DEFAULT_THEME;
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // ignore
  }
  return DEFAULT_THEME;
}

function applyTheme(next: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.remove("light", "dark");
  root.classList.add(next);
  root.style.colorScheme = next;
}

export function useTheme() {
  if (!applied) {
    applied = true;
    applyTheme(theme.value);
  }

  const setTheme = (next: Theme) => {
    theme.value = next;
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore
    }
    // disableTransitionOnChange
    const css = document.createElement("style");
    css.appendChild(
      document.createTextNode(
        "*{-webkit-transition:none!important;-moz-transition:none!important;-o-transition:none!important;-ms-transition:none!important;transition:none!important}",
      ),
    );
    document.head.appendChild(css);
    applyTheme(next);
    requestAnimationFrame(() => {
      document.head.removeChild(css);
    });
  };

  return {
    theme,
    resolvedTheme: computed(() => theme.value),
    setTheme,
  };
}
