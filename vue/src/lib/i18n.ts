import { inject, provide, ref, computed, type InjectionKey, type Ref, type ComputedRef } from "vue";
import zh, { type TranslationSchema } from "./locales-zh";
import en from "./locales-en";

export type { TranslationSchema };
export type Locale = "zh" | "en";

const locales: Record<Locale, TranslationSchema> = { zh, en };
const LOCALE_STORAGE_KEY = "firerpa-locale";

export interface I18nContextValue {
  locale: Ref<Locale>;
  setLocale: (locale: Locale) => void;
  t: ComputedRef<TranslationSchema>;
}

const I18nKey: InjectionKey<I18nContextValue> = Symbol("i18n");

export function provideI18n(defaultLocale: Locale = "zh") {
  const locale = ref<Locale>(defaultLocale);

  try {
    const saved = localStorage.getItem(LOCALE_STORAGE_KEY) as Locale | null;
    if (saved && (saved === "zh" || saved === "en")) {
      locale.value = saved;
    }
  } catch (e) {
    console.error("Failed to read locale from localStorage:", e);
  }

  const setLocale = (next: Locale) => {
    locale.value = next;
    try {
      localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch (e) {
      console.error("Failed to save locale to localStorage:", e);
    }
  };

  const ctx: I18nContextValue = {
    locale,
    setLocale,
    t: computed(() => locales[locale.value]),
  };
  provide(I18nKey, ctx);
  return ctx;
}

export function useTranslation() {
  const ctx = inject(I18nKey);
  if (!ctx) throw new Error("useTranslation must be used after provideI18n");
  return ctx;
}

/** Simple template interpolation: t("hello {name}", { name: "world" }) */
export function interpolate(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? `{${key}}`));
}
