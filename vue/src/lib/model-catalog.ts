export type ModelCatalogEntry = {
  provider?: string;
  model_id?: string;
  display_name?: string;
  context_window?: number;
  max_output_tokens?: number;
  aliases?: string[];
  supports_chat_completion?: boolean;
  supports_vision?: boolean;
};

/** Canonical context sizes kept in the Create Model dropdown. */
export const STANDARD_CONTEXT_LENGTHS = [
  128000, 200000, 256000, 512000, 1000000, 2000000, 10000000,
] as const;

export const MIN_CONTEXT_LENGTH = 128000;
export const DEFAULT_CONTEXT_LENGTH = 256000;
export const MODEL_CATALOG_URL = "/assets/model.json";

export function formatContextLength(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return String(n);
  if (n >= 1_000_000 && n % 1_000_000 === 0) return `${n / 1_000_000}M`;
  if (n >= 1_000 && n % 1_000 === 0) return `${n / 1_000}K`;
  if (n >= 1_048_576 && n % 1_048_576 === 0) return `${n / 1_048_576}M`;
  if (n >= 1_024 && n % 1_024 === 0) return `${n / 1_024}K`;
  return n.toLocaleString();
}

export function snapToStandardContextLength(n: number): number | null {
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n < MIN_CONTEXT_LENGTH) return MIN_CONTEXT_LENGTH;
  let best: number = STANDARD_CONTEXT_LENGTHS[0];
  let bestDist = Math.abs(n - best);
  for (const size of STANDARD_CONTEXT_LENGTHS) {
    const dist = Math.abs(n - size);
    if (dist < bestDist) {
      best = size;
      bestDist = dist;
    }
  }
  return best;
}

let catalogPromise: Promise<ModelCatalogEntry[]> | null = null;

export function loadModelCatalog(): Promise<ModelCatalogEntry[]> {
  if (!catalogPromise) {
    catalogPromise = fetch(MODEL_CATALOG_URL)
      .then((res) => {
        if (!res.ok) throw new Error(`catalog ${res.status}`);
        return res.json() as Promise<{ models?: ModelCatalogEntry[] }>;
      })
      .then((data) => (Array.isArray(data?.models) ? data.models : []))
      .catch(() => {
        catalogPromise = null;
        return [] as ModelCatalogEntry[];
      });
  }
  return catalogPromise;
}

export function collectContextLengths(models: ModelCatalogEntry[]): number[] {
  const seen = new Set<number>();
  for (const model of models) {
    const snapped = snapToStandardContextLength(Number(model.context_window));
    if (snapped != null) seen.add(snapped);
  }
  if (!seen.size) return [...STANDARD_CONTEXT_LENGTHS];
  return [...seen].sort((a, b) => a - b);
}

export function findCatalogModel(models: ModelCatalogEntry[], modelName: string): ModelCatalogEntry | null {
  const needle = modelName.trim().toLowerCase();
  if (!needle) return null;
  return (
    models.find((m) => {
      if ((m.model_id || "").toLowerCase() === needle) return true;
      if ((m.display_name || "").toLowerCase() === needle) return true;
      return (m.aliases || []).some((alias) => String(alias).toLowerCase() === needle);
    }) ?? null
  );
}

export function catalogMaxOutputTokens(model: ModelCatalogEntry | null | undefined): number | null {
  const n = Number(model?.max_output_tokens);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

export function matchCatalogContextLength(models: ModelCatalogEntry[], modelName: string): number | null {
  return snapToStandardContextLength(Number(findCatalogModel(models, modelName)?.context_window));
}

export type CatalogNameSuggestion = {
  value: string;
  modelId: string;
  source: "model_id" | "alias";
  contextLength: number | null;
  maxOutputTokens: number | null;
  supportsChatCompletion: boolean;
  supportsVision: boolean;
};

export function suggestCatalogModelNames(
  models: ModelCatalogEntry[],
  query: string,
  limit = 20,
): CatalogNameSuggestion[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  const seen = new Set<string>();
  const hits: Array<CatalogNameSuggestion & { prefix: boolean }> = [];

  const consider = (raw: string, model: ModelCatalogEntry, source: "model_id" | "alias") => {
    const value = String(raw || "").trim();
    if (!value) return;
    const key = value.toLowerCase();
    if (seen.has(key) || !key.includes(needle)) return;
    seen.add(key);
    const modelId = String(model.model_id || "").trim();
    hits.push({
      value,
      modelId,
      source,
      contextLength: snapToStandardContextLength(Number(model.context_window)),
      maxOutputTokens: catalogMaxOutputTokens(model),
      supportsChatCompletion: model.supports_chat_completion === true,
      supportsVision: model.supports_vision === true,
      prefix: key.startsWith(needle),
    });
  };

  for (const model of models) {
    consider(String(model.model_id || ""), model, "model_id");
    for (const alias of model.aliases || []) {
      consider(String(alias), model, "alias");
    }
  }

  hits.sort((a, b) => {
    if (a.prefix !== b.prefix) return a.prefix ? -1 : 1;
    if (a.source !== b.source) return a.source === "model_id" ? -1 : 1;
    const len = a.value.length - b.value.length;
    return len !== 0 ? len : a.value.localeCompare(b.value);
  });

  return hits.slice(0, limit).map(({ prefix: _prefix, ...item }) => item);
}
