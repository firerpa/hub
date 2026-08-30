export type ApiEnvelope<T> = {
  status?: number;
  error?: string;
  message?: string;
  data?: T;
};

export class ApiRequestError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
  }
}

function toMessage(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== "object") return fallback;
  const m = (payload as { message?: unknown }).message;
  const e = (payload as { error?: unknown }).error;
  if (typeof m === "string" && m) return m;
  if (typeof e === "string" && e) return e;
  return fallback;
}

function toCode(payload: unknown) {
  if (!payload || typeof payload !== "object") return undefined;
  const e = (payload as { error?: unknown }).error;
  return typeof e === "string" ? e : undefined;
}

export async function apiRequest<T>(
  input: string,
  init?: RequestInit & { errorMessage?: string },
) {
  const headers = new Headers(init?.headers || {});
  const isJsonBody =
    init?.body &&
    typeof init.body === "string" &&
    !headers.has("Content-Type");
  if (isJsonBody) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(input, {
    credentials: "include",
    ...init,
    headers,
  });

  const raw = await response.text();
  let payload: ApiEnvelope<T> = {};
  try {
    payload = raw ? (JSON.parse(raw) as ApiEnvelope<T>) : {};
  } catch {
    payload = {};
  }

  const httpError = !response.ok;
  const businessError =
    typeof payload.status === "number" && payload.status !== 0;

  if (httpError || businessError) {
    throw new ApiRequestError(
      toMessage(payload, init?.errorMessage || "Request failed"),
      response.status || 500,
      toCode(payload),
    );
  }

  return payload;
}

export function formatApiError(err: unknown, fallback: string) {
  if (err instanceof ApiRequestError) {
    return err.code ? `${err.message} (${err.code})` : err.message;
  }
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}
