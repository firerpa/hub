import { computed, onBeforeUnmount, ref, toValue, watch, type MaybeRefOrGetter } from "vue";

export type HashLocation = {
  pathname: string;
  search: string;
};

type HashLocationListener = (location: HashLocation) => void;
type HashNavigationBlocker = (next: HashLocation, current: HashLocation) => boolean;

function normalizePath(path: string) {
  const trimmed = (path || "").trim();
  if (!trimmed || trimmed === "#") return "/";
  if (trimmed.startsWith("/")) return trimmed;
  return `/${trimmed}`;
}

function parseHashLocation(rawHash: string): HashLocation {
  const hash = rawHash.startsWith("#") ? rawHash.slice(1) : rawHash;
  const target = hash || "/";
  const safePath = normalizePath(target);

  try {
    const url = new URL(safePath, "https://pigeon.local");
    return { pathname: normalizePath(url.pathname), search: url.search || "" };
  } catch {
    return { pathname: "/", search: "" };
  }
}

function readHashLocation(): HashLocation {
  if (typeof window === "undefined") {
    return { pathname: "/", search: "" };
  }
  return parseHashLocation(window.location.hash || "");
}

function locationsEqual(a: HashLocation, b: HashLocation) {
  return a.pathname === b.pathname && a.search === b.search;
}

function toDocumentHashUrl(location: HashLocation) {
  return `${window.location.pathname}${window.location.search}#${location.pathname}${location.search}`;
}

const locationListeners = new Set<HashLocationListener>();
let currentHashLocation: HashLocation = { pathname: "/", search: "" };
let hashNavigationBlocker: HashNavigationBlocker | null = null;
let listeningToHistory = false;

const GUARD_STATE_KEY = "__pigeonUnsavedGuard";

function isUnsavedGuardState(state: unknown) {
  return Boolean(state && typeof state === "object" && (state as Record<string, unknown>)[GUARD_STATE_KEY]);
}

function pushUnsavedGuardState(url?: string) {
  const nextUrl = url || `${window.location.pathname}${window.location.search}${window.location.hash}`;
  window.history.pushState({ [GUARD_STATE_KEY]: true }, "", nextUrl);
}

function emitHashLocation(location: HashLocation) {
  currentHashLocation = location;
  locationListeners.forEach((listener) => listener(location));
}

function restoreHashLocation(location: HashLocation) {
  pushUnsavedGuardState(toDocumentHashUrl(location));
}

function handleHistoryTraversal(event: Event) {
  const next = readHashLocation();
  const same = locationsEqual(next, currentHashLocation);

  if (hashNavigationBlocker && (!same || event.type === "popstate")) {
    if (hashNavigationBlocker(next, currentHashLocation)) {
      restoreHashLocation(currentHashLocation);
      return;
    }
  }

  if (same) return;
  emitHashLocation(next);
}

function ensureHistoryListening() {
  if (listeningToHistory || typeof window === "undefined") return;
  listeningToHistory = true;
  currentHashLocation = readHashLocation();
  window.addEventListener("hashchange", handleHistoryTraversal, true);
  window.addEventListener("popstate", handleHistoryTraversal, true);
}

export function setHashNavigationBlocker(blocker: HashNavigationBlocker | null) {
  hashNavigationBlocker = blocker;
}

export function useHashNavigationGuard(
  enabled: MaybeRefOrGetter<boolean>,
  onBlocked: (next: HashLocation, current: HashLocation) => void,
) {
  let onBlockedCurrent = onBlocked;
  let bypass = false;
  let active = false;

  const activate = () => {
    ensureHistoryListening();
    pushUnsavedGuardState();
    setHashNavigationBlocker((next, current) => {
      if (bypass) {
        bypass = false;
        return false;
      }
      onBlockedCurrent(next, current);
      return true;
    });
  };

  const deactivate = () => {
    setHashNavigationBlocker(null);
    if (isUnsavedGuardState(window.history.state)) {
      window.history.back();
    }
  };

  watch(
    () => toValue(enabled),
    (v) => {
      if (v && !active) {
        active = true;
        activate();
      } else if (!v && active) {
        active = false;
        deactivate();
      }
    },
    { immediate: true, flush: "post" },
  );

  onBeforeUnmount(() => {
    if (!active) return;
    active = false;
    deactivate();
  });

  const allowNextNavigation = () => {
    bypass = true;
  };

  const restoreGuard = () => {
    bypass = false;
  };

  return { allowNextNavigation, restoreGuard };
}

export function leaveThroughUnsavedGuard() {
  if (typeof window === "undefined") return;
  if (isUnsavedGuardState(window.history.state)) {
    window.history.go(-2);
    return;
  }
  window.history.back();
}

const globalLocation = ref<HashLocation>({ pathname: "/", search: "" });
let globalLocationInitialized = false;

export function useHashLocation() {
  if (!globalLocationInitialized) {
    globalLocationInitialized = true;
    ensureHistoryListening();
    const listener: HashLocationListener = (next) => {
      globalLocation.value = next;
    };
    locationListeners.add(listener);
    globalLocation.value = currentHashLocation;
  }
  return globalLocation;
}

export function useHashPathname() {
  return computed(() => useHashLocation().value.pathname);
}

export function toHashHref(path: string) {
  return `/#${normalizePath(path)}`;
}

export function useHashRouter() {
  const push = (path: string) => {
    if (typeof window === "undefined") return;
    window.location.hash = normalizePath(path);
  };

  const replace = (path: string) => {
    if (typeof window === "undefined") return;
    const next = toHashHref(path);
    window.history.replaceState(window.history.state, "", next);
    window.dispatchEvent(new Event("hashchange"));
  };

  const back = () => {
    if (typeof window === "undefined") return;
    window.history.back();
  };

  const refresh = () => {
    if (typeof window === "undefined") return;
    window.location.reload();
  };

  return { push, replace, back, refresh };
}

export function useHashSearchParams() {
  const location = useHashLocation();
  return computed(() => new URLSearchParams(location.value.search));
}

export function matchHashPath(pathname: string, pattern: RegExp) {
  const match = pattern.exec(pathname);
  return match?.[1] ? decodeURIComponent(match[1]) : undefined;
}
