/**
 * Hash routing, deliberately (ADR-0031).
 *
 * FastAPI mounts the API at `/` as well as `/api`, so a console path such as
 * `/scans` would be answered by the API's JSON on a reload. Hash routes never
 * reach the server: they work offline, need no change to the SPA catch-all,
 * and cannot collide with an endpoint added later. Twenty lines instead of a
 * router dependency.
 */
import { useMemo, useSyncExternalStore } from "react";

export type RouteId =
  | "overview"
  | "scans"
  | "inventory"
  | "risk"
  | "drift"
  | "roadmap"
  | "fixes"
  | "agility"
  | "coverage"
  | "reports"
  | "compare"
  | "settings";

export type RouteGroup = "analyze" | "plan" | "report" | "settings";

export interface RouteDef {
  id: RouteId;
  path: string;
  title: string;
  group: RouteGroup;
}

export const ROUTES: readonly RouteDef[] = [
  { id: "overview", path: "overview", title: "Overview", group: "analyze" },
  { id: "scans", path: "scans", title: "Scans", group: "analyze" },
  { id: "inventory", path: "inventory", title: "Inventory", group: "analyze" },
  { id: "risk", path: "risk-analysis", title: "Risk Analysis", group: "analyze" },
  { id: "drift", path: "drift", title: "Cryptographic Drift", group: "analyze" },
  { id: "roadmap", path: "roadmap", title: "Migration Roadmap", group: "plan" },
  { id: "fixes", path: "fixes", title: "Verified Fixes", group: "plan" },
  { id: "agility", path: "agility", title: "Crypto Agility", group: "plan" },
  { id: "coverage", path: "coverage", title: "Coverage", group: "report" },
  { id: "reports", path: "reports", title: "Reports", group: "report" },
  { id: "compare", path: "compare", title: "Compare Scans", group: "report" },
  { id: "settings", path: "settings", title: "Settings", group: "settings" },
];

export interface ParsedRoute {
  /** Null for a path no screen owns -- rendered as "not found", not guessed. */
  route: RouteId | null;
  path: string;
  params: URLSearchParams;
}

export function parseHash(hash: string): ParsedRoute {
  const raw = hash.replace(/^#\/?/, "");
  const [path = "", query = ""] = raw.split("?", 2);
  const params = new URLSearchParams(query);
  if (path === "") return { route: "overview", path, params };
  const match = ROUTES.find((r) => r.path === path);
  return { route: match?.id ?? null, path, params };
}

export function hrefFor(id: RouteId, params?: Record<string, string>): string {
  const path = ROUTES.find((r) => r.id === id)?.path ?? "overview";
  const query = params ? new URLSearchParams(params).toString() : "";
  return `#/${path}${query ? `?${query}` : ""}`;
}

/** Fired alongside `hashchange` so a navigation re-renders synchronously. */
const NAVIGATED = "qorbit:navigated";

export function navigate(id: RouteId, params?: Record<string, string>): void {
  const target = hrefFor(id, params);
  if (window.location.hash !== target) window.location.hash = target;
  window.dispatchEvent(new Event(NAVIGATED));
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  window.addEventListener(NAVIGATED, onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
    window.removeEventListener(NAVIGATED, onChange);
  };
}

export function useRoute(): ParsedRoute {
  const hash = useSyncExternalStore(
    subscribe,
    () => window.location.hash,
    () => "",
  );
  return useMemo(() => parseHash(hash), [hash]);
}
