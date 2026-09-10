/**
 * The typed HTTP client. Same-origin only.
 *
 * The console is served BY FastAPI out of `web/dist`, so every request is
 * same-origin and relative -- there is no configurable base URL, no CDN, and
 * nothing to point at a third party. That is not a simplification: ECDAT's
 * offline guarantee is a promise about the whole tool, and a dashboard that
 * could be pointed elsewhere is a dashboard that will be.
 *
 * In development Vite proxies `/api` to `127.0.0.1:8000` (see vite.config.ts),
 * so the same relative paths work without a build.
 */
import type {
  Cbom,
  DerivedCreated,
  FixesResponse,
  ScanSummary,
} from "./types";

/** Mount point. FastAPI serves the API under `/api` and the SPA at `/`. */
export const API_BASE = "/api";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    body: string,
  ) {
    super(`${path} failed with ${status}: ${body.slice(0, 200)}`);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json" },
    ...init,
  });
  if (!response.ok) {
    throw new ApiError(response.status, path, await response.text());
  }
  return (await response.json()) as T;
}

/** Every stored row, newest first. Includes `fix` and `rescore` rows. */
export function listScans(kind?: string): Promise<ScanSummary[]> {
  return request<ScanSummary[]>(`/scans${kind ? `?kind=${kind}` : ""}`);
}

/** One row's denormalised summary -- no CBOM parse (ADR-0016). */
export function getScan(scanId: string): Promise<ScanSummary> {
  return request<ScanSummary>(`/scans/${scanId}`);
}

/** The stored document, verbatim bytes. */
export function getCbom(scanId: string): Promise<Cbom> {
  return request<Cbom>(`/scans/${scanId}/cbom`);
}

/**
 * Re-score a stored CBOM against a new CRQC horizon.
 *
 * Returns the NEW row's id -- a rescore is a fresh linked row, never an edit
 * of the scan it came from (ADR-0016), so the caller fetches that row's
 * document rather than expecting this to hand back the estate.
 */
export function rescore(scanId: string, zYears: number): Promise<DerivedCreated> {
  return request<DerivedCreated>(`/scans/${scanId}/rescore?z_years=${zYears}`, {
    method: "POST",
  });
}

/** The fix results for a scan, off its most recent fix row (ADR-0015). */
export function getFixes(scanId: string): Promise<FixesResponse> {
  return request<FixesResponse>(`/scans/${scanId}/fixes`);
}
