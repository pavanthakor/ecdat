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
  CompareResponse,
  DerivedCreated,
  FixesResponse,
  ReportKind,
  ScanCreated,
  ScanSummary,
  SystemManifestIn,
  TargetIn,
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

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Every stored row, newest first. Includes `fix` and `rescore` rows. */
export function listScans(kind?: string): Promise<ScanSummary[]> {
  return request<ScanSummary[]>(`/scans${kind ? `?kind=${kind}` : ""}`);
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

/**
 * Run a fix pass: copy the target, apply each template, re-scan to verify.
 * Synchronous and slow on the server (ADR-0015); the caller shows it running.
 */
export function runFix(scanId: string): Promise<DerivedCreated> {
  return post<DerivedCreated>(`/scans/${scanId}/fix`, {});
}

/** Every scanner id the server can run (the registry, ADR-0005). */
export function listScanners(): Promise<string[]> {
  return request<string[]>("/scanners");
}

/** Scan one target. Synchronous: the row exists when this resolves. */
export function createScan(body: TargetIn): Promise<ScanCreated> {
  return post<ScanCreated>("/scans", body);
}

/** Scan a whole system manifest into ONE correlated CBOM (ADR-0019). */
export function createSystemScan(body: SystemManifestIn): Promise<ScanCreated> {
  return post<ScanCreated>("/systems/scan", body);
}

/** What changed from `baseId` to `headId`, joined on bom-ref (ADR-0031). */
export function compareScans(baseId: string, headId: string): Promise<CompareResponse> {
  return request<CompareResponse>(`/scans/${baseId}/compare/${headId}`);
}

/** A report PDF, rendered on request from the stored CBOM (ADR-0020). */
export function reportUrl(scanId: string, kind: ReportKind): string {
  return `${API_BASE}/scans/${scanId}/report/${kind}`;
}

/** The stored CBOM document, for download. */
export function cbomUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/cbom`;
}
