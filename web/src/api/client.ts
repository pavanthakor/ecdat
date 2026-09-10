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
 *
 * **The key (ADR-0035).** Every request carries the configured API key as
 * `Authorization: Bearer <key>`. It lives in this browser's localStorage under
 * `ecdat.apiKey`, and "Sign out" removes it. A 401 from any request tells the
 * console to ask for a key: the SERVER decides whether one is needed, so the
 * console never guesses. A 403 is an ordinary error -- the key is valid, its
 * role is not enough, and signing in again is not the fix.
 *
 * Files (the PDFs, the CBOM) come through `fetchBlob`: a plain `<a href>`
 * cannot carry a header, so it could not carry the key.
 */
import type {
  Cbom,
  CompareResponse,
  DerivedCreated,
  FixesResponse,
  Job,
  JobAccepted,
  Page,
  Principal,
  ReportKind,
  ScanSummary,
  SystemManifestIn,
  TargetIn,
} from "./types";

/** Mount point. FastAPI serves the API under `/api` and the SPA at `/`. */
export const API_BASE = "/api";

/** Where the console keeps the key. Readable by this origin's scripts only. */
export const TOKEN_STORAGE_KEY = "ecdat.apiKey";

/** How often the console asks after a queued or running job. */
export const JOB_POLL_MS = 1000;

/** FastAPI's `{"detail": ...}`, or the raw body when there is none. */
function detailOf(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === "object" && "detail" in parsed) {
      const detail = (parsed as { detail: unknown }).detail;
      return typeof detail === "string" ? detail : JSON.stringify(detail);
    }
  } catch {
    // Not JSON: the body itself is the best account of what went wrong.
  }
  return body;
}

export class ApiError extends Error {
  /** The server's own words for what went wrong. */
  readonly detail: string;

  constructor(
    readonly status: number,
    readonly path: string,
    body: string,
  ) {
    const detail = detailOf(body);
    super(`${path} failed with ${status}: ${detail.slice(0, 300)}`);
    this.name = "ApiError";
    this.detail = detail;
  }
}

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

/** Used only when the browser refuses storage (a locked-down profile). */
let memoryToken: string | null = null;

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  const store = storage();
  return store ? store.getItem(TOKEN_STORAGE_KEY) : memoryToken;
}

/** Store a key, or forget it with `null`. */
export function setToken(token: string | null): void {
  memoryToken = token;
  const store = storage();
  if (!store) return;
  if (token) store.setItem(TOKEN_STORAGE_KEY, token);
  else store.removeItem(TOKEN_STORAGE_KEY);
}

type UnauthorizedListener = (detail: string) => void;
const unauthorized = new Set<UnauthorizedListener>();

/** Hear about every 401, with the server's reason. Returns an unsubscribe. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorized.add(listener);
  return () => {
    unauthorized.delete(listener);
  };
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

interface RequestOptions extends Omit<RequestInit, "headers"> {
  headers?: Record<string, string>;
  /**
   * Send THIS key instead of the stored one, and keep a 401 to this call:
   * how the sign-in form checks a key before it is kept.
   */
  token?: string;
}

async function send(path: string, options: RequestOptions = {}): Promise<Response> {
  const { token, headers, ...init } = options;
  const key = token ?? getToken();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(key ? { Authorization: `Bearer ${key}` } : {}),
      ...headers,
    },
  });
  if (!response.ok) {
    const error = new ApiError(response.status, path, await response.text());
    if (response.status === 401 && token === undefined) {
      for (const listener of unauthorized) listener(error.detail);
    }
    throw error;
  }
  return response;
}

async function request<T>(path: string, options?: RequestOptions): Promise<T> {
  const response = await send(path, options);
  return (await response.json()) as T;
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function query(params: Record<string, string | number | undefined>): string {
  const pairs = Object.entries(params)
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(String(value))}`);
  return pairs.length > 0 ? `?${pairs.join("&")}` : "";
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/** Which key this is (or `token` would be), and its role. */
export function whoami(token?: string): Promise<Principal> {
  return request<Principal>("/auth/whoami", token === undefined ? undefined : { token });
}

export interface ListOptions {
  /** `scan`, `fix` or `rescore`; omitted = every row. */
  kind?: string;
  limit?: number;
  offset?: number;
}

/**
 * One page of stored rows, newest first, with the total (ADR-0035). No
 * options = the server's default page. Includes `fix` and `rescore` rows.
 */
export function listScans(options: ListOptions = {}): Promise<Page<ScanSummary>> {
  const { kind, limit, offset } = options;
  return request<Page<ScanSummary>>(`/scans${query({ kind, limit, offset })}`);
}

/** One row's summary -- for a scan that is not on the page in hand. */
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

/** The fix results for a scan, off its most recent fix row (ADR-0015). Admin. */
export function getFixes(scanId: string): Promise<FixesResponse> {
  return request<FixesResponse>(`/scans/${scanId}/fixes`);
}

/**
 * Queue a fix pass: copy the target, apply each template, re-scan to verify.
 * Answers at once with the JOB (ADR-0035); `waitForJob` follows it.
 */
export function runFix(scanId: string): Promise<JobAccepted> {
  return post<JobAccepted>(`/scans/${scanId}/fix`, {});
}

/** Every scanner id the server can run (the registry, ADR-0005). */
export function listScanners(): Promise<string[]> {
  return request<string[]>("/scanners");
}

/** Queue a scan of one target. Answers with the JOB, not the scan. */
export function createScan(body: TargetIn): Promise<JobAccepted> {
  return post<JobAccepted>("/scans", body);
}

/** Queue a system scan -- ONE correlated CBOM (ADR-0019). Answers with the JOB. */
export function createSystemScan(body: SystemManifestIn): Promise<JobAccepted> {
  return post<JobAccepted>("/systems/scan", body);
}

/** Where a job is: pending, running, done (with its scan id) or failed (with why). */
export function getJob(jobId: string): Promise<Job> {
  return request<Job>(`/jobs/${jobId}`);
}

/** A job that ended `failed`. Its message is the server's recorded reason. */
export class JobFailedError extends Error {
  constructor(readonly job: Job) {
    super(job.error ?? `job ${job.id} failed without a recorded reason`);
    this.name = "JobFailedError";
  }
}

export interface WaitOptions {
  intervalMs?: number;
  /** Every state the job is seen in, the final one included. */
  onUpdate?: (job: Job) => void;
  signal?: AbortSignal;
}

function aborted(): Error {
  const error = new Error("job polling aborted");
  error.name = "AbortError";
  return error;
}

function pause(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(aborted());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(aborted());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Poll a job until it is done, and return it (its `scan_id` is set). A failed
 * job rejects with `JobFailedError`; an abort rejects and stops polling.
 */
export async function waitForJob(
  jobId: string,
  { intervalMs = JOB_POLL_MS, onUpdate, signal }: WaitOptions = {},
): Promise<Job> {
  for (;;) {
    if (signal?.aborted) throw aborted();
    const job = await getJob(jobId);
    if (signal?.aborted) throw aborted();
    onUpdate?.(job);
    if (job.status === "done") return job;
    if (job.status === "failed") throw new JobFailedError(job);
    await pause(intervalMs, signal);
  }
}

/** What changed from `baseId` to `headId`, joined on bom-ref (ADR-0031). */
export function compareScans(baseId: string, headId: string): Promise<CompareResponse> {
  return request<CompareResponse>(`/scans/${baseId}/compare/${headId}`);
}

/** A report PDF, rendered on request from the stored CBOM (ADR-0020). */
export function reportPath(scanId: string, kind: ReportKind): string {
  return `/scans/${scanId}/report/${kind}`;
}

/** The stored CBOM document. */
export function cbomPath(scanId: string): string {
  return `/scans/${scanId}/cbom`;
}

/** A file the API serves, fetched WITH the key -- which a link cannot send. */
export async function fetchBlob(path: string): Promise<Blob> {
  const response = await send(path, { headers: { Accept: "*/*" } });
  return response.blob();
}
