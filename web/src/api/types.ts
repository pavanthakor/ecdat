/**
 * The wire shapes ECDAT's API actually returns.
 *
 * Written against captured responses from a real scan (see
 * `src/test/fixtures/`), not against the FastAPI models by eye: the CBOM is a
 * CycloneDX document whose ECDAT content lives in a flat, REPEATING
 * `properties` array, and getting that wrong is the kind of mistake that only
 * shows up as an empty column.
 */

/** A component's policy band. The only saturated colours in the console. */
export type Band = "Critical" | "High" | "Medium" | "Low";

/** Which of the three drift views a fact came from (ADR-0001). */
export type View = "declared" | "shipped" | "observed";

export const BANDS: readonly Band[] = ["Critical", "High", "Medium", "Low"];
export const VIEWS: readonly View[] = ["declared", "shipped", "observed"];

/** One entry in a scan row's `scanners_ran`. */
export interface ScannerRecord {
  id: string;
  version?: string;
}

/**
 * A row from `GET /scans`.
 *
 * `scanners_ran` is `null` for a scan written before the column existed and
 * `[]` when the set is known to be empty (ADR-0016). The console MUST render
 * those differently: "never looked for binaries" is not "binaries were clean".
 */
export interface ScanSummary {
  id: string;
  target: {
    kind: string;
    ref: string;
    system: string | null;
    data_class: string | null;
  };
  created_at: string;
  component_count: number;
  band_counts: Record<Band, number>;
  max_score: number;
  drift_counts: Record<string, number>;
  coverage_gaps: number;
  kind: "scan" | "fix" | "rescore";
  parent_scan_id: string | null;
  scanners_ran: ScannerRecord[] | null;
  sector: string | null;
  exposure: string | null;
  z_years: number | null;
  /** Which engine produced the scan (ADR-0017). `null` on an older row. */
  engine_versions: Record<string, unknown> | null;
  /** Set when an installed engine differed from the pinned one. */
  engine_warning: string | null;
}

/** A raw CycloneDX property. Names REPEAT -- `ecdat:actions` appears once per action. */
export interface CbomProperty {
  name: string;
  value: string;
}

export interface CbomOccurrence {
  location?: string;
  line?: number;
  additionalContext?: string;
  "bom-ref"?: string;
}

export interface CbomComponent {
  "bom-ref": string;
  name: string;
  type?: string;
  cryptoProperties?: {
    assetType?: string;
    algorithmProperties?: {
      primitive?: string;
      parameterSetIdentifier?: string;
      nistQuantumSecurityLevel?: number;
    };
    protocolProperties?: { type?: string; version?: string };
  };
  evidence?: { occurrences?: CbomOccurrence[] };
  properties?: CbomProperty[];
}

export interface Cbom {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  metadata?: Record<string, unknown>;
  components: CbomComponent[];
}

/** Drift on one component, read back off `ecdat:drift:*` (ADR-0012). */
export interface Drift {
  kind: string;
  declared: string;
  observed: string;
  cause: string;
  confidence: string | null;
  evidence: string[];
  peers: string[];
}

/** One `ecdat:occurrence`: `view|locator|scanner|detail`. */
export interface Occurrence {
  view: string;
  locator: string;
  scanner: string;
  detail: string;
  /** From the CycloneDX evidence block, when the two can be matched up. */
  snippet: string | null;
}

/**
 * A component, flattened into the shape the console renders.
 *
 * Everything here is READ from the stored document. The console never scores,
 * re-derives a band, or recomputes a count -- an opinion the dashboard formed
 * itself would be an opinion no stored CBOM could be audited against.
 */
export interface Artefact {
  bomRef: string;
  name: string;
  view: View | string;
  /**
   * EVERY view this artefact was sighted in -- `ecdat:view` repeats, one per
   * view (ADR-0002). `view` keeps the first for the table's single column.
   */
  views: string[];
  /**
   * `ecdat:configurable` (ADR-0026): true when the algorithm is chosen by
   * configuration, false when it is fixed in code, and NULL when no scanner
   * made the determination. Null is "not assessed", never "hard-coded".
   */
  configurable: boolean | null;
  band: Band;
  score: number;
  assetType: string;
  usage: string;
  primitive: string | null;
  endpoint: string | null;
  deadline: string | null;
  labels: string[];
  firedRules: string[];
  actions: string[];
  categories: { category: string; score: number }[];
  quantumStatus: string | null;
  params: Record<string, string>;
  occurrences: Occurrence[];
  drift: Drift[];
  coverageViews: string[];
  coverageMissing: string[];
  /** Mosca terms, carried so the drawer can show WHY a score moved with Z. */
  xYears: number | null;
  yYears: number | null;
  zYears: number | null;
  bases: { x: string | null; y: string | null; z: string | null };
  /**
   * True when any rule behind this verdict is unverified (ADR-0017). The
   * console must never present such a component as scored on that fact.
   */
  provisional: boolean;
  provisionalRules: string[];
  deadlineProvisional: boolean;
  /**
   * `ecdat:confidence` (ADR-0034): how sure the detector was, in [0, 1]. The
   * normaliser keeps the most confident report when it merges sightings. NULL
   * when the document records none -- "not recorded", never "certain".
   */
  confidence: number | null;
  /**
   * `ecdat:param:candidate` (ADR-0034): the rule itself called this a
   * CANDIDATE for analyst review -- a key-ish name holding a high-entropy
   * literal that was not seen reaching a crypto sink.
   */
  candidate: boolean;
  /** Fix-it results, present only on a `kind: "fix"` row (ADR-0015). */
  fix: {
    template: string;
    verified: boolean;
    reason: string;
    source: string | null;
    diff: string | null;
  } | null;
}

/** `GET /scans/{id}/fixes`. */
export interface FixEntry {
  bom_ref: string;
  component: string;
  template: string;
  verified: boolean;
  reason: string;
  source: string | null;
  diff: string | null;
}

export interface FixesResponse {
  parent_scan_id: string;
  fix_scan_id: string | null;
  created_at: string | null;
  fixes: FixEntry[];
}

/** `POST /scans/{id}/rescore`, and `POST /scans/{id}/fix?wait=true`. */
export interface DerivedCreated {
  scan_id: string;
  parent_scan_id: string;
  kind: string;
  /** The fix job, for a synchronous fix pass. A rescore is not a job. */
  job_id?: string | null;
}

/** `POST /scans?wait=true` and `POST /systems/scan?wait=true`. */
export interface ScanCreated {
  scan_id: string;
  component_count: number;
  job_id?: string | null;
}

/** One page of a list that grows with use (ADR-0035): `GET /scans`, `GET /jobs`. */
export interface Page<T> {
  items: T[];
  /** Every row the filter matches, not just this page's. */
  total: number;
  limit: number;
  offset: number;
}

export type JobStatus = "pending" | "running" | "done" | "failed";

/** `GET /jobs/{id}` -- `api.app.JobOut` (ADR-0035). */
export interface Job {
  id: string;
  /** `scan`, `system-scan` or `fix`. */
  kind: string;
  status: JobStatus;
  subject: string;
  parent_scan_id: string | null;
  /** The stored row, once `done`. */
  scan_id: string | null;
  /** Why it failed, once `failed`: the exception's type and message. */
  error: string | null;
  /** The NAME of the key that asked. */
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

/** The 202 body of `POST /scans`, `POST /systems/scan`, `POST /scans/{id}/fix`. */
export interface JobAccepted {
  job_id: string;
  kind: string;
  status: JobStatus;
}

export type Role = "viewer" | "admin";

/** `GET /auth/whoami`: the key's name and role -- never the key. */
export interface Principal {
  name: string;
  role: Role;
}

export type TargetKind = "repo" | "directory" | "image" | "host" | "endpoint" | "spool";
export type Sector =
  | "government"
  | "strategic"
  | "defence"
  | "power"
  | "telecom"
  | "transport"
  | "bfsi"
  | "other";
export type Exposure = "internet" | "internal" | "build" | "unknown";

/** The body of `POST /scans` -- `api.app.TargetIn`. */
export interface TargetIn {
  kind: TargetKind;
  ref: string;
  system?: string | null;
  data_class?: string | null;
  sector?: Sector;
  exposure?: Exposure;
  z_years?: number;
  /** Omitted = every registered scanner; `[]` = none, honoured as such. */
  scanners?: string[] | null;
}

/** The body of `POST /systems/scan` -- `api.app.SystemManifestIn`. */
export interface SystemManifestIn {
  system: string;
  targets: { kind: string; ref: string }[];
  sector?: string;
  exposure?: string;
  data_class?: string | null;
  z_years?: number;
}

/** `GET /scans/{a}/compare/{b}` (ADR-0031) -- joined on bom-ref. */
export interface CompareVerdict {
  band: string | null;
  score: number | null;
  deadline: string | null;
  quantum_status: string | null;
}

export interface CompareEntry {
  bom_ref: string;
  name: string;
  band: string | null;
  score: number | null;
  deadline: string | null;
}

export interface CompareChange {
  bom_ref: string;
  name: string;
  fields: string[];
  before: CompareVerdict;
  after: CompareVerdict;
  evidence_added: string[];
  evidence_removed: string[];
}

export interface CompareDrift {
  bom_ref: string;
  name: string;
  kind: string;
  declared: string;
  observed: string;
  cause: string;
}

export interface CompareResponse {
  base: { id: string; kind: string; created_at: string; system: string | null };
  head: { id: string; kind: string; created_at: string; system: string | null };
  new: CompareEntry[];
  resolved: CompareEntry[];
  changed: CompareChange[];
  drift_introduced: CompareDrift[];
  drift_resolved: CompareDrift[];
  unchanged: number;
}

/** The three PDFs `GET /scans/{id}/report/{kind}` renders (ADR-0020). */
export type ReportKind = "executive" | "technical" | "coverage";
