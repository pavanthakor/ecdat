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

/** `POST /scans/{id}/rescore` and `POST /scans/{id}/fix`. */
export interface DerivedCreated {
  scan_id: string;
  parent_scan_id: string;
  kind: string;
}
