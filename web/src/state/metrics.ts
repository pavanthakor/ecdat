/**
 * Every number the console shows that is not read verbatim off a document.
 *
 * ADR-0018 says the console reads and does not score. ADR-0031 makes that a
 * rule a reviewer can check, number by number. A value on screen is exactly
 * one of:
 *
 *   1. a STORED value -- a score, band, deadline, count on the scan row;
 *   2. a COUNT of stored facts in the loaded document; or
 *   3. a RATIO of two such counts, rendered with both of them visible.
 *
 * Anything else is `not-computed`, and a not-computed metric is a distinct
 * state with a reason -- never a zero, never a placeholder bar. A plausible
 * number looks exactly like a true one, which is why this matters more on a
 * dashboard than anywhere else in the tool.
 *
 * Nothing here feeds a score. The one place arithmetic touches Mosca terms --
 * the horizon delta -- is the inequality itself, evaluated on stored x/y/z
 * and rendered with its terms, never fed back into a band.
 */
import type { Artefact, Band, ScanSummary, View } from "@/api/types";
import { VIEWS } from "@/api/types";

export type Measured<T> =
  | { status: "computed"; value: T; basis: string }
  | { status: "not-computed"; reason: string };

export function computed<T>(value: T, basis: string): Measured<T> {
  return { status: "computed", value, basis };
}

export function notComputed<T>(reason: string): Measured<T> {
  return { status: "not-computed", reason };
}

function percent(part: number, whole: number): number {
  return Math.round((part / whole) * 100);
}

const BAND_RANK: Record<Band, number> = { Critical: 3, High: 2, Medium: 1, Low: 0 };

/** Worst first: score, then band, then name, then bom-ref -- a TOTAL order. */
export function sortByRisk(artefacts: Artefact[]): Artefact[] {
  return [...artefacts].sort(
    (a, b) =>
      b.score - a.score ||
      BAND_RANK[b.band] - BAND_RANK[a.band] ||
      a.name.localeCompare(b.name) ||
      a.bomRef.localeCompare(b.bomRef),
  );
}

// ---------------------------------------------------------------------------
// Crypto agility
// ---------------------------------------------------------------------------

export interface Agility {
  configurable: number;
  hardCoded: number;
  /** No scanner determined configurability. Not counted as hard-coded. */
  unassessed: number;
  /** configurable / (configurable + hard-coded). Unassessed are excluded. */
  share: Measured<number>;
  /** Not built: nothing detects key-store or HSM custody. */
  keyStore: Measured<number>;
  /** Not built: nothing measures whether an endpoint can renegotiate. */
  protocol: Measured<number>;
  /** Hard-coded components, worst first -- where agility work pays. */
  improve: Artefact[];
}

export const KEY_STORE_REASON =
  "ECDAT does not yet detect whether key material is held in a key store or HSM";
export const PROTOCOL_REASON =
  "ECDAT does not yet measure whether an endpoint can renegotiate its algorithms";

export function agility(artefacts: Artefact[]): Agility {
  const configurable = artefacts.filter((a) => a.configurable === true).length;
  const hardCoded = artefacts.filter((a) => a.configurable === false).length;
  const assessed = configurable + hardCoded;
  return {
    configurable,
    hardCoded,
    unassessed: artefacts.length - assessed,
    share:
      assessed === 0
        ? notComputed("no component in this scan carries a configurability finding")
        : computed(
            percent(configurable, assessed),
            `${configurable} of ${assessed} components with a configurability finding`,
          ),
    keyStore: notComputed(KEY_STORE_REASON),
    protocol: notComputed(PROTOCOL_REASON),
    improve: sortByRisk(artefacts.filter((a) => a.configurable === false)),
  };
}

// ---------------------------------------------------------------------------
// Quantum exposure
// ---------------------------------------------------------------------------

export interface QuantumExposure {
  /** `quantum_status: broken` -- Shor breaks it outright. */
  broken: number;
  /** `quantum_status: weakened` -- Grover halves its margin. */
  weakened: number;
  assessed: number;
  /** No pack rule gave a quantum verdict. Not "safe". */
  unassessed: number;
}

export function quantumExposure(artefacts: Artefact[]): QuantumExposure {
  const assessed = artefacts.filter((a) => a.quantumStatus !== null).length;
  return {
    broken: artefacts.filter((a) => a.quantumStatus === "broken").length,
    weakened: artefacts.filter((a) => a.quantumStatus === "weakened").length,
    assessed,
    unassessed: artefacts.length - assessed,
  };
}

// ---------------------------------------------------------------------------
// View coverage
// ---------------------------------------------------------------------------

/** Where an artefact was seen: its correlation group, else its own sightings. */
export function seenViews(artefact: Artefact): string[] {
  return artefact.coverageViews.length > 0 ? artefact.coverageViews : artefact.views;
}

export interface ViewCoverage {
  /** Views with at least one sighting in this document, in VIEWS order. */
  collected: View[];
  /** collected / three, as a percentage. */
  share: Measured<number>;
  /** Per view: how many artefacts were seen in it. */
  pulse: Record<View, { seen: number; total: number; percent: number }>;
}

export function collectedViews(artefacts: Artefact[]): View[] {
  return VIEWS.filter((view) =>
    artefacts.some((a) => a.views.includes(view) || a.coverageViews.includes(view)),
  );
}

export function viewCoverage(artefacts: Artefact[]): ViewCoverage {
  const collected = collectedViews(artefacts);
  const total = artefacts.length;
  const pulse = Object.fromEntries(
    VIEWS.map((view) => {
      const seen = artefacts.filter((a) => seenViews(a).includes(view)).length;
      return [view, { seen, total, percent: total === 0 ? 0 : percent(seen, total) }];
    }),
  ) as ViewCoverage["pulse"];
  return {
    collected,
    share:
      total === 0
        ? notComputed("this scan holds no artefacts to attribute a view to")
        : computed(
            percent(collected.length, VIEWS.length),
            `${collected.length} of ${VIEWS.length} views collected (${collected.join(", ")})`,
          ),
    pulse,
  };
}

/**
 * The drift headline, off the STORED row -- or why there is none.
 *
 * Drift needs two views. With one, the honest answer is "cannot be assessed",
 * because "no drift" would claim the views agree when only one was looked at
 * (ADR-0012: a missing view is a coverage gap, never drift).
 */
export function driftMeasure(
  scan: ScanSummary | null,
  artefacts: Artefact[],
): Measured<number> {
  if (!scan) return notComputed("no scan selected");
  const collected = collectedViews(artefacts);
  if (collected.length < 2) {
    return notComputed(
      collected.length === 0
        ? "no view was collected, and drift needs at least two"
        : `only the ${collected[0]} view was collected, and drift needs at least two`,
    );
  }
  const counts = scan.drift_counts ?? {};
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
  return computed(
    total,
    total === 0
      ? `${collected.join(", ")} collected — the views agree`
      : Object.entries(counts)
          .map(([kind, n]) => `${n} ${kind}`)
          .join(" · "),
  );
}

// ---------------------------------------------------------------------------
// Scan status
// ---------------------------------------------------------------------------

export type ScanStatusKind = "COMPLETE" | "PARTIAL" | "UNKNOWN" | "DERIVED";

/**
 * A scan's status, from its row -- with the rule stated, because nothing on
 * the row says "complete" by itself.
 *
 * `scanners_ran` records the OFFERED set, not whether each plugin applied,
 * ran or finished -- skipped and failed scanners are logged, not stored
 * (PUNCHLIST). So COMPLETE means only what the row can support: scanners were
 * recorded and no component was correlated against a group missing a view.
 */
export function scanStatus(scan: ScanSummary): { status: ScanStatusKind; reason: string } {
  if (scan.kind !== "scan") {
    return {
      status: "DERIVED",
      reason: `a ${scan.kind} of ${scan.parent_scan_id?.slice(0, 8) ?? "an unrecorded scan"}; its coverage is its parent's`,
    };
  }
  if (scan.scanners_ran === null) {
    return {
      status: "UNKNOWN",
      reason: "this row predates scanners_ran, so what ran cannot be established",
    };
  }
  if (scan.scanners_ran.length === 0) {
    return { status: "PARTIAL", reason: "no scanner was selected for this scan" };
  }
  if (scan.coverage_gaps > 0) {
    return {
      status: "PARTIAL",
      reason: `${scan.coverage_gaps} component(s) were correlated against a group missing at least one view`,
    };
  }
  return { status: "COMPLETE", reason: "no component is missing a view" };
}

// ---------------------------------------------------------------------------
// Mosca terms
// ---------------------------------------------------------------------------

export interface Range {
  min: number;
  max: number;
}

export interface MoscaSummary {
  /** x -- years the data must stay secret. */
  x: Measured<Range>;
  /** y -- years a migration takes. An ESTIMATE, not a measurement. */
  y: Measured<Range>;
  /** z -- the horizon the loaded document was scored at. */
  z: number | null;
  /** min over components of z - (x + y); negative means exposed today. */
  delta: Measured<{ worst: number; exposed: number; assessed: number }>;
}

function rangeOf(values: (number | null)[], term: string): Measured<Range> {
  const present = values.filter((v): v is number => v !== null);
  if (present.length === 0) return notComputed(`no component carries a ${term} term`);
  return computed(
    { min: Math.min(...present), max: Math.max(...present) },
    `${present.length} component(s)`,
  );
}

export function moscaSummary(artefacts: Artefact[]): MoscaSummary {
  const z = artefacts.find((a) => a.zYears !== null)?.zYears ?? null;
  const gaps = artefacts
    .filter((a) => a.xYears !== null && a.yYears !== null && a.zYears !== null)
    .map((a) => (a.zYears as number) - ((a.xYears as number) + (a.yYears as number)));
  return {
    x: rangeOf(
      artefacts.map((a) => a.xYears),
      "data-lifetime (x)",
    ),
    y: rangeOf(
      artefacts.map((a) => a.yYears),
      "migration-time (y)",
    ),
    z,
    delta:
      gaps.length === 0
        ? notComputed("no component carries all three Mosca terms")
        : computed(
            {
              worst: Math.min(...gaps),
              exposed: gaps.filter((gap) => gap < 0).length,
              assessed: gaps.length,
            },
            "z − (x + y), per component",
          ),
  };
}

// ---------------------------------------------------------------------------
// Queue and histogram
// ---------------------------------------------------------------------------

export function priorityQueue(artefacts: Artefact[], limit = 8): Artefact[] {
  return sortByRisk(artefacts).slice(0, limit);
}

/** The band a ten-point bucket falls in. The policy thresholds sit on tens. */
export function bucketBand(floor: number): Band {
  return floor >= 80 ? "Critical" : floor >= 60 ? "High" : floor >= 40 ? "Medium" : "Low";
}

export function scoreHistogram(
  artefacts: Artefact[],
): { floor: number; count: number; band: Band }[] {
  const buckets = Array.from({ length: 10 }, (_, index) => ({
    floor: index * 10,
    count: 0,
    band: bucketBand(index * 10),
  }));
  for (const artefact of artefacts) {
    buckets[Math.max(0, Math.min(9, Math.floor(artefact.score / 10)))].count += 1;
  }
  return buckets;
}

// ---------------------------------------------------------------------------
// Migration roadmap
// ---------------------------------------------------------------------------

/**
 * The migration target, as the pack LABELLED it (ADR-0030).
 *
 * A family, never a parameter set: the pack says ML-DSA, not ML-DSA-65, and
 * the console does not choose one on its behalf. No label, no target.
 */
export function targetOf(artefact: Artefact): string | null {
  if (artefact.labels.includes("target-ml-dsa")) return "ML-DSA";
  if (artefact.labels.includes("target-ml-kem")) return "ML-KEM";
  if (artefact.labels.includes("target-depends-on-usage")) return "ML-KEM or ML-DSA";
  return null;
}

function hybridOf(artefact: Artefact): boolean | null {
  const raw = artefact.params.hybrid?.toLowerCase();
  if (raw === "true") return true;
  if (raw === "false") return false;
  return null;
}

export interface RoadmapRow {
  artefact: Artefact;
  deadline: string;
  overdue: boolean;
  column: string;
  target: string | null;
  hybrid: boolean | null;
  provisional: boolean;
}

export interface Roadmap {
  columns: string[];
  rows: RoadmapRow[];
  clusters: { deadline: string; rows: RoadmapRow[] }[];
  /** Artefacts no pack gave a deadline. Listed, never placed on the axis. */
  undated: Artefact[];
}

export function roadmapOf(artefacts: Artefact[], today: string): Roadmap {
  const year = Number.parseInt(today.slice(0, 4), 10);
  const columns = ["overdue", `${year}`, `${year + 1}`, `${year + 2}`, `${year + 3}+`];
  const columnOf = (deadline: string): string => {
    if (deadline < today) return "overdue";
    const due = Number.parseInt(deadline.slice(0, 4), 10);
    if (due <= year) return `${year}`;
    if (due >= year + 3) return `${year + 3}+`;
    return `${due}`;
  };

  const dated = sortByRisk(artefacts.filter((a) => a.deadline !== null));
  const rows = dated
    .map((artefact) => {
      const deadline = artefact.deadline as string;
      return {
        artefact,
        deadline,
        overdue: deadline < today,
        column: columnOf(deadline),
        target: targetOf(artefact),
        hybrid: hybridOf(artefact),
        provisional: artefact.deadlineProvisional,
      };
    })
    .sort((a, b) => a.deadline.localeCompare(b.deadline));

  const clusters: Roadmap["clusters"] = [];
  for (const row of rows) {
    const last = clusters[clusters.length - 1];
    if (last && last.deadline === row.deadline) last.rows.push(row);
    else clusters.push({ deadline: row.deadline, rows: [row] });
  }

  return {
    columns,
    rows,
    clusters,
    undated: sortByRisk(artefacts.filter((a) => a.deadline === null)),
  };
}

// ---------------------------------------------------------------------------
// Drift: Declared -> Shipped -> Observed
// ---------------------------------------------------------------------------

/**
 * Which view the `observed` side of each drift rule is actually from.
 *
 * `ecdat:drift:observed` is the OTHER side of the disagreement, and for R1 that
 * side is the shipped image, not a handshake (correlate/drift.py). Keyed on
 * the backend's kind constants; an unknown kind falls back to the views its
 * evidence cites rather than being assumed to be runtime.
 */
const COMPARED_VIEW: Record<string, View> = {
  "shipped-cannot-do-declared": "shipped",
  "declared-pqc-observed-classical": "observed",
  "declared-pqc-observed-unconfirmed": "observed",
  "protocol-downgrade": "observed",
  "cipher-outside-declared-set": "observed",
};

export type CellRole = "stated" | "compared" | "not-compared" | "not-collected";

export interface DriftCell {
  view: View;
  role: CellRole;
  value: string | null;
  /** Solid vs dashed on screen. Null where the view says nothing. */
  provenance: "verified" | "provisional" | null;
}

export interface DriftPanel {
  key: string;
  artefact: Artefact;
  kind: string;
  declared: string;
  observed: string;
  cause: string;
  /** The correlator's confidence as a percentage; 50 = backed by an absence. */
  confidence: number | null;
  comparedView: View;
  cells: Record<View, DriftCell>;
  peers: string[];
  evidence: string[];
}

function comparedViewOf(kind: string, evidence: string[]): View {
  const known = COMPARED_VIEW[kind];
  if (known) return known;
  const cited = evidence.map((entry) => entry.split("|", 1)[0]);
  if (cited.includes("shipped") && !cited.includes("observed")) return "shipped";
  return "observed";
}

export function driftPanelsOf(artefacts: Artefact[]): DriftPanel[] {
  const collected = collectedViews(artefacts);
  const panels = new Map<string, DriftPanel>();

  for (const artefact of sortByRisk(artefacts)) {
    for (const drift of artefact.drift) {
      const key = [artefact.bomRef, drift.kind, drift.declared, drift.observed].join("|");
      const existing = panels.get(key);
      if (existing) {
        existing.peers = [...new Set([...existing.peers, ...drift.peers])].sort();
        existing.evidence = [...new Set([...existing.evidence, ...drift.evidence])];
        continue;
      }
      const raw = drift.confidence === null ? Number.NaN : Number.parseFloat(drift.confidence);
      const confidence = Number.isNaN(raw) ? null : Math.round(raw * 100);
      const comparedView = comparedViewOf(drift.kind, drift.evidence);
      const cell = (view: View): DriftCell => {
        if (view === "declared") {
          return { view, role: "stated", value: drift.declared, provenance: "verified" };
        }
        if (view === comparedView) {
          return {
            view,
            role: "compared",
            value: drift.observed,
            // Confirmed by two positive sightings, or backed by an absence.
            provenance: confidence !== null && confidence >= 100 ? "verified" : "provisional",
          };
        }
        return {
          view,
          role: collected.includes(view) ? "not-compared" : "not-collected",
          value: null,
          provenance: null,
        };
      };
      panels.set(key, {
        key,
        artefact,
        kind: drift.kind,
        declared: drift.declared,
        observed: drift.observed,
        cause: drift.cause,
        confidence,
        comparedView,
        cells: { declared: cell("declared"), shipped: cell("shipped"), observed: cell("observed") },
        peers: [...new Set(drift.peers)].sort(),
        evidence: [...new Set(drift.evidence)],
      });
    }
  }
  return [...panels.values()];
}

// ---------------------------------------------------------------------------
// Scanner coverage
// ---------------------------------------------------------------------------

export const SCANNER_LABELS: Record<string, string> = {
  source: "Source",
  deps: "Dependencies",
  container: "Container",
  binary: "Binary",
  config: "Configuration",
  "runtime-spool": "Runtime TLS",
};

export const SCANNER_VIEW: Record<string, View> = {
  source: "declared",
  deps: "declared",
  config: "declared",
  container: "shipped",
  binary: "shipped",
  "runtime-spool": "observed",
};

export interface ScannerCard {
  id: string;
  label: string;
  /**
   * SELECTED = in the row's `scanners_ran`, which records the OFFERED set
   * (core/orchestrator.py: `scanner_records(scanners)`), not the outcome. A
   * repo scan's row lists the binary scanner although the orchestrator
   * skipped it; ran / skipped / failed is only in the server log (PUNCHLIST).
   * So the console never says "ran".
   */
  status: "SELECTED" | "NOT RUN" | "UNKNOWN";
  /** Artefacts with at least one sighting attributed to this scanner. */
  artefacts: number;
  /** Of those, how many carry an unverified (unscored) fact. */
  provisional: number;
  /** Installed engine, "UNAVAILABLE" when not installed, null when none. */
  engine: string | null;
  version: string | null;
}

function scannersOf(artefact: Artefact): Set<string> {
  const ids = new Set<string>();
  for (const occurrence of artefact.occurrences) {
    for (const id of occurrence.scanner.split(",")) if (id) ids.add(id.trim());
  }
  return ids;
}

export function scannerCoverage(
  scan: ScanSummary,
  available: string[] | null,
  artefacts: Artefact[],
): ScannerCard[] {
  const recorded = scan.scanners_ran;
  const ids = available ?? (recorded ?? []).map((entry) => entry.id);
  return ids.map((id) => {
    const cited = artefacts.filter((a) => scannersOf(a).has(id));
    const entry = recorded?.find((r) => r.id === id);
    const engine = scan.engine_versions?.[id] as
      | { pinned?: string | null; installed?: string | null }
      | undefined;
    let engineLabel: string | null = null;
    if (engine && typeof engine === "object") {
      if (!engine.installed) engineLabel = "UNAVAILABLE";
      else if (engine.pinned && engine.installed !== engine.pinned) {
        engineLabel = `${engine.installed} (pinned ${engine.pinned})`;
      } else engineLabel = engine.installed;
    }
    return {
      id,
      label: SCANNER_LABELS[id] ?? id,
      status: recorded === null ? "UNKNOWN" : entry ? "SELECTED" : "NOT RUN",
      artefacts: cited.length,
      provisional: cited.filter((a) => a.provisional).length,
      engine: engineLabel,
      version: entry?.version ?? null,
    };
  });
}

// ---------------------------------------------------------------------------
// Fixes
// ---------------------------------------------------------------------------

/** Lines a unified diff adds and removes, and how many files it touches. */
export function diffStats(diff: string): { added: number; removed: number; files: number } {
  let added = 0;
  let removed = 0;
  let files = 0;
  for (const line of diff.split("\n")) {
    if (line.startsWith("+++ ")) files += 1;
    else if (line.startsWith("--- ")) continue;
    else if (line.startsWith("+")) added += 1;
    else if (line.startsWith("-")) removed += 1;
  }
  return { added, removed, files };
}

/** "FIPS 180-4" out of a template's citation, or null. Never invented. */
export function fipsTag(source: string | null): string | null {
  if (!source) return null;
  const match = /FIPS[\s-]?(\d{2,3}(?:-\d+)?)/.exec(source);
  return match ? `FIPS ${match[1]}` : null;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

function csvCell(value: string | number | boolean | null): string {
  const text = value === null ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * The Inventory as CSV -- the same stored values the table shows, one row per
 * artefact. A projection, not a report: nothing is scored or summarised.
 */
export function inventoryCsv(artefacts: Artefact[]): string {
  const header = [
    "bom_ref",
    "name",
    "view",
    "band",
    "score",
    "usage",
    "endpoint",
    "deadline",
    "provisional",
    "drift",
    "locations",
  ];
  const rows = artefacts.map((a) =>
    [
      a.bomRef,
      a.name,
      a.view,
      a.band,
      a.score,
      a.usage,
      a.endpoint,
      a.deadline,
      a.provisional,
      a.drift.map((d) => d.kind).join(" "),
      a.occurrences.map((o) => o.locator).join(" "),
    ]
      .map(csvCell)
      .join(","),
  );
  return `${[header.join(","), ...rows].join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

/**
 * Which scan to compare a head against, from the links the store keeps.
 *
 * A derived row compares against its PARENT (what did this rescore move?);
 * a scan against the previous scan of the same system. Nothing else is
 * guessed -- with no such row, there is no default and the screen asks.
 */
export function defaultComparison(
  scans: ScanSummary[],
  head: ScanSummary,
): { base: ScanSummary | null; head: ScanSummary } {
  if (head.kind !== "scan" && head.parent_scan_id) {
    return { base: scans.find((s) => s.id === head.parent_scan_id) ?? null, head };
  }
  const scope = (s: ScanSummary) => s.target.system ?? s.target.ref;
  const previous = scans
    .filter(
      (s) =>
        s.kind === "scan" &&
        s.id !== head.id &&
        scope(s) === scope(head) &&
        s.created_at < head.created_at,
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  return { base: previous[0] ?? null, head };
}
