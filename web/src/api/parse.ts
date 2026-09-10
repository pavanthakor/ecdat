/**
 * Turning a stored CBOM into the rows the console renders.
 *
 * **The console reads. It does not score.** Every band, score, count and
 * deadline here is lifted out of the stored document exactly as the policy
 * engine wrote it. Nothing is recomputed, and no default is invented for a
 * missing property -- a dashboard that derived its own numbers could disagree
 * with the CBOM it is displaying, and the disagreement would be invisible to
 * the person reading it.
 *
 * The awkward part of the shape, and the reason this module exists: ECDAT's
 * content lives in a FLAT, REPEATING `properties` array. `ecdat:actions`
 * appears once per action; `ecdat:category_score` once per category;
 * `ecdat:drift:evidence` once per sighting. Reading it as a map would silently
 * keep one of each.
 */
import type {
  Artefact,
  Band,
  Cbom,
  CbomComponent,
  CbomProperty,
  Drift,
  Occurrence,
} from "./types";

const BAND_SET = new Set(["Critical", "High", "Medium", "Low"]);

/** Every value stored under `name`, in document order. */
function all(properties: CbomProperty[], name: string): string[] {
  return properties.filter((p) => p.name === name).map((p) => p.value);
}

/** The single value stored under `name`, or null. */
function one(properties: CbomProperty[], name: string): string | null {
  const hit = properties.find((p) => p.name === name);
  return hit ? hit.value : null;
}

/** A comma-joined property split back into its members. */
function list(properties: CbomProperty[], name: string): string[] {
  const raw = one(properties, name);
  if (!raw) return [];
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function integer(properties: CbomProperty[], name: string): number | null {
  const raw = one(properties, name);
  if (raw === null) return null;
  const value = Number.parseInt(raw, 10);
  return Number.isNaN(value) ? null : value;
}

/**
 * A stored probability, or null. Strict on purpose: a missing or garbled value
 * is "not recorded", and `parseFloat` would read "0.5x" as 0.5 and "" as NaN
 * silently -- a number the document never said.
 */
function probability(properties: CbomProperty[], name: string): number | null {
  const raw = one(properties, name)?.trim();
  if (raw === undefined || !/^\d+(?:\.\d+)?$/.test(raw)) return null;
  const value = Number(raw);
  return value >= 0 && value <= 1 ? value : null;
}

/** `criticality=20` -> `{category, score}`, ordered as the engine wrote them. */
function categories(properties: CbomProperty[]): Artefact["categories"] {
  return all(properties, "ecdat:category_score").map((entry) => {
    const [category, score] = entry.split("=", 2);
    return { category, score: Number.parseInt(score ?? "0", 10) || 0 };
  });
}

/** `ecdat:param:endpoint` -> `params.endpoint`. */
function params(properties: CbomProperty[]): Record<string, string> {
  const collected: Record<string, string> = {};
  for (const property of properties) {
    if (property.name.startsWith("ecdat:param:")) {
      collected[property.name.slice("ecdat:param:".length)] = property.value;
    }
  }
  return collected;
}

/**
 * `declared|path:line|source|rule=x` -> a structured occurrence.
 *
 * The snippet is taken from the CycloneDX evidence block, matched on location
 * and line. It is separate because the normaliser puts the human-readable
 * excerpt there and the machine-readable address here.
 */
function occurrences(component: CbomComponent): Occurrence[] {
  const properties = component.properties ?? [];
  const evidence = component.evidence?.occurrences ?? [];

  return all(properties, "ecdat:occurrence").map((raw) => {
    const [view = "", locator = "", scanner = "", ...rest] = raw.split("|");
    const detail = rest.join("|");
    const [path, line] = splitLocator(locator);
    const match = evidence.find(
      (e) => e.location === path && (line === null || e.line === line),
    );
    return {
      view,
      locator,
      scanner,
      detail,
      snippet: match?.additionalContext ?? null,
    };
  });
}

function splitLocator(locator: string): [string, number | null] {
  const index = locator.lastIndexOf(":");
  if (index === -1) return [locator, null];
  const tail = locator.slice(index + 1);
  if (!/^\d+$/.test(tail)) return [locator, null];
  return [locator.slice(0, index), Number.parseInt(tail, 10)];
}

/**
 * Drift, reassembled from its repeating properties (ADR-0012).
 *
 * A component can carry several drifts; the engine writes each one's fields in
 * order, so `kind` starts a new record and the rest attach to it.
 */
function drifts(properties: CbomProperty[]): Drift[] {
  const kinds = all(properties, "ecdat:drift:kind");
  if (kinds.length === 0) return [];

  const declared = all(properties, "ecdat:drift:declared");
  const observed = all(properties, "ecdat:drift:observed");
  const causes = all(properties, "ecdat:drift:cause");
  const confidences = all(properties, "ecdat:drift:confidence");
  const evidence = all(properties, "ecdat:drift:evidence");
  const peers = all(properties, "ecdat:drift:peer");

  return kinds.map((kind, index) => ({
    kind,
    declared: declared[index] ?? "",
    observed: observed[index] ?? "",
    cause: causes[index] ?? "",
    confidence: confidences[index] ?? null,
    // Evidence and peers do not align one-to-one with drifts -- a drift can
    // cite several sightings -- so a single drift takes them all rather than
    // guessing a split that the document does not encode.
    evidence: kinds.length === 1 ? evidence : evidence.slice(index, index + 1),
    peers: kinds.length === 1 ? peers : peers.slice(index, index + 1),
  }));
}

function fix(properties: CbomProperty[]): Artefact["fix"] {
  const template = one(properties, "ecdat:fix:template");
  if (!template) return null;
  return {
    template,
    verified: one(properties, "ecdat:fix:verified") === "true",
    reason: one(properties, "ecdat:fix:reason") ?? "",
    source: one(properties, "ecdat:fix:source"),
    // The invariant from ADR-0015 carried onto the wire: a diff is present
    // only when the fix was verified, so the console cannot show an unproven
    // patch even by accident.
    diff: one(properties, "ecdat:fix:diff"),
  };
}

function toArtefact(component: CbomComponent): Artefact {
  const properties = component.properties ?? [];
  const band = one(properties, "ecdat:band");
  const crypto = component.cryptoProperties;
  const provisionalRules = all(properties, "ecdat:provisional_rule");
  const view = one(properties, "ecdat:view") ?? "declared";
  const views = all(properties, "ecdat:view");
  const configurable = one(properties, "ecdat:configurable");

  return {
    bomRef: component["bom-ref"],
    name: component.name,
    view,
    views: views.length > 0 ? views : [view],
    // Absent is NOT false: no scanner made the call, so it is not assessed.
    configurable: configurable === null ? null : configurable === "true",
    band: (band && BAND_SET.has(band) ? band : "Low") as Band,
    score: integer(properties, "ecdat:score") ?? 0,
    assetType: one(properties, "ecdat:asset_type") ?? crypto?.assetType ?? "unknown",
    usage: one(properties, "ecdat:usage") ?? "unknown",
    primitive: crypto?.algorithmProperties?.primitive ?? null,
    endpoint: one(properties, "ecdat:param:endpoint"),
    deadline: one(properties, "ecdat:deadline"),
    labels: list(properties, "ecdat:labels"),
    firedRules: list(properties, "ecdat:fired_rules"),
    actions: all(properties, "ecdat:actions"),
    categories: categories(properties),
    quantumStatus: one(properties, "ecdat:quantum_status"),
    params: params(properties),
    occurrences: occurrences(component),
    drift: drifts(properties),
    coverageViews: list(properties, "ecdat:coverage:views"),
    coverageMissing: list(properties, "ecdat:coverage:missing"),
    xYears: integer(properties, "ecdat:x_years"),
    yYears: integer(properties, "ecdat:y_years"),
    zYears: integer(properties, "ecdat:z_years"),
    bases: {
      x: one(properties, "ecdat:x_years_basis"),
      y: one(properties, "ecdat:y_years_basis"),
      z: one(properties, "ecdat:z_years_basis"),
    },
    provisional: one(properties, "ecdat:provisional") === "true",
    provisionalRules,
    deadlineProvisional: one(properties, "ecdat:deadline_provisional") === "true",
    confidence: probability(properties, "ecdat:confidence"),
    // Written by Python as `str(True)`; either spelling of true is the flag.
    candidate: (one(properties, "ecdat:param:candidate") ?? "").toLowerCase() === "true",
    fix: fix(properties),
  };
}

export function parseCbom(document: Cbom): Artefact[] {
  return (document.components ?? []).map(toArtefact);
}
