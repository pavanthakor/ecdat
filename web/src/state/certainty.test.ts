/**
 * How sure ECDAT is about each finding, as data logic (ADR-0034 on screen).
 *
 * The scanner can now say "I am not sure": a 0.5 CANDIDATE (a key-ish name
 * holding a high-entropy literal nobody saw reach a crypto sink), or a finding
 * below 1.0 for another reason -- a heuristic technique, or a parameter that
 * never resolved to a constant. The console must carry that doubt to the
 * screen, and these pin the logic under the rendering: which bucket a finding
 * is in, what the drawer says about WHY, and what the filter keeps.
 *
 * The rule is the one the slice locked: confidence below 1.0 OR a `candidate`
 * flag gets the candidate treatment. A document that records no confidence is
 * UNRECORDED -- neither candidate nor confirmed -- because inventing certainty
 * for a missing property is exactly what the console must never do.
 */
import { describe, expect, it } from "vitest";

import candidateDoc from "@/test/fixtures/cbom_candidate.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";

import { parseCbom } from "@/api/parse";
import type { Artefact, Cbom } from "@/api/types";
import { certaintyCountsOf, certaintyOf, certaintyReason, formatConfidence } from "./certainty";
import { applyFilters, NO_FILTERS } from "./inventory";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const artefacts = parseCbom(candidateDoc as unknown as Cbom);
const rulesOf = (artefact: Artefact) => artefact.occurrences.map((o) => o.detail);

/** The 0.5 ADR-0034 candidate. */
const candidate = artefacts.find((a) => a.candidate)!;
/** 0.6: an ECDSA JWT whose algorithm arrived through a variable. */
const unresolved = artefacts.find((a) => rulesOf(a).includes("rule=js-jwt-ecdsa"))!;
/** 1.0: a key that reached a sink, with its declaration's candidate folded in. */
const confirmed = artefacts.find(
  (a) =>
    rulesOf(a).includes("rule=js-hardcoded-key") &&
    rulesOf(a).includes("rule=js-hardcoded-key-candidate"),
)!;

describe("certaintyOf -- three answers, never two", () => {
  it("a 0.5 candidate is a candidate", () => {
    expect(certaintyOf(candidate)).toBe("candidate");
  });

  it("ANY confidence below 1.0 gets the candidate treatment, not only a flagged one", () => {
    expect(unresolved.candidate).toBe(false);
    expect(certaintyOf(unresolved)).toBe("candidate");
  });

  it("1.0 with no flag is confirmed -- including a key a candidate was folded into", () => {
    expect(certaintyOf(confirmed)).toBe("confirmed");
  });

  it("a candidate flag wins even over a stated 1.0", () => {
    expect(certaintyOf({ ...confirmed, candidate: true })).toBe("candidate");
  });

  it("a missing confidence is UNRECORDED, neither candidate nor confirmed", () => {
    expect(certaintyOf({ ...confirmed, confidence: null })).toBe("unrecorded");
  });

  it("counts the real scan: 6 candidates, 31 confirmed, none unrecorded", () => {
    expect(certaintyCountsOf(artefacts)).toEqual({
      candidate: 6,
      confirmed: 31,
      unrecorded: 0,
    });
    expect(certaintyCountsOf(z11)).toEqual({ candidate: 0, confirmed: 17, unrecorded: 0 });
  });
});

describe("formatConfidence", () => {
  it("prints the stored value, one decimal at least", () => {
    expect(formatConfidence(1)).toBe("1.0");
    expect(formatConfidence(0.5)).toBe("0.5");
    expect(formatConfidence(0.6)).toBe("0.6");
    expect(formatConfidence(0.95)).toBe("0.95");
  });

  it("says 'not recorded' rather than printing a number nobody stored", () => {
    expect(formatConfidence(null)).toBe("not recorded");
  });
});

describe("certaintyReason -- WHY, in words, for the drawer", () => {
  it("explains an ADR-0034 candidate: a high-entropy literal not seen reaching a crypto sink", () => {
    const reason = certaintyReason(candidate);

    expect(reason).toMatch(/high-entropy/i);
    expect(reason).toMatch(/crypto sink/i);
    expect(reason).toMatch(/not confirmed/i);
    expect(reason).toContain("0.5");
  });

  it("does NOT tell the candidate story for a finding uncertain for another reason", () => {
    // A 0.6 ECDSA JWT is certainly an ECDSA JWT; what did not resolve is its
    // captured parameter. Calling it a high-entropy literal would be false.
    const reason = certaintyReason(unresolved);

    expect(reason).toContain("0.6");
    expect(reason).toMatch(/inferred/i);
    expect(reason).not.toMatch(/high-entropy/i);
  });

  it("states a confirmed finding's confidence", () => {
    expect(certaintyReason(confirmed)).toContain("1.0");
    expect(certaintyReason(confirmed)).toMatch(/confirmed/i);
  });

  it("says plainly when no confidence was recorded", () => {
    expect(certaintyReason({ ...confirmed, confidence: null })).toMatch(/not recorded/i);
  });
});

describe("applyFilters -- the candidates / confirmed toggle", () => {
  it("'all' keeps every row, candidates and confirmed alike", () => {
    expect(applyFilters(artefacts, NO_FILTERS)).toHaveLength(37);
  });

  it("'candidates' keeps exactly the rows with the candidate treatment", () => {
    const rows = applyFilters(artefacts, { ...NO_FILTERS, certainty: "candidates" });

    expect(rows).toHaveLength(6);
    expect(rows.every((a) => certaintyOf(a) === "candidate")).toBe(true);
    expect(rows).toContain(candidate);
    expect(rows).toContain(unresolved);
  });

  it("'confirmed' keeps exactly the 1.0 rows", () => {
    const rows = applyFilters(artefacts, { ...NO_FILTERS, certainty: "confirmed" });

    expect(rows).toHaveLength(31);
    expect(rows.every((a) => a.confidence === 1 && !a.candidate)).toBe(true);
    expect(rows).toContain(confirmed);
  });

  it("the two buckets partition this scan: nothing dropped, nothing counted twice", () => {
    const candidates = applyFilters(artefacts, { ...NO_FILTERS, certainty: "candidates" });
    const confirmedRows = applyFilters(artefacts, { ...NO_FILTERS, certainty: "confirmed" });

    expect(candidates.length + confirmedRows.length).toBe(artefacts.length);
    expect(candidates.some((a) => confirmedRows.includes(a))).toBe(false);
  });

  it("an UNRECORDED confidence is in neither bucket -- only under 'all'", () => {
    const unknown = [{ ...confirmed, confidence: null }];

    expect(applyFilters(unknown, { ...NO_FILTERS, certainty: "candidates" })).toHaveLength(0);
    expect(applyFilters(unknown, { ...NO_FILTERS, certainty: "confirmed" })).toHaveLength(0);
    expect(applyFilters(unknown, NO_FILTERS)).toHaveLength(1);
  });

  it("'candidates' on a scan with none returns nothing, not everything", () => {
    expect(applyFilters(z11, { ...NO_FILTERS, certainty: "candidates" })).toHaveLength(0);
    expect(applyFilters(z11, { ...NO_FILTERS, certainty: "confirmed" })).toHaveLength(17);
  });

  it("combines with the band filter", () => {
    const rows = applyFilters(artefacts, {
      ...NO_FILTERS,
      certainty: "candidates",
      bands: ["Medium"],
    });

    expect(rows).toEqual([unresolved]);
  });
});
