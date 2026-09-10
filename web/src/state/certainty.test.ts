/**
 * How sure ECDAT is about each finding, as data logic (ADR-0034 on screen).
 *
 * Four answers, and only ONE of them is a candidate:
 *
 * * **candidate** -- the rule flagged it (`ecdat:param:candidate`): a key-ish
 *   name holding a high-entropy literal nobody saw reach a crypto sink. It
 *   might not be real key material at all. The table tags it; the Candidates
 *   filter finds it.
 * * **inferred** -- real crypto at confidence below 1.0 because one detail was
 *   inferred: a parameter that arrived through a variable, or a binary
 *   heuristic. NOT a candidate. The table does not shout about it; the drawer
 *   shows its confidence and says why.
 * * **confirmed** -- 1.0, no flag.
 * * **unrecorded** -- the document records no confidence.
 *
 * The first version (0d22a73) tagged everything below 1.0, which put the
 * candidate tag on an ECDSA JWT whose algorithm is certain and on every binary
 * finding ever scanned. "Candidate" means "might not be real crypto", not
 * "real, one detail inferred".
 */
import { describe, expect, it } from "vitest";

import binaryDoc from "@/test/fixtures/cbom_binary.json";
import candidateDoc from "@/test/fixtures/cbom_candidate.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";

import { parseCbom } from "@/api/parse";
import type { Artefact, Cbom } from "@/api/types";
import { certaintyCountsOf, certaintyOf, certaintyReason, formatConfidence } from "./certainty";
import { applyFilters, NO_FILTERS } from "./inventory";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const artefacts = parseCbom(candidateDoc as unknown as Cbom);
const binary = parseCbom(binaryDoc as unknown as Cbom);
const rulesOf = (artefact: Artefact) => artefact.occurrences.map((o) => o.detail);

/** 0.5, flagged: the ADR-0034 candidate. */
const candidate = artefacts.find((a) => a.candidate)!;
/** 0.6: an ECDSA JWT whose algorithm arrived through a variable. Certainly ECDSA. */
const unresolved = artefacts.find((a) => rulesOf(a).includes("rule=js-jwt-ecdsa"))!;
/** 1.0: a key that reached a sink, with its declaration's candidate folded in. */
const confirmed = artefacts.find(
  (a) =>
    rulesOf(a).includes("rule=js-hardcoded-key") &&
    rulesOf(a).includes("rule=js-hardcoded-key-candidate"),
)!;
/** 0.9: a binary finding -- the linker resolved EVP_aes_256_gcm. */
const symbol = binary.find(
  (a) => a.confidence === 0.9 && rulesOf(a).includes("symbol=EVP_aes_256_gcm"),
)!;

const CANDIDATES = { ...NO_FILTERS, certainty: "candidates" as const };
const CONFIRMED = { ...NO_FILTERS, certainty: "confirmed" as const };

describe("certaintyOf -- a candidate is a FLAG, not a number", () => {
  it("the flagged 0.5 finding is a candidate", () => {
    expect(certaintyOf(candidate)).toBe("candidate");
  });

  it("a 0.6 finding whose parameter came from a variable is INFERRED, not a candidate", () => {
    expect(unresolved.confidence).toBe(0.6);
    expect(unresolved.candidate).toBe(false);
    expect(certaintyOf(unresolved)).toBe("inferred");
  });

  it("a 0.9 binary finding is INFERRED, not a candidate", () => {
    expect(symbol.confidence).toBe(0.9);
    expect(certaintyOf(symbol)).toBe("inferred");
  });

  it("no binary finding is a candidate, though every one is below 1.0 by design", () => {
    expect(binary).toHaveLength(22);
    expect(binary.every((a) => a.confidence !== null && a.confidence < 1)).toBe(true);
    expect(binary.some((a) => certaintyOf(a) === "candidate")).toBe(false);
  });

  it("1.0 with no flag is confirmed -- including a key a candidate was folded into", () => {
    expect(certaintyOf(confirmed)).toBe("confirmed");
  });

  it("the flag wins over any number, even a stated 1.0", () => {
    expect(certaintyOf({ ...confirmed, candidate: true })).toBe("candidate");
  });

  it("a missing confidence is UNRECORDED", () => {
    expect(certaintyOf({ ...confirmed, confidence: null })).toBe("unrecorded");
  });

  it("counts the real scans: ONE candidate in the JS scan, none in the binary one", () => {
    expect(certaintyCountsOf(artefacts)).toEqual({
      candidate: 1,
      inferred: 5,
      confirmed: 31,
      unrecorded: 0,
    });
    expect(certaintyCountsOf(binary)).toEqual({
      candidate: 0,
      inferred: 22,
      confirmed: 0,
      unrecorded: 0,
    });
    expect(certaintyCountsOf(z11)).toEqual({
      candidate: 0,
      inferred: 0,
      confirmed: 17,
      unrecorded: 0,
    });
  });
});

describe("formatConfidence", () => {
  it("prints the stored value, one decimal at least", () => {
    expect(formatConfidence(1)).toBe("1.0");
    expect(formatConfidence(0.5)).toBe("0.5");
    expect(formatConfidence(0.6)).toBe("0.6");
    expect(formatConfidence(0.9)).toBe("0.9");
    expect(formatConfidence(0.85)).toBe("0.85");
  });

  it("says 'not recorded' rather than printing a number nobody stored", () => {
    expect(formatConfidence(null)).toBe("not recorded");
  });
});

describe("certaintyReason -- WHY, in words, for the drawer", () => {
  it("tells the candidate story for the flagged finding", () => {
    const reason = certaintyReason(candidate);

    expect(reason).toMatch(/high-entropy/i);
    expect(reason).toMatch(/crypto sink/i);
    expect(reason).toMatch(/not confirmed/i);
    expect(reason).toContain("0.5");
  });

  it("a 0.6 inferred finding: its confidence, and that part was inferred -- no candidate story", () => {
    const reason = certaintyReason(unresolved);

    expect(reason).toContain("0.6");
    expect(reason).toMatch(/inferred/i);
    expect(reason).not.toMatch(/high-entropy|candidate/i);
  });

  it("a 0.9 binary finding: its confidence, and that part was inferred", () => {
    const reason = certaintyReason(symbol);

    expect(reason).toContain("0.9");
    expect(reason).toMatch(/inferred/i);
    expect(reason).not.toMatch(/high-entropy|candidate/i);
  });

  it("states a confirmed finding's confidence", () => {
    expect(certaintyReason(confirmed)).toContain("1.0");
    expect(certaintyReason(confirmed)).toMatch(/confirmed/i);
  });

  it("says plainly when no confidence was recorded", () => {
    expect(certaintyReason({ ...confirmed, confidence: null })).toMatch(/not recorded/i);
  });
});

/**
 * The toggles split the table on the FLAG: "Candidates" is the flagged
 * findings, "Confirmed" is everything else. A 0.6 or 0.9 finding is real
 * crypto with one detail inferred -- it is not a candidate, so it belongs
 * under Confirmed, and the drawer still shows its confidence and says why.
 * (The first cut of the toggle kept only 1.0 rows under Confirmed, which left
 * every inferred finding in neither toggle.)
 */
describe("applyFilters -- 'Candidates' is the flag; 'Confirmed' is everything else", () => {
  it("'all' keeps every row", () => {
    expect(applyFilters(artefacts, NO_FILTERS)).toHaveLength(37);
    expect(applyFilters(binary, NO_FILTERS)).toHaveLength(22);
  });

  it("'candidates' keeps ONLY the flagged finding -- no 0.6, no binary heuristic", () => {
    expect(applyFilters(artefacts, CANDIDATES)).toEqual([candidate]);
    expect(applyFilters(binary, CANDIDATES)).toHaveLength(0);
  });

  it("'confirmed' keeps every row that is NOT a flagged candidate", () => {
    const rows = applyFilters(artefacts, CONFIRMED);

    expect(rows).toHaveLength(36);
    expect(rows.some((a) => a.candidate)).toBe(false);
    expect(rows).not.toContain(candidate);
    expect(rows).toContain(confirmed);
    expect(rows).toContain(unresolved);
  });

  it("an INFERRED row is not a candidate, so it shows under 'Confirmed'", () => {
    expect(applyFilters(artefacts, CANDIDATES)).not.toContain(unresolved);
    expect(applyFilters(artefacts, CONFIRMED)).toContain(unresolved);
    expect(applyFilters([symbol], CONFIRMED)).toEqual([symbol]);
  });

  it("a whole binary scan -- every finding inferred, none flagged -- is all 'Confirmed'", () => {
    expect(applyFilters(binary, CONFIRMED)).toHaveLength(22);
  });

  it("the two toggles partition the rows: nothing dropped, nothing counted twice", () => {
    const counts = certaintyCountsOf(artefacts);
    const candidates = applyFilters(artefacts, CANDIDATES);
    const confirmedRows = applyFilters(artefacts, CONFIRMED);

    expect(counts.candidate + counts.inferred + counts.confirmed + counts.unrecorded).toBe(
      artefacts.length,
    );
    expect(candidates).toHaveLength(counts.candidate);
    expect(confirmedRows).toHaveLength(counts.inferred + counts.confirmed + counts.unrecorded);
    expect(candidates.length + confirmedRows.length).toBe(artefacts.length);
    expect(candidates.some((a) => confirmedRows.includes(a))).toBe(false);
  });

  it("an UNRECORDED confidence is not a candidate either: it shows under 'Confirmed'", () => {
    const unknown = [{ ...confirmed, confidence: null }];

    expect(applyFilters(unknown, CANDIDATES)).toHaveLength(0);
    expect(applyFilters(unknown, CONFIRMED)).toHaveLength(1);
    expect(applyFilters(unknown, NO_FILTERS)).toHaveLength(1);
  });

  it("'candidates' on a scan with none returns nothing, not everything", () => {
    expect(applyFilters(z11, CANDIDATES)).toHaveLength(0);
    expect(applyFilters(z11, CONFIRMED)).toHaveLength(17);
  });

  it("combines with the band filter", () => {
    expect(applyFilters(artefacts, { ...CANDIDATES, bands: ["Low"] })).toEqual([candidate]);
    // The Medium 0.6 ECDSA JWT is inferred, so it is not a Medium candidate.
    expect(applyFilters(artefacts, { ...CANDIDATES, bands: ["Medium"] })).toHaveLength(0);
  });
});
