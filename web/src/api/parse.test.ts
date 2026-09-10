/**
 * Parsing a real CBOM into the shape the console renders.
 *
 * Every fixture here is a document a real scan produced -- `cbom_z11.json` and
 * `cbom_z20.json` are the same estate before and after a REAL rescore through
 * `POST /scans/{id}/rescore`, and `cbom_provisional.json` came out of the
 * policy engine with the India DST pack demoted. Hand-written fixtures would
 * test the parser against the shape I imagined, which is the shape that is
 * always right.
 *
 * The rule these tests exist to pin: **the console reads, it does not score.**
 * Bands, scores and counts come off the stored document. A dashboard that
 * recomputed them could disagree with the CBOM it is displaying, and the
 * disagreement would be invisible.
 */
import { describe, expect, it } from "vitest";

import driftDoc from "@/test/fixtures/cbom_drift.json";
import provisionalDoc from "@/test/fixtures/cbom_provisional.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";
import z20Doc from "@/test/fixtures/cbom_z20.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom, parseScanSummaries } from "./parse";
import type { Cbom, ScanSummary } from "./types";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const z20 = parseCbom(z20Doc as unknown as Cbom);
const z5 = parseCbom(z5Doc as unknown as Cbom);
const drifted = parseCbom(driftDoc as unknown as Cbom);
const provisional = parseCbom(provisionalDoc as unknown as Cbom);

const byName = (list: typeof z11, name: string) => {
  const hit = list.find((a) => a.name === name);
  if (!hit) throw new Error(`no artefact named ${name}`);
  return hit;
};

describe("parseScanSummaries", () => {
  it("reads the denormalised scan row without touching the CBOM", () => {
    const [scan] = parseScanSummaries(scansDoc as unknown as ScanSummary[]);

    expect(scan.component_count).toBe(17);
    expect(scan.band_counts).toEqual({ Critical: 2, High: 1, Medium: 0, Low: 14 });
    expect(scan.max_score).toBe(98);
    expect(scan.z_years).toBe(11);
    expect(scan.sector).toBe("bfsi");
  });

  it("keeps a null scanners_ran distinct from an empty one", () => {
    // ADR-0016: null = "we cannot say what ran"; [] = "we can, and it was
    // nothing". A console that renders both as "none" is lying about coverage.
    const rows = parseScanSummaries([
      { ...(scansDoc as unknown as ScanSummary[])[0], scanners_ran: null },
      { ...(scansDoc as unknown as ScanSummary[])[0], id: "b", scanners_ran: [] },
    ]);

    expect(rows[0].scanners_ran).toBeNull();
    expect(rows[1].scanners_ran).toEqual([]);
  });
});

describe("parseCbom", () => {
  it("flattens every component in the document", () => {
    expect(z11).toHaveLength(17);
  });

  it("reads the band and score off the stored properties", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.band).toBe("Critical");
    expect(rsa.score).toBe(98);
    expect(rsa.view).toBe("declared");
    expect(rsa.assetType).toBe("algorithm");
    expect(rsa.primitive).toBe("pke");
  });

  it("splits the repeating comma-joined properties", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.firedRules).toContain("quantum-shor-broken-asymmetric");
    expect(rsa.firedRules).toContain("dst-cii-priority-migration");
    expect(rsa.labels).toContain("shor-broken");
    // `ecdat:actions` repeats -- one property per action, not a joined string.
    expect(rsa.actions.length).toBeGreaterThan(3);
    expect(rsa.actions.some((a) => a.includes("ML-KEM"))).toBe(true);
  });

  it("parses category_score into ordered category totals", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.categories).toEqual([
      { category: "criticality", score: 20 },
      { category: "exposure", score: 10 },
      { category: "mosca", score: 28 },
      { category: "quantum", score: 40 },
    ]);
    // The four must sum to the stored score -- if they do not, the console is
    // showing a breakdown of a different number than the one in the band.
    expect(rsa.categories.reduce((t, c) => t + c.score, 0)).toBe(rsa.score);
  });

  it("parses ecdat:occurrence into its four fields", () => {
    const rsa = byName(z11, "RSA-2048");
    const [first] = rsa.occurrences;

    expect(first.view).toBe("declared");
    expect(first.locator).toBe("testdata/quantumbank/services/auth/tokens.py:5");
    expect(first.scanner).toBe("source");
    expect(first.detail).toBe("rule=py-rsa-keygen");
    expect(first.snippet).toContain("rsa.generate_private_key");
  });

  it("carries the endpoint param so config findings can be grouped", () => {
    const endpoints = z11
      .map((a) => a.endpoint)
      .filter((e): e is string => e !== null);

    expect(endpoints).toContain("payments.quantumbank.invalid:443");
    expect(endpoints).toContain("openssl@quantumbank");
  });

  it("carries the Mosca terms and their bases", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.xYears).toBe(25);
    expect(rsa.yYears).toBe(5);
    expect(rsa.zYears).toBe(11);
    expect(rsa.bases.y).toContain("ESTIMATE");
  });

  it("reads coverage, distinguishing looked-at from missing views", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.coverageViews).toEqual(["declared"]);
    expect(rsa.coverageMissing).toEqual(["observed", "shipped"]);
  });

  it("reads drift off a document that has it", () => {
    const drifting = drifted.filter((a) => a.drift.length > 0);

    expect(drifting.length).toBeGreaterThan(0);
    const [first] = drifting[0].drift;
    expect(first.kind).toBeTruthy();
    expect(first.declared).toBeTruthy();
    expect(first.evidence.length).toBeGreaterThan(0);
  });

  it("reports no drift on a document that has none", () => {
    expect(z11.every((a) => a.drift.length === 0)).toBe(true);
  });
});

describe("the verified / provisional distinction (ADR-0017)", () => {
  it("marks a component whose verdict rests on an unverified rule", () => {
    const rsa = byName(provisional, "RSA-2048");

    expect(rsa.provisional).toBe(true);
    expect(rsa.provisionalRules).toContain("dst-cii-priority-migration");
    expect(rsa.deadlineProvisional).toBe(true);
  });

  it("leaves a fully verified component unmarked", () => {
    const rsa = byName(z11, "RSA-2048");

    expect(rsa.provisional).toBe(false);
    expect(rsa.provisionalRules).toEqual([]);
    expect(rsa.deadlineProvisional).toBe(false);
  });

  it("keeps the demoted label text, caveat and all", () => {
    // Demoted, never dropped: the label is still there, carrying its own
    // warning, because a label is what gets copied into a ticket.
    const rsa = byName(provisional, "RSA-2048");

    expect(rsa.labels.some((l) => l.includes("provisional"))).toBe(true);
    expect(rsa.labels.some((l) => l.startsWith("CII"))).toBe(true);
  });

  it("shows that a provisional verdict scored LESS, not the same", () => {
    // The property that makes the visual distinction meaningful: the demoted
    // component really did lose the points, so a console that rendered them
    // alike would be hiding a 20-point difference.
    expect(byName(provisional, "RSA-2048").score).toBe(78);
    expect(byName(z11, "RSA-2048").score).toBe(98);
  });
});

describe("a REAL rescore moves scores and order", () => {
  it("re-scores components when the CRQC horizon changes", () => {
    // z=11 -> z=20 through POST /scans/{id}/rescore. Mosca urgency falls as
    // the horizon recedes, so scores drop and the ordering changes.
    expect(byName(z11, "RSA-2048").score).toBe(98);
    expect(byName(z20, "RSA-2048").score).toBe(85);
    expect(byName(z11, "MD5").score).toBe(78);
    expect(byName(z20, "MD5").score).toBe(65);
  });

  it("pulling the horizon CLOSER re-colours most of the estate", () => {
    // The demo direction, and the one that actually moves bands: at z=5 the
    // Mosca gap widens until 15 of the 17 components change band. Pushing the
    // horizon out to 20 lowers every score by the same 13 points and crosses
    // no threshold at all -- asserted separately below, because a slider that
    // only ever recolours in one direction is worth knowing about.
    const bandOf = (list: typeof z11, name: string) => byName(list, name).band;

    expect(bandOf(z11, "MD5")).toBe("High");
    expect(bandOf(z5, "MD5")).toBe("Critical");

  });

  it("counts the band changes at z=5 against the real documents", () => {
    const bandByRef = new Map(z5.map((a) => [a.bomRef, a.band]));
    const changed = z11.filter((a) => bandByRef.get(a.bomRef) !== a.band);

    expect(changed).toHaveLength(15);
  });

  it("pushing the horizon OUT lowers every score without crossing a band", () => {
    // Honest about the limit: every component here shares one data class, so
    // they all lose the same 13 points and nothing crosses a threshold.
    const bandByRef = new Map(z20.map((a) => [a.bomRef, a.band]));
    expect(z11.every((a) => bandByRef.get(a.bomRef) === a.band)).toBe(true);

    const scoreByRef = new Map(z20.map((a) => [a.bomRef, a.score]));
    expect(z11.every((a) => scoreByRef.get(a.bomRef)! < a.score)).toBe(true);
  });

  it("carries the new z_years through to every component", () => {
    expect(z20.every((a) => a.zYears === 20)).toBe(true);
  });
});
