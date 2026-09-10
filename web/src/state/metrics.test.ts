/**
 * The console's derived numbers, pinned against REAL documents.
 *
 * ADR-0031's rule for a number on screen: it is a stored value, a COUNT of
 * stored facts, or a ratio of two such counts with both visible. Anything else
 * is "not computed" -- and a not-computed metric is a distinct state, never a
 * zero. These tests pin both halves: the arithmetic that IS done, and the
 * places it refuses to invent one.
 */
import { describe, expect, it } from "vitest";

import driftDoc from "@/test/fixtures/cbom_drift.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Artefact, Cbom, ScanSummary } from "@/api/types";
import {
  agility,
  defaultComparison,
  diffStats,
  driftPanelsOf,
  fipsTag,
  inventoryCsv,
  moscaSummary,
  priorityQueue,
  quantumExposure,
  roadmapOf,
  scanStatus,
  scannerCoverage,
  scoreHistogram,
  targetOf,
  viewCoverage,
} from "./metrics";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const z5 = parseCbom(z5Doc as unknown as Cbom);
const drift = parseCbom(driftDoc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

const withoutConfigurability = (artefacts: Artefact[]) =>
  artefacts.map((a) => ({ ...a, configurable: null }));

describe("crypto agility — only what the CBOM records", () => {
  it("counts configurable and hard-coded components off ecdat:configurable", () => {
    const result = agility(z11);
    expect(result.configurable).toBe(11);
    expect(result.hardCoded).toBe(6);
    expect(result.unassessed).toBe(0);
    expect(result.share).toMatchObject({ status: "computed", value: 65 });
    if (result.share.status === "computed") {
      expect(result.share.basis).toContain("11 of 17");
    }
  });

  it("leaves components with no configurability finding OUT of the denominator", () => {
    const result = agility(drift);
    expect([result.configurable, result.hardCoded, result.unassessed]).toEqual([
      11, 10, 5,
    ]);
    expect(result.share).toMatchObject({ status: "computed", value: 52 });
  });

  it("is NOT COMPUTED when no component carries the fact — never 0%", () => {
    const result = agility(withoutConfigurability(z11));
    expect(result.share.status).toBe("not-computed");
    expect(result.unassessed).toBe(17);
  });

  it("never computes the key-store or protocol sub-metrics", () => {
    for (const artefacts of [z11, drift]) {
      const result = agility(artefacts);
      expect(result.keyStore.status).toBe("not-computed");
      expect(result.protocol.status).toBe("not-computed");
    }
  });

  it("names the hard-coded components as where to improve, worst first", () => {
    const { improve } = agility(z11);
    expect(improve).toHaveLength(6);
    expect(improve.every((a) => a.configurable === false)).toBe(true);
    expect(improve.map((a) => a.name).slice(0, 3)).toEqual(["RSA", "RSA-2048", "MD5"]);
  });
});

describe("quantum exposure", () => {
  it("counts Shor-broken artefacts and says how many carry no verdict", () => {
    expect(quantumExposure(z11)).toEqual({
      broken: 2,
      weakened: 0,
      assessed: 2,
      unassessed: 15,
    });
    expect(quantumExposure(drift).broken).toBe(4);
  });
});

describe("view coverage — a view not collected is not a view that came back clean", () => {
  it("a one-target scan collected one view of three", () => {
    const result = viewCoverage(z11);
    expect(result.collected).toEqual(["declared"]);
    expect(result.share).toMatchObject({ status: "computed", value: 33 });
    expect(result.pulse.declared.percent).toBe(100);
    expect(result.pulse.shipped.percent).toBe(0);
    expect(result.pulse.observed.percent).toBe(0);
  });

  it("a system scan collected all three, and the pulse counts correlated sightings", () => {
    const result = viewCoverage(drift);
    expect(result.collected).toEqual(["declared", "shipped", "observed"]);
    expect(result.share).toMatchObject({ status: "computed", value: 100 });
    expect(result.pulse.declared.percent).toBe(65);
    expect(result.pulse.shipped.percent).toBe(81);
    expect(result.pulse.observed.percent).toBe(85);
  });

  it("is not computed for a document with no artefacts", () => {
    expect(viewCoverage([]).share.status).toBe("not-computed");
  });
});

describe("scan status", () => {
  it("PARTIAL when components were correlated against an incomplete view group", () => {
    const status = scanStatus(scan);
    expect(status.status).toBe("PARTIAL");
    expect(status.reason).toContain("17");
  });

  it("COMPLETE only when no component is missing a view", () => {
    expect(scanStatus({ ...scan, coverage_gaps: 0 }).status).toBe("COMPLETE");
  });

  it("UNKNOWN — never COMPLETE — when the row predates scanners_ran", () => {
    expect(scanStatus({ ...scan, coverage_gaps: 0, scanners_ran: null }).status).toBe(
      "UNKNOWN",
    );
  });

  it("PARTIAL when no scanner ran at all", () => {
    expect(scanStatus({ ...scan, coverage_gaps: 0, scanners_ran: [] }).status).toBe(
      "PARTIAL",
    );
  });

  it("DERIVED for a rescore or fix row, whose coverage is its parent's", () => {
    expect(scanStatus({ ...scan, kind: "rescore", parent_scan_id: "p" }).status).toBe(
      "DERIVED",
    );
  });
});

describe("Mosca terms", () => {
  it("reads x and y off the components and the gap to the live horizon", () => {
    const result = moscaSummary(z11);
    expect(result.x).toMatchObject({ status: "computed", value: { min: 25, max: 25 } });
    expect(result.y).toMatchObject({ status: "computed", value: { min: 3, max: 5 } });
    expect(result.z).toBe(11);
    expect(result.delta).toMatchObject({
      status: "computed",
      value: { worst: -19, exposed: 17, assessed: 17 },
    });
  });

  it("follows a rescore", () => {
    const result = moscaSummary(z5);
    expect(result.z).toBe(5);
    expect(result.delta).toMatchObject({ status: "computed", value: { worst: -25 } });
  });

  it("is not computed when no component carries x", () => {
    const result = moscaSummary(z11.map((a) => ({ ...a, xYears: null })));
    expect(result.x.status).toBe("not-computed");
    expect(result.delta.status).toBe("not-computed");
  });
});

describe("priority queue and histogram", () => {
  it("puts the worst first, ties broken by name", () => {
    expect(priorityQueue(z11, 3).map((a) => a.name)).toEqual(["RSA", "RSA-2048", "MD5"]);
  });

  it("buckets every artefact once", () => {
    const buckets = scoreHistogram(z11);
    expect(buckets.reduce((sum, b) => sum + b.count, 0)).toBe(17);
    expect(buckets.find((b) => b.floor === 90)?.count).toBe(2);
    expect(buckets.find((b) => b.floor === 70)?.count).toBe(1);
    expect(buckets.find((b) => b.floor === 30)?.count).toBe(14);
  });
});

describe("migration roadmap", () => {
  it("bars only what a pack dated, and lists the rest as undated", () => {
    const roadmap = roadmapOf(z11, "2026-09-10");
    expect(roadmap.rows).toHaveLength(3);
    expect(roadmap.undated).toHaveLength(14);
    expect(roadmap.clusters.map((c) => [c.deadline, c.rows.length])).toEqual([
      ["2026-01-01", 1],
      ["2027-12-31", 2],
    ]);
  });

  it("marks a past deadline overdue rather than drawing it in the future", () => {
    const roadmap = roadmapOf(z11, "2026-09-10");
    const md5 = roadmap.rows.find((row) => row.artefact.name === "MD5")!;
    expect(md5.overdue).toBe(true);
    expect(md5.column).toBe("overdue");
    const rsa = roadmap.rows.find((row) => row.artefact.name === "RSA")!;
    expect(rsa.overdue).toBe(false);
    expect(rsa.column).toBe("2027");
    expect(roadmap.columns).toEqual(["overdue", "2026", "2027", "2028", "2029+"]);
  });

  it("reads the target from the pack's label, and invents none", () => {
    const base = z11[0];
    expect(targetOf({ ...base, labels: ["target-ml-dsa"] })).toBe("ML-DSA");
    expect(targetOf({ ...base, labels: ["target-ml-kem", "harvest-now-decrypt-later"] })).toBe(
      "ML-KEM",
    );
    expect(targetOf({ ...base, labels: ["target-depends-on-usage"] })).toBe(
      "ML-KEM or ML-DSA",
    );
    expect(targetOf({ ...base, labels: ["internet-reachable"] })).toBeNull();
  });
});

describe("drift panels — three views, each saying what it knows", () => {
  it("one panel per distinct disagreement, peers merged", () => {
    const panels = driftPanelsOf(drift);
    expect(panels).toHaveLength(5);
    const tls = panels.find((p) => p.kind === "cipher-outside-declared-set")!;
    expect([...tls.peers].sort()).toEqual(["nginx", "payments-api"]);
  });

  it("puts a shipped-cannot-do-declared value in the SHIPPED cell", () => {
    const panel = driftPanelsOf(drift).find(
      (p) => p.kind === "shipped-cannot-do-declared",
    )!;
    expect(panel.cells.declared).toMatchObject({
      role: "stated",
      value: "X25519MLKEM768",
    });
    expect(panel.cells.shipped).toMatchObject({
      role: "compared",
      value: "OpenSSL 3.0.2 (not PQC-capable)",
      provenance: "verified",
    });
    expect(panel.cells.observed.role).toBe("not-compared");
    expect(panel.confidence).toBe(100);
  });

  it("an unconfirmed observation is PROVISIONAL at half confidence", () => {
    const [artefact] = drift.filter((a) => a.drift.length > 0);
    const unconfirmed = {
      ...artefact,
      drift: [
        {
          ...artefact.drift[0],
          kind: "declared-pqc-observed-unconfirmed",
          confidence: "0.5",
        },
      ],
    };
    const [panel] = driftPanelsOf([unconfirmed, ...drift.filter((a) => a.drift.length === 0)]);
    expect(panel.cells.observed).toMatchObject({ role: "compared", provenance: "provisional" });
    expect(panel.confidence).toBe(50);
  });

  it("a view the document never collected is NOT COLLECTED, not 'not compared'", () => {
    const [artefact] = drift.filter((a) =>
      a.drift.some((d) => d.kind === "declared-pqc-observed-classical"),
    );
    const declaredOnly = [{ ...artefact, coverageViews: [], views: ["declared"] }];
    const panel = driftPanelsOf(declaredOnly).find(
      (p) => p.kind === "declared-pqc-observed-classical",
    )!;
    expect(panel.cells.shipped.role).toBe("not-collected");
  });

  it("a scan with no drift has no panels", () => {
    expect(driftPanelsOf(z11)).toEqual([]);
  });
});

describe("scanner coverage", () => {
  const available = ["binary", "config", "container", "deps", "runtime-spool", "source"];

  it("SELECTED — never 'ran' — because the row records the offered set, not the outcome", () => {
    // `scanners_ran` is scanner_records(offered): a repo scan's row lists the
    // binary scanner even though the orchestrator SKIPPED it. Saying "ran"
    // would claim ECDAT looked for binaries where it did not (PUNCHLIST).
    const cards = scannerCoverage(scan, available, z11);
    const byId = Object.fromEntries(cards.map((c) => [c.id, c]));
    expect(byId.binary.status).toBe("NOT RUN");
    expect(byId.deps.status).toBe("NOT RUN");
    expect(byId.source).toMatchObject({ status: "SELECTED", artefacts: 6 });
    expect(byId.config).toMatchObject({ status: "SELECTED", artefacts: 11 });
    expect(byId.container).toMatchObject({ status: "SELECTED", artefacts: 0 });
    expect(cards.some((c) => (c.status as string) === "RAN")).toBe(false);
  });

  it("UNKNOWN for every scanner when the row never recorded what ran", () => {
    const cards = scannerCoverage({ ...scan, scanners_ran: null }, available, z11);
    expect(new Set(cards.map((c) => c.status))).toEqual(new Set(["UNKNOWN"]));
  });

  it("an engine that is not installed is UNAVAILABLE", () => {
    const cards = scannerCoverage(
      { ...scan, engine_versions: { source: { pinned: "1.176.1", installed: null } } },
      available,
      z11,
    );
    expect(cards.find((c) => c.id === "source")?.engine).toBe("UNAVAILABLE");
  });

  it("without the server's list, shows only what the row recorded", () => {
    const cards = scannerCoverage(scan, null, z11);
    expect(cards.map((c) => c.id)).toEqual(["config", "container", "runtime-spool", "source"]);
  });
});

describe("fix helpers", () => {
  it("counts a unified diff's lines, not its headers", () => {
    const diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n-old\n+new\n+more\n";
    expect(diffStats(diff)).toEqual({ added: 2, removed: 1, files: 1 });
  });

  it("reads a FIPS number out of a citation, and nothing else", () => {
    expect(fipsTag("NIST FIPS 180-4 section 1")).toBe("FIPS 180-4");
    expect(fipsTag("RFC 8446")).toBeNull();
    expect(fipsTag(null)).toBeNull();
  });
});

describe("inventory CSV", () => {
  it("one row per artefact, quoted where a value needs it", () => {
    const lines = inventoryCsv(z11).trim().split("\n");
    expect(lines[0]).toMatch(/^bom_ref,name,view,band,score/);
    expect(lines).toHaveLength(18);
    const tricky = inventoryCsv([{ ...z11[0], name: 'AES, "GCM"' }]);
    expect(tricky).toContain('"AES, ""GCM"""');
  });
});

describe("default comparison", () => {
  const older = { ...scan, id: "older", created_at: "2026-09-01T00:00:00Z" };
  const rescore = { ...scan, id: "r1", kind: "rescore" as const, parent_scan_id: scan.id };

  it("a derived row compares against its parent", () => {
    expect(defaultComparison([rescore, scan], rescore).base?.id).toBe(scan.id);
  });

  it("a scan compares against the previous scan of the same system", () => {
    expect(defaultComparison([scan, older], scan).base?.id).toBe("older");
  });

  it("has no base when there is nothing to compare against", () => {
    expect(defaultComparison([scan], scan).base).toBeNull();
  });
});
