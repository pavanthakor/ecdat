/**
 * The two pieces of presentation logic that can be silently wrong.
 *
 * The live band readout beside the slider must be recomputed from the CURRENT
 * artefacts, not read off the scan row -- the row describes the horizon the
 * scan was stored at, and the whole point of the slider is that the estate now
 * looks different. Reading the row would leave the headline numbers frozen
 * while the table underneath them changed, which is worse than showing
 * nothing.
 *
 * The empty state must distinguish three situations a single "no results"
 * message would collapse: nothing selected, a scan that genuinely found no
 * crypto, and filters that exclude everything. Only the third has an action.
 */
import { describe, expect, it } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { bandCountsOf, emptyStateOf, engineLine } from "./presentation";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const z5 = parseCbom(z5Doc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

describe("bandCountsOf -- the live readout beside the slider", () => {
  it("counts the artefacts actually on screen", () => {
    expect(bandCountsOf(z11)).toEqual({
      Critical: 2,
      High: 1,
      Medium: 0,
      Low: 14,
    });
  });

  it("agrees with the stored scan row at the horizon the scan was stored at", () => {
    // If these ever disagree the console is computing something the store did
    // not, which is the one thing the dashboard must never do.
    expect(bandCountsOf(z11)).toEqual(scan.band_counts);
  });

  it("CHANGES when the horizon moves -- this is the demo's wow moment", () => {
    // z=11 -> z=5: MD5 crosses into Critical and thirteen artefacts leave Low.
    expect(bandCountsOf(z5)).toEqual({
      Critical: 3,
      High: 0,
      Medium: 14,
      Low: 0,
    });
    expect(bandCountsOf(z5)).not.toEqual(bandCountsOf(z11));
  });

  it("always reports every band, including the zeroes", () => {
    // A band that disappears from the readout reads as "not assessed" rather
    // than "none" -- the same distinction ADR-0016 draws for scanners_ran.
    expect(Object.keys(bandCountsOf([]))).toEqual([
      "Critical",
      "High",
      "Medium",
      "Low",
    ]);
    expect(bandCountsOf([])).toEqual({
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
    });
  });
});

describe("emptyStateOf -- three situations, three messages", () => {
  it("says nothing at all when there are rows to show", () => {
    expect(emptyStateOf({ scan, total: 17, shown: 17 })).toBeNull();
    expect(emptyStateOf({ scan, total: 17, shown: 3 })).toBeNull();
  });

  it("distinguishes no scan selected", () => {
    const state = emptyStateOf({ scan: null, total: 0, shown: 0 });

    expect(state?.kind).toBe("no-scan");
    expect(state?.action).toBeNull();
  });

  it("distinguishes a scan that found no cryptography", () => {
    // Not a failure and not a filter problem: the scan ran and the estate is
    // empty. Offering "clear filters" here would send a reader chasing a
    // control that would not help.
    const state = emptyStateOf({ scan, total: 0, shown: 0 });

    expect(state?.kind).toBe("no-artefacts");
    expect(state?.action).toBeNull();
    expect(state?.title.toLowerCase()).not.toContain("filter");
  });

  it("distinguishes filters that exclude everything, and offers the fix", () => {
    const state = emptyStateOf({ scan, total: 17, shown: 0 });

    expect(state?.kind).toBe("filtered-out");
    expect(state?.action).toBe("clear-filters");
  });

  it("gives each state its own wording", () => {
    const titles = [
      emptyStateOf({ scan: null, total: 0, shown: 0 }),
      emptyStateOf({ scan, total: 0, shown: 0 }),
      emptyStateOf({ scan, total: 17, shown: 0 }),
    ].map((state) => state?.title);

    expect(new Set(titles).size).toBe(3);
  });
});

describe("engineLine -- the auditable footer", () => {
  it("names the engine that produced the scan", () => {
    const line = engineLine({
      ...scan,
      engine_versions: {
        ecdat: "0.1.0",
        source: { pinned: "1.176.1", installed: "1.176.1", matches: true },
      },
      engine_warning: null,
    });

    expect(line.parts).toContain("ECDAT 0.1.0");
    expect(line.parts).toContain("semgrep 1.176.1");
    expect(line.warning).toBeNull();
  });

  it("surfaces an engine mismatch rather than hiding it", () => {
    const line = engineLine({
      ...scan,
      engine_versions: {
        ecdat: "0.1.0",
        source: { pinned: "1.176.1", installed: "9.9.9", matches: false },
      },
      engine_warning: "engine version 9.9.9 differs from the pinned 1.176.1",
    });

    expect(line.parts.some((p) => p.includes("9.9.9"))).toBe(true);
    expect(line.warning).toContain("9.9.9");
  });

  it("says so when a row does not record its engine", () => {
    const line = engineLine({ ...scan, engine_versions: null, engine_warning: null });

    expect(line.parts).toContain("engine not recorded");
  });

  it("counts provisional facts across the estate", () => {
    expect(engineLine(scan, z11).parts).toContain("0 facts provisional");
  });
});
