/**
 * The inventory table's state logic: filtering, sorting, and the rescore flow.
 *
 * Tested as pure functions plus a hook driven with a mocked `fetch` returning
 * REAL captured JSON, because these are the parts that can be silently wrong.
 * Layout is not tested; a column in the wrong place is visible, a filter that
 * quietly drops rows is not.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import driftDoc from "@/test/fixtures/cbom_drift.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom } from "@/api/types";
import { applyFilters, sortArtefacts, useScanView } from "./inventory";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const drifted = parseCbom(driftDoc as unknown as Cbom);

const EMPTY = { bands: [], views: [], driftOnly: false, query: "" };

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("applyFilters", () => {
  it("returns everything when no filter is set", () => {
    expect(applyFilters(z11, EMPTY)).toHaveLength(z11.length);
  });

  it("narrows to the selected bands", () => {
    const critical = applyFilters(z11, { ...EMPTY, bands: ["Critical"] });

    expect(critical.length).toBeGreaterThan(0);
    expect(critical.every((a) => a.band === "Critical")).toBe(true);
    expect(critical.length).toBeLessThan(z11.length);
  });

  it("unions several bands rather than intersecting them", () => {
    const both = applyFilters(z11, { ...EMPTY, bands: ["Critical", "High"] });
    const critical = applyFilters(z11, { ...EMPTY, bands: ["Critical"] });
    const high = applyFilters(z11, { ...EMPTY, bands: ["High"] });

    expect(both).toHaveLength(critical.length + high.length);
  });

  it("narrows to the selected views", () => {
    const declared = applyFilters(drifted, { ...EMPTY, views: ["declared"] });

    expect(declared.length).toBeGreaterThan(0);
    expect(declared.every((a) => a.view === "declared")).toBe(true);
  });

  it("drift-only keeps exactly the components carrying drift", () => {
    const drifting = applyFilters(drifted, { ...EMPTY, driftOnly: true });

    expect(drifting.length).toBeGreaterThan(0);
    expect(drifting.every((a) => a.drift.length > 0)).toBe(true);
    expect(drifting.length).toBe(drifted.filter((a) => a.drift.length > 0).length);
  });

  it("drift-only on a document with no drift returns nothing, not everything", () => {
    // The failure that matters: a filter that no-ops when it matches nothing
    // reads as "no drift here" and "the filter is broken" identically.
    expect(applyFilters(z11, { ...EMPTY, driftOnly: true })).toHaveLength(0);
  });

  it("combines band and drift filters", () => {
    const combined = applyFilters(drifted, {
      ...EMPTY,
      bands: ["Critical"],
      driftOnly: true,
    });

    expect(combined.every((a) => a.band === "Critical" && a.drift.length > 0)).toBe(
      true,
    );
  });

  it("searches name, bom-ref, endpoint and locator", () => {
    expect(applyFilters(z11, { ...EMPTY, query: "RSA" }).length).toBeGreaterThan(0);
    expect(
      applyFilters(z11, { ...EMPTY, query: "payments.quantumbank" }).length,
    ).toBeGreaterThan(0);
    expect(applyFilters(z11, { ...EMPTY, query: "tokens.py" }).length).toBeGreaterThan(
      0,
    );
    expect(applyFilters(z11, { ...EMPTY, query: "zzzz-no-such-thing" })).toHaveLength(
      0,
    );
  });
});

describe("sortArtefacts", () => {
  it("defaults to worst-first by score", () => {
    const sorted = sortArtefacts(z11, { column: "score", direction: "desc" });

    expect(sorted[0].score).toBe(98);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i - 1].score).toBeGreaterThanOrEqual(sorted[i].score);
    }
  });

  it("breaks ties by name so the order is total and stable", () => {
    const first = sortArtefacts(z11, { column: "score", direction: "desc" });
    const again = sortArtefacts([...z11].reverse(), {
      column: "score",
      direction: "desc",
    });

    expect(first.map((a) => a.bomRef)).toEqual(again.map((a) => a.bomRef));
  });

  it("sorts by band in severity order, not alphabetically", () => {
    const sorted = sortArtefacts(z11, { column: "band", direction: "desc" });

    // Alphabetically "Critical" < "High" < "Low" < "Medium", which would put
    // Low above Medium. Severity order must win.
    expect(sorted[0].band).toBe("Critical");
    const bands = sorted.map((a) => a.band);
    expect(bands.indexOf("Low")).toBeGreaterThan(bands.lastIndexOf("High"));
  });

  it("reverses on direction", () => {
    const desc = sortArtefacts(z11, { column: "score", direction: "desc" });
    const asc = sortArtefacts(z11, { column: "score", direction: "asc" });

    expect(asc[0].score).toBeLessThanOrEqual(desc[0].score);
    expect(asc[asc.length - 1].score).toBe(desc[0].score);
  });
});

// ---------------------------------------------------------------------------
// The Mosca slider: a REAL rescore round trip
// ---------------------------------------------------------------------------

const SCAN_ID = (scansDoc as { id: string }[])[0].id;

function mockApi() {
  const calls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : String(input);
    calls.push(`${init?.method ?? "GET"} ${url}`);

    if (url.endsWith("/api/scans")) {
      return new Response(JSON.stringify(scansDoc), { status: 200 });
    }
    // `/cbom` FIRST: the rescored row's id is "rescored-1", and matching
    // "/rescore" by substring would swallow "/scans/rescored-1/cbom".
    if (url.endsWith("/cbom")) {
      const doc = url.includes("rescored-1") ? z5Doc : z11Doc;
      return new Response(JSON.stringify(doc), { status: 200 });
    }
    if (url.includes("/rescore?")) {
      // The real endpoint returns the NEW row's id, not the document.
      return new Response(
        JSON.stringify({
          scan_id: "rescored-1",
          parent_scan_id: SCAN_ID,
          kind: "rescore",
        }),
        { status: 201 },
      );
    }
    return new Response("{}", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

describe("useScanView -- the Mosca slider", () => {
  it("loads the scan and its CBOM", async () => {
    mockApi();
    const { result } = renderHook(() => useScanView());

    await waitFor(() => expect(result.current.artefacts.length).toBe(17));
    expect(result.current.scan?.id).toBe(SCAN_ID);
    expect(result.current.zYears).toBe(11);
  });

  it("rescores on a Z change and replaces the table from the NEW document", async () => {
    const calls = mockApi();
    const { result } = renderHook(() => useScanView());
    await waitFor(() => expect(result.current.artefacts.length).toBe(17));

    const before = result.current.artefacts.find((a) => a.name === "RSA-2048");
    expect(before?.score).toBe(98);
    expect(before?.band).toBe("Critical");

    act(() => result.current.setZYears(5));
    await waitFor(
      () =>
        expect(
          result.current.artefacts.find((a) => a.name === "MD5")?.band,
        ).toBe("Critical"),
      { timeout: 3000 },
    );

    // RE-SCORED and RE-COLOURED off the real rescored document: pulling the
    // CRQC horizon in to 5 years widens every Mosca gap.
    const md5After = result.current.artefacts.find((a) => a.name === "MD5");
    expect(md5After?.band).toBe("Critical");
    expect(result.current.artefacts.find((a) => a.name === "RSA-2048")?.score).toBe(
      100,
    );
    expect(calls.some((c) => c.startsWith("POST") && c.includes("z_years=5"))).toBe(
      true,
    );
  });

  it("re-renders every row against the new document after a rescore", async () => {
    // Honest about what moves. Every component in QuantumBank shares one data
    // class, so a rescore shifts all their Mosca terms together: the SCORES
    // and BANDS change, the relative ranking does not. The table is driven off
    // the new document either way -- which is the property that matters, and
    // the one a stale-state bug would break.
    mockApi();
    const { result } = renderHook(() => useScanView());
    await waitFor(() => expect(result.current.artefacts.length).toBe(17));

    const before = sortArtefacts(result.current.artefacts, {
      column: "score",
      direction: "desc",
    }).map((a) => `${a.bomRef}:${a.score}:${a.band}`);

    act(() => result.current.setZYears(5));
    await waitFor(
      () =>
        expect(
          result.current.artefacts.find((a) => a.name === "MD5")?.band,
        ).toBe("Critical"),
      { timeout: 3000 },
    );

    const after = sortArtefacts(result.current.artefacts, {
      column: "score",
      direction: "desc",
    }).map((a) => `${a.bomRef}:${a.score}:${a.band}`);

    expect(after).not.toEqual(before);
    // 15 of the 17 changed band; every one changed score.
    expect(after.filter((row, i) => row !== before[i])).toHaveLength(17);
  });

  it("debounces: dragging through values issues ONE rescore", async () => {
    // Real timers, and a real ~400ms wait. Fake timers here fight React's own
    // act() flushing -- and the property under test is a wall-clock one
    // anyway: a drag must not fire a rescore per pixel.
    const calls = mockApi();
    const { result } = renderHook(() => useScanView());
    await waitFor(() => expect(result.current.artefacts.length).toBe(17));

    act(() => {
      result.current.setZYears(9);
      result.current.setZYears(8);
      result.current.setZYears(6);
      result.current.setZYears(5);
    });

    // The slider label moves immediately; nothing has been requested yet.
    expect(result.current.zYears).toBe(5);
    expect(calls.filter((c) => c.includes("/rescore?"))).toHaveLength(0);

    await waitFor(
      () =>
        expect(
          result.current.artefacts.find((a) => a.name === "MD5")?.band,
        ).toBe("Critical"),
      { timeout: 3000 },
    );

    const rescores = calls.filter((c) => c.includes("/rescore?"));
    expect(rescores).toHaveLength(1);
    expect(rescores[0]).toContain("z_years=5");
  });

  it("keeps the previous table and surfaces the error when a rescore fails", async () => {
    mockApi();
    const { result } = renderHook(() => useScanView());
    await waitFor(() => expect(result.current.artefacts.length).toBe(17));

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("boom", { status: 500 })),
    );
    act(() => result.current.setZYears(5));
    await waitFor(() => expect(result.current.error).not.toBeNull(), {
      timeout: 3000,
    });

    // A failed rescore must NOT leave an empty console: the last good
    // inventory is still true, it is just no longer the horizon asked for.
    expect(result.current.artefacts).toHaveLength(17);
    expect(result.current.artefacts.find((a) => a.name === "RSA-2048")?.score).toBe(
      98,
    );
  });
});
