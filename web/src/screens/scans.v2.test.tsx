/**
 * Scan History on the v2 mockup (scans.html; ADR-0039): four stat cards off
 * the stored rows, the timeline, the history table -- "Avg. duration" is not
 * computed, because the store records no start time.
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import scansDoc from "@/test/fixtures/scans.json";

import type { ScanSummary } from "@/api/types";
import { ScansScreen } from "@/screens/Scans";
import type { ScanView } from "@/state/inventory";
import { colourIsSeverityOnly } from "@/test/v2";

const scans = scansDoc as unknown as ScanSummary[];
const scan = scans[0];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function stubScans() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).split("?")[0].endsWith("/api/scans")) {
        return new Response(JSON.stringify({ items: scans, total: scans.length, limit: 25, offset: 0 }), {
          status: 200,
        });
      }
      return new Response("{}", { status: 404 });
    }),
  );
}

function view(selectScan = vi.fn()): ScanView {
  return {
    scans,
    scan,
    artefacts: [],
    zYears: 11,
    loading: false,
    rescoring: false,
    error: null,
    setZYears: () => {},
    selectScan,
    reload: () => {},
  };
}

const value = (id: string) => within(screen.getByTestId(`metric-${id}`)).getByTestId("metric-value");

describe("Scan History (scans.html)", () => {
  it("four stat cards, the timeline, then the history table -- off the stored rows", async () => {
    stubScans();
    render(<ScansScreen view={view()} />);
    await screen.findByText(`Showing 1–${scans.length} of ${scans.length}`);

    expect(value("scans-total")).toHaveTextContent(String(scans.length));
    expect(screen.getByTestId("metric-scans-duration")).toHaveAttribute("data-state", "not-computed");
    expect(screen.getByTestId("metric-scans-duration")).toHaveTextContent(/not when it began/i);

    const nodes = screen.getAllByTestId("timeline-node");
    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toHaveAttribute("aria-current", "true");
    expect(nodes[0]).toHaveTextContent("Current");

    expect(screen.getAllByTestId("scan-row")).toHaveLength(scans.length);
    const expected = (scan.band_counts.Critical > 0 ? 1 : 0) + (scan.band_counts.High > 0 ? 1 : 0);
    expect(colourIsSeverityOnly()).toBe(expected);
  });

  it("a timeline node loads that scan", async () => {
    stubScans();
    const selectScan = vi.fn();
    render(<ScansScreen view={view(selectScan)} />);
    await userEvent.click(screen.getByTestId("timeline-node"));
    expect(selectScan).toHaveBeenCalledWith(scan.id);
  });
});
