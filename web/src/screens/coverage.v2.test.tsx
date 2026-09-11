/**
 * Scanner Coverage on the v2 mockup (coverage.html; ADR-0039): the headline is
 * views collected of three, each scanner card says only what the row records,
 * and an uncollected view draws no bar.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { CoverageScreen } from "@/screens/Coverage";
import { viewCoverage } from "@/state/metrics";
import { colourIsSeverityOnly } from "@/test/v2";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function stubScanners() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("/api/scanners")
        ? new Response(JSON.stringify(["binary", "config", "container", "deps", "runtime-spool", "source"]), {
            status: 200,
          })
        : new Response("{}", { status: 404 }),
    ),
  );
}

describe("Scanner Coverage (coverage.html)", () => {
  it("the headline is views collected of three; each scanner's status is a border, not a colour", async () => {
    stubScanners();
    render(<CoverageScreen scan={scan} artefacts={z11} />);
    await waitFor(() => expect(screen.getAllByTestId("scanner-card")).toHaveLength(6));

    const share = viewCoverage(z11).share;
    expect(share.status).toBe("computed");
    expect(screen.getByTestId("coverage-share")).toHaveTextContent(
      `${share.status === "computed" ? share.value : ""}%`,
    );

    for (const card of screen.getAllByTestId("scanner-card")) {
      const chip = within(card).getByText(card.getAttribute("data-status")!);
      expect(chip).toHaveAttribute("data-provenance");
      if (card.getAttribute("data-status") === "NOT RUN") expect(card.className).toContain("dashed");
    }
    expect(screen.getByTestId("policy-card")).toBeInTheDocument();
    // No probe card: no probe scanner exists.
    expect(screen.queryByText(/probe/i)).toBeNull();
    expect(colourIsSeverityOnly()).toBe(0);
  });

  it("an uncollected view says how to collect it and draws no bar", async () => {
    stubScanners();
    render(<CoverageScreen scan={scan} artefacts={z11} />);
    for (const view of ["shipped", "observed"]) {
      const row = screen.getByTestId(`matrix-${view}`);
      expect(row).toHaveAttribute("data-collected", "false");
      expect(row).toHaveTextContent(/not collected/i);
      expect(row).toHaveTextContent(/to collect it/i);
      expect(row.querySelector(".layer-fill")).toBeNull();
    }
    expect(screen.getByTestId("matrix-declared")).toHaveAttribute("data-collected", "true");
  });
});
