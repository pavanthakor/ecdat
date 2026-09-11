/**
 * Reports on the v2 mockup (reports.html; ADR-0039): three report cards with
 * View and Generate, the artifact rows -- and no format ECDAT cannot produce.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { ReportsScreen } from "@/screens/Reports";
import { colourIsSeverityOnly } from "@/test/v2";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

describe("Reports (reports.html)", () => {
  it("three PDF report cards, each with View and Generate", () => {
    render(<ReportsScreen scan={scan} artefacts={z11} />);
    for (const kind of ["executive", "technical", "coverage"]) {
      const card = screen.getByTestId(`report-${kind}`);
      expect(within(card).getByRole("button", { name: /view/i })).toBeInTheDocument();
      expect(within(card).getByRole("button", { name: /generate/i })).toBeInTheDocument();
      // The mockup tags the technical report HTML and the coverage report CSV: both are PDF only.
      expect(within(card).getByText("PDF")).toBeInTheDocument();
      expect(within(card).queryByText(/^(HTML|CSV)$/)).toBeNull();
    }
    expect(colourIsSeverityOnly()).toBe(0);
  });

  it("the artifact rows: CBOM, PDF and CSV download; HTML is not computed and offers nothing", () => {
    render(<ReportsScreen scan={scan} artefacts={z11} />);
    expect(within(screen.getByTestId("artifact-cbom")).getByRole("button", { name: /download cbom json/i })).toBeEnabled();
    expect(within(screen.getByTestId("artifact-csv")).getByRole("button", { name: /download inventory csv/i })).toBeEnabled();
    const html = screen.getByTestId("export-html");
    expect(html).toHaveAttribute("data-state", "not-computed");
    expect(html).toHaveTextContent(/not computed/i);
    expect(within(html).queryByRole("button")).toBeNull();
  });
});
