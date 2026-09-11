/**
 * Inventory on the v2 mockup (inventory.html; ADR-0039): the filter bar, four
 * stat cards counted from the document, the nine-column table -- and colour
 * only where a band is.
 */
import { render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { InventoryScreen } from "@/screens/Inventory";
import { NO_FILTERS, type Filters, type ScanView } from "@/state/inventory";
import { colourIsSeverityOnly } from "@/test/v2";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

function Harness() {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const view: ScanView = {
    scans: [scan],
    scan,
    artefacts: z11,
    zYears: 11,
    loading: false,
    rescoring: false,
    error: null,
    setZYears: () => {},
    selectScan: () => {},
    reload: () => {},
  };
  return <InventoryScreen view={view} filters={filters} onFilters={setFilters} selectedRef={null} />;
}

const value = (id: string) => within(screen.getByTestId(`metric-${id}`)).getByTestId("metric-value");

describe("Inventory (inventory.html)", () => {
  it("filter bar, four stat cards, then the nine-column table -- all counted from the document", () => {
    const { container } = render(<Harness />);
    expect(container.querySelector(".filter-bar")).not.toBeNull();

    expect(value("inv-total")).toHaveTextContent("17");
    const severe = z11.filter((a) => a.band === "Critical" || a.band === "High").length;
    expect(value("inv-severe")).toHaveTextContent(String(severe));
    // One view collected: "Drifted" cannot be counted, and says so.
    expect(screen.getByTestId("metric-inv-drifted")).toHaveAttribute("data-state", "not-computed");
    expect(screen.getByTestId("metric-inv-deadline")).toHaveAttribute("data-state", "computed");

    expect(screen.getAllByRole("columnheader").map((th) => th.textContent)).toEqual([
      "Artefact",
      "BOM ref",
      "View",
      "Band",
      "Score",
      "Usage",
      "Endpoint",
      "Deadline",
      "Drift",
    ]);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(17);
    expect(screen.getByRole("button", { name: /export csv/i })).toBeEnabled();

    // A rail and a badge per row: the only colour on the screen.
    expect(colourIsSeverityOnly()).toBe(34);
  });

  it("provenance is the View chip's border, and the mockup's Internet-facing chip is not faked", () => {
    const { container } = render(<Harness />);
    const chips = Array.from(container.querySelectorAll("tbody [data-provenance]"));
    expect(chips).toHaveLength(17);
    for (const chip of chips) {
      expect(["verified", "provisional"]).toContain(chip.getAttribute("data-provenance"));
      expect(chip.className).not.toMatch(/critical|high|medium|\blow\b/);
    }
    // Exposure is recorded per scan, not per artefact: there is nothing to filter on.
    expect(screen.queryByText(/internet-facing/i)).toBeNull();
  });
});
