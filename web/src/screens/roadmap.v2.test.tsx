/**
 * Migration Roadmap on the v2 mockup (roadmap.html; ADR-0039): the Gantt with
 * its deadline cards, two detail panels, and the undated listed -- never placed.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { RoadmapScreen } from "@/screens/Roadmap";
import { colourIsSeverityOnly } from "@/test/v2";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

describe("Migration Roadmap (roadmap.html)", () => {
  it("a band-coloured bar per dated artefact, the deadline cards, two details, the undated listed", () => {
    render(<RoadmapScreen artefacts={z11} scan={scan} today="2026-09-10" />);

    const bars = screen.getAllByTestId("roadmap-bar");
    expect(bars).toHaveLength(3);
    for (const bar of bars) {
      const band = bar.getAttribute("data-band")!.toLowerCase();
      expect(bar.className).toMatch(new RegExp(`band-(bg|border)-${band}`));
    }
    expect(screen.getAllByTestId("deadline-card").length).toBeGreaterThan(0);
    expect(screen.getAllByTestId("roadmap-detail")).toHaveLength(2);
    expect(screen.getAllByTestId("roadmap-undated-item")).toHaveLength(14);

    // A one-choice "Sort by deadline" menu is not reproduced.
    expect(screen.queryByText(/sort by deadline/i)).toBeNull();
    colourIsSeverityOnly();
  });
});
