/**
 * Crypto Agility on the v2 mockup (agility.html; ADR-0039): the real
 * configurable share and split, "not computed" for what nothing measures, and
 * none of the mockup's target, rating or trend.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";

import { parseCbom } from "@/api/parse";
import type { Cbom } from "@/api/types";
import { AgilityScreen } from "@/screens/Agility";
import { colourIsSeverityOnly } from "@/test/v2";

const z11 = parseCbom(z11Doc as unknown as Cbom);

describe("Crypto Agility (agility.html)", () => {
  it("the share and split from ecdat:configurable; the improve list, worst first, with bands", () => {
    const { container } = render(<AgilityScreen artefacts={z11} loading={false} />);
    expect(container.querySelector(".metric-hero-num")).toHaveTextContent("65%");

    const rows = screen.getAllByTestId("improve-row");
    expect(rows).toHaveLength(6);
    for (const row of rows) {
      expect(within(row).getByText(/^(Critical|High|Medium|Low)$/)).toHaveAttribute("data-band");
    }
    expect(colourIsSeverityOnly()).toBe(6);
  });

  it("what nothing measures draws no bar, and the mockup's target, rating and trend are absent", () => {
    render(<AgilityScreen artefacts={z11} loading={false} />);
    for (const id of ["agility-key-store", "agility-protocol"]) {
      const row = screen.getByTestId(id);
      expect(row.querySelector(".bar-metric-fill")).toBeNull();
      expect(row.querySelector(".bar-metric-track.absent")).not.toBeNull();
    }
    const text = document.body.textContent ?? "";
    for (const sample of ["Target 80", "Moderately adaptable", "Last 6 scans"]) {
      expect({ sample, found: text.includes(sample) }).toEqual({ sample, found: false });
    }
  });
});
