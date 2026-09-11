/**
 * The screens rebuilt on the v2 mockups (ADR-0039), rendered with the real
 * fixtures: each keeps its mockup's structure, is wired to real data, says
 * "not computed" where the mockup shows something ECDAT does not compute, and
 * passes the colour audit -- colour means severity and nothing else.
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import driftDoc from "@/test/fixtures/cbom_drift.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, Principal, ScanSummary } from "@/api/types";
import { DriftScreen } from "@/screens/Drift";
import { AuthContext, type Auth } from "@/state/auth";
import { auditColour } from "@/test/colour";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const drift = parseCbom(driftDoc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** A screen as a VIEWER key sees it. Outside a provider the role is unknown, and offered. */
function asViewer(ui: ReactElement): ReactElement {
  const viewer: Auth = {
    status: "ready",
    principal: { name: "viewer-key", role: "viewer" } as Principal,
    reason: null,
    session: 0,
    signIn: async () => {},
    signOut: () => {},
  };
  return <AuthContext.Provider value={viewer}>{ui}</AuthContext.Provider>;
}

/** No band colour without its band's name; returns how many were checked. */
function colourIsSeverityOnly(): number {
  const audit = auditColour();
  expect(audit.violations).toEqual([]);
  return audit.coloured;
}

describe("Cryptographic Drift (drift.html)", () => {
  it("the selected chain beside the findings list, then layer coverage -- all from the drift records", async () => {
    render(<DriftScreen artefacts={drift} scan={scan} loading={false} />);
    const rows = screen.getAllByTestId("drift-row");
    expect(rows).toHaveLength(5);
    expect(rows[0]).toHaveAttribute("aria-selected", "true");

    const detail = () => screen.getByTestId("drift-panel");
    for (const view of ["declared", "shipped", "observed"]) {
      expect(within(detail()).getByTestId(`view-${view}`)).toBeInTheDocument();
    }
    // Exactly one arrow leads into the view that disagrees, and says so in words.
    expect(within(detail()).getAllByText("diverges")).toHaveLength(1);

    await userEvent.click(rows[1]);
    expect(rows[1]).toHaveAttribute("aria-selected", "true");
    expect(rows[0]).toHaveAttribute("aria-selected", "false");

    expect(screen.getByTestId("layer-coverage")).toBeInTheDocument();
    // The five list badges and the detail's: the only colour on the screen.
    expect(colourIsSeverityOnly()).toBe(6);
  });

  it("the mismatch is a border and a word, not red; provenance is a chip, not a colour", () => {
    render(<DriftScreen artefacts={drift} scan={scan} loading={false} />);
    const compared = screen
      .getAllByTestId(/^view-/)
      .find((node) => node.getAttribute("data-role") === "compared")!;
    expect(compared.className).toContain("mismatch");
    expect(compared.className).not.toMatch(/critical|high|medium|red/);
    expect(within(compared).getByText(/verified|provisional/i)).toHaveAttribute("data-provenance");
  });

  it("a viewer's Re-scan is disabled and says it needs an admin key", () => {
    render(asViewer(<DriftScreen artefacts={drift} scan={scan} loading={false} />));
    const button = screen.getByRole("button", { name: /re-scan/i });
    expect(button).toBeDisabled();
    expect(button.getAttribute("title")).toMatch(/admin key/i);
  });

  it("one view collected: the layer rows say which views are missing, and draw no bar for them", () => {
    render(<DriftScreen artefacts={z11} scan={scan} loading={false} />);
    for (const view of ["shipped", "observed"]) {
      const row = screen.getByTestId(`layer-${view}`);
      expect(row).toHaveAttribute("data-collected", "false");
      expect(row).toHaveTextContent(/not collected/i);
      expect(row.querySelector(".layer-fill")).toBeNull();
    }
    colourIsSeverityOnly();
  });
});
