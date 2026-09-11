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
import { FixesScreen } from "@/screens/Fixes";
import { AuthContext, type Auth } from "@/state/auth";
import { targetOf } from "@/state/metrics";
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

describe("Verified Fixes (fixes.html)", () => {
  // The z11 fixture carries no migration label, so one copy is given the
  // pack label the Target column reads (ADR-0030); MD5 stays unlabelled.
  const rsa = z11.find((a) => a.name === "RSA-2048")!;
  const withTarget = { ...rsa, labels: [...rsa.labels, "target-ml-kem"] };
  const artefacts = z11.map((a) => (a.bomRef === rsa.bomRef ? withTarget : a));
  const md5 = z11.find((a) => a.name === "MD5")!;
  const DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-sign(rsa)\n+sign(mldsa)";

  function stubFixes() {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith(`/scans/${scan.id}/fixes`)) {
          return new Response(
            JSON.stringify({
              parent_scan_id: scan.id,
              fix_scan_id: "fix-1",
              created_at: "2026-09-10T07:00:00Z",
              fixes: [
                {
                  bom_ref: withTarget.bomRef,
                  component: withTarget.name,
                  template: "source-rsa",
                  verified: true,
                  reason: "the sandbox re-scan no longer finds it",
                  source: "FIPS 204",
                  diff: DIFF,
                },
                {
                  bom_ref: md5.bomRef,
                  component: "MD5",
                  template: "source-md5",
                  verified: false,
                  reason: "the re-scan still found MD5",
                  source: null,
                  diff: null,
                },
              ],
            }),
            { status: 200 },
          );
        }
        return new Response("{}", { status: 404 });
      }),
    );
  }

  it("a card per fix: current, the pack's target, its band, and a diff for the verified one only", async () => {
    stubFixes();
    render(<FixesScreen scan={scan} artefacts={artefacts} />);
    const [verified, unverified] = await screen.findAllByTestId("fix-card");

    expect(targetOf(withTarget)).toBe("ML-KEM");
    expect(verified).toHaveTextContent("ML-KEM");
    expect(unverified).toHaveTextContent(/no target labelled by a pack/i);
    expect(within(verified).getByText(withTarget.band)).toHaveAttribute("data-band", withTarget.band);
    expect(verified.querySelector("pre.diff-block")).not.toBeNull();
    expect(verified.querySelectorAll(".diff-add")).toHaveLength(1);
    expect(verified.querySelectorAll(".diff-remove")).toHaveLength(1);
    expect(within(verified).getByRole("button", { name: /copy patch/i })).toBeInTheDocument();

    expect(unverified).toHaveTextContent("the re-scan still found MD5");
    expect(unverified.querySelector("pre")).toBeNull();
    expect(within(unverified).queryByRole("button", { name: /copy patch/i })).toBeNull();
    colourIsSeverityOnly();
  });

  it("the lifecycle marks only what ECDAT knows: proposed, and the sandbox verdict", async () => {
    stubFixes();
    render(<FixesScreen scan={scan} artefacts={artefacts} />);
    const [verified, unverified] = await screen.findAllByTestId("fix-card");
    const steps = (card: HTMLElement) =>
      Array.from(card.querySelectorAll("[data-state]")).map((step) => [step.textContent, step.getAttribute("data-state")]);

    expect(steps(verified)).toEqual([
      ["Proposed", "done"],
      ["Verified in sandbox", "done"],
      ["Applied externally", "current"],
      ["Re-scanned", "pending"],
    ]);
    expect(steps(unverified)).toEqual([
      ["Proposed", "done"],
      ["Not verified in sandbox", "failed"],
      ["Applied externally", "pending"],
      ["Re-scanned", "pending"],
    ]);
  });

  it("the diff is ink and weight, not red and green", async () => {
    stubFixes();
    render(<FixesScreen scan={scan} artefacts={artefacts} />);
    const [verified] = await screen.findAllByTestId("fix-card");
    for (const line of Array.from(verified.querySelectorAll(".diff-line"))) {
      expect(line.className).not.toMatch(/critical|red|green|ok\b/);
    }
  });
});
