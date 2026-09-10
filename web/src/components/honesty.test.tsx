/**
 * THE HONESTY RULE, at the DOM level (ADR-0031).
 *
 * Every panel is wired to real data or shows an honest "not computed" state.
 * The failure this file exists to catch is the quiet one: a metric the backend
 * never computed rendered as 0, a fake bar filling a card, a coverage gap
 * rendered as "all clear". None of those is visible in a screenshot review --
 * a plausible number looks exactly like a true one.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import driftDoc from "@/test/fixtures/cbom_drift.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { MetricCard } from "@/components/Honest";
import { AgilityScreen } from "@/screens/Agility";
import { CompareScreen } from "@/screens/Compare";
import { CoverageScreen } from "@/screens/Coverage";
import { DriftScreen } from "@/screens/Drift";
import { FixesScreen } from "@/screens/Fixes";
import { RiskAnalysisScreen } from "@/screens/RiskAnalysis";
import { RoadmapScreen } from "@/screens/Roadmap";

const z11 = parseCbom(z11Doc as unknown as Cbom);
const drift = parseCbom(driftDoc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function stubFetch(routes: Record<string, unknown>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    for (const [suffix, body] of Object.entries(routes)) {
      if (url.endsWith(suffix)) {
        return new Response(JSON.stringify(body), { status: 200 });
      }
    }
    return new Response("{}", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("a metric card", () => {
  it("NOT COMPUTED renders the empty state and never a number", () => {
    render(
      <MetricCard
        id="agility"
        label="Crypto agility"
        measured={{
          status: "not-computed",
          reason: "no component carries a configurability finding",
        }}
      />,
    );
    const card = screen.getByTestId("metric-agility");
    expect(card).toHaveAttribute("data-state", "not-computed");
    expect(card).toHaveTextContent(/not computed/i);
    expect(within(card).queryByTestId("metric-value")).toBeNull();
    expect(card.textContent).not.toMatch(/\d/);
  });

  it("a computed ZERO is a number, not an absence", () => {
    render(
      <MetricCard
        id="drift"
        label="Drift"
        measured={{ status: "computed", value: 0, basis: "all views agree" }}
      />,
    );
    const card = screen.getByTestId("metric-drift");
    expect(card).toHaveAttribute("data-state", "computed");
    expect(within(card).getByTestId("metric-value")).toHaveTextContent("0");
  });
});

describe("crypto agility", () => {
  it("shows the configurable share it CAN compute, and not-computed for the rest", () => {
    render(<AgilityScreen artefacts={z11} loading={false} />);

    expect(screen.getByTestId("agility-gauge")).toHaveTextContent("65%");
    expect(screen.getByTestId("agility-configurable")).toHaveTextContent("11");
    expect(screen.getByTestId("agility-hard-coded")).toHaveTextContent("6");

    for (const id of ["agility-key-store", "agility-protocol"]) {
      const row = screen.getByTestId(id);
      expect(row).toHaveAttribute("data-state", "not-computed");
      expect(row).toHaveTextContent(/not computed/i);
      expect(row.textContent).not.toMatch(/\d/);
    }
  });

  it("with no configurability finding anywhere, the gauge is empty — not 0%", () => {
    render(
      <AgilityScreen
        artefacts={z11.map((a) => ({ ...a, configurable: null }))}
        loading={false}
      />,
    );
    const gauge = screen.getByTestId("agility-gauge");
    expect(gauge).toHaveAttribute("data-state", "not-computed");
    expect(gauge.textContent).not.toMatch(/\d/);
  });
});

describe("compare scans", () => {
  it("with only one scan, asks for two and fabricates no diff", () => {
    const fetchMock = stubFetch({});
    render(<CompareScreen scans={[scan]} current={scan} />);

    const empty = screen.getByTestId("compare-empty");
    expect(empty).toHaveTextContent(/select two scans/i);
    expect(screen.queryAllByTestId("compare-count")).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("risk analysis", () => {
  it("is an honest placeholder that points at the screens that DO answer", () => {
    render(<RiskAnalysisScreen scan={scan} />);
    const placeholder = screen.getByTestId("risk-placeholder");
    expect(placeholder).toHaveTextContent(/scoped to the current scan/i);
    expect(within(placeholder).getByRole("link", { name: /inventory/i })).toHaveAttribute(
      "href",
      "#/inventory",
    );
    expect(within(placeholder).getByRole("link", { name: /drift/i })).toHaveAttribute(
      "href",
      "#/drift",
    );
    expect(screen.queryAllByTestId("metric-value")).toHaveLength(0);
  });
});

describe("cryptographic drift", () => {
  it("one view collected: 'cannot be assessed', NEVER 'no drift'", () => {
    render(<DriftScreen artefacts={z11} scan={scan} loading={false} />);
    const empty = screen.getByTestId("drift-empty");
    expect(empty).toHaveAttribute("data-kind", "not-assessable");
    expect(empty).toHaveTextContent(/not collected/i);
    expect(empty.textContent).not.toMatch(/no drift|views agree/i);
  });

  it("renders each drift across the three views, with the cause named", () => {
    render(<DriftScreen artefacts={drift} scan={scan} loading={false} />);
    const panels = screen.getAllByTestId("drift-panel");
    expect(panels).toHaveLength(5);

    const shipped = panels.find((p) =>
      p.textContent?.includes("shipped-cannot-do-declared"),
    )!;
    expect(within(shipped).getByTestId("view-shipped")).toHaveTextContent(
      "OpenSSL 3.0.2 (not PQC-capable)",
    );
    expect(within(shipped).getByTestId("view-observed")).toHaveTextContent(
      /not compared/i,
    );
    expect(shipped).toHaveTextContent(/lacks ML-KEM/);
    // No monitoring job exists, so there is no next check to show a date for.
    expect(within(shipped).getByTestId("next-check")).toHaveTextContent(/not scheduled/i);
  });
});

describe("migration roadmap", () => {
  it("draws a bar only for a dated artefact; the undated are listed, not placed", () => {
    render(<RoadmapScreen artefacts={z11} scan={scan} today="2026-09-10" />);
    expect(screen.getAllByTestId("roadmap-bar")).toHaveLength(3);
    expect(screen.getAllByTestId("roadmap-undated-item")).toHaveLength(14);
  });
});

describe("verified fixes", () => {
  it("no fix pass yet: says so and offers the pass, with no diff anywhere", async () => {
    stubFetch({
      [`/scans/${scan.id}/fixes`]: {
        parent_scan_id: scan.id,
        fix_scan_id: null,
        created_at: null,
        fixes: [],
      },
    });
    const { container } = render(<FixesScreen scan={scan} />);

    await screen.findByText(/no fix pass has been run/i);
    expect(screen.getByRole("button", { name: /run fix pass/i })).toBeInTheDocument();
    expect(container.querySelector("pre")).toBeNull();
  });

  it("an unverified fix shows its reason and NO patch to copy", async () => {
    stubFetch({
      [`/scans/${scan.id}/fixes`]: {
        parent_scan_id: scan.id,
        fix_scan_id: "fix-1",
        created_at: "2026-09-10T07:00:00Z",
        fixes: [
          {
            bom_ref: "abc",
            component: "MD5",
            template: "source-md5",
            verified: false,
            reason: "the re-scan still found MD5",
            source: null,
            diff: null,
          },
        ],
      },
    });
    const { container } = render(<FixesScreen scan={scan} />);

    const card = await screen.findByTestId("fix-card");
    expect(card).toHaveAttribute("data-verified", "false");
    expect(card).toHaveTextContent(/not verified/i);
    expect(card).toHaveTextContent("the re-scan still found MD5");
    expect(within(card).queryByRole("button", { name: /copy patch/i })).toBeNull();
    expect(container.querySelector("pre")).toBeNull();
  });
});

describe("coverage", () => {
  it("a row that never recorded its scanners says UNKNOWN, never NOT RUN", async () => {
    stubFetch({
      "/api/scanners": ["binary", "config", "container", "deps", "runtime-spool", "source"],
    });
    render(<CoverageScreen scan={{ ...scan, scanners_ran: null }} artefacts={z11} />);

    await waitFor(() => expect(screen.getAllByTestId("scanner-card")).toHaveLength(6));
    for (const card of screen.getAllByTestId("scanner-card")) {
      expect(card).toHaveAttribute("data-status", "UNKNOWN");
      expect(card.textContent).not.toMatch(/not run/i);
    }
  });
});
