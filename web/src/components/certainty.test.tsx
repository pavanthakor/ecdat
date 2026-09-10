/**
 * Candidate vs confirmed, ON SCREEN (ADR-0034 carried to the console).
 *
 * A 0.5 candidate rendered exactly like a confirmed finding is an uncertain
 * claim presented as a confident one, in the one place a reviewer looks. These
 * pin that the console SAYS "not sure" -- in the table, in the drawer, and in a
 * filter -- and that it says it the way it already says "provisional": by
 * BORDER and WEIGHT and a word, never by colour. Colour is severity and nothing
 * else, so a Low candidate and a Low confirmed finding must share their band
 * colour exactly; only the marker differs.
 *
 * Every artefact here comes from `cbom_candidate.json`, a document a real scan
 * stored.
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import candidateDoc from "@/test/fixtures/cbom_candidate.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Artefact, Cbom, ScanSummary } from "@/api/types";
import { InventoryScreen } from "@/screens/Inventory";
import { NO_FILTERS, type Filters, type ScanView } from "@/state/inventory";
import { ArtefactDrawer } from "./ArtefactDrawer";
import { InventoryTable } from "./InventoryTable";

const artefacts = parseCbom(candidateDoc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];
const rulesOf = (artefact: Artefact) => artefact.occurrences.map((o) => o.detail);

/** 0.5, band Low: the ADR-0034 candidate. */
const candidate = artefacts.find((a) => a.candidate)!;
/** 1.0, band Low: a key that reached a sink, its candidate folded in. */
const confirmed = artefacts.find(
  (a) =>
    rulesOf(a).includes("rule=js-hardcoded-key") &&
    rulesOf(a).includes("rule=js-hardcoded-key-candidate"),
)!;
/** 0.6, band Medium: an ECDSA JWT whose parameter never resolved. */
const unresolved = artefacts.find((a) => rulesOf(a).includes("rule=js-jwt-ecdsa"))!;

/** Any band colour token. The candidate marker must carry none of them. */
const BAND_COLOUR = /\b(?:text|bg|border)-(?:critical|high|medium|low)\b/;

function table(overrides: Partial<Parameters<typeof InventoryTable>[0]> = {}) {
  const props: Parameters<typeof InventoryTable>[0] = {
    rows: [candidate, confirmed, unresolved],
    total: 3,
    sort: { column: "score", direction: "desc" },
    filters: NO_FILTERS,
    selected: null,
    loading: false,
    emptyState: null,
    onSort: () => {},
    onFilters: () => {},
    onSelect: () => {},
    onClearFilters: () => {},
    ...overrides,
  };
  return render(<InventoryTable {...props} />);
}

function rowOf(container: HTMLElement, artefact: Artefact): HTMLElement {
  const row = container.querySelector<HTMLElement>(`tr[data-ref="${artefact.bomRef}"]`);
  if (!row) throw new Error(`no row for ${artefact.bomRef}`);
  return row;
}

describe("the fixture is the case this slice is about", () => {
  it("has a Low candidate, a Low confirmed key and a Medium 0.6 finding", () => {
    expect([candidate.band, candidate.confidence, candidate.candidate]).toEqual(["Low", 0.5, true]);
    expect([confirmed.band, confirmed.confidence, confirmed.candidate]).toEqual(["Low", 1, false]);
    expect([unresolved.band, unresolved.confidence, unresolved.candidate]).toEqual([
      "Medium",
      0.6,
      false,
    ]);
  });
});

describe("the inventory row", () => {
  it("marks a 0.5 candidate: a dashed 'candidate' tag, a lighter name, its confidence in words", () => {
    const { container } = table();
    const row = rowOf(container, candidate);

    expect(row).toHaveAttribute("data-certainty", "candidate");
    const tag = within(row).getByTestId("candidate-tag");
    expect(tag).toHaveTextContent(/candidate/i);
    expect(tag.className).toContain("border-dashed");
    // In the text, not only in a tooltip: a caveat that needs a hover is a
    // caveat that will be missed on a projector (ADR-0018).
    expect(row).toHaveTextContent("confidence 0.5");
    expect(within(row).getByTestId("artefact-name").className).not.toContain("font-semibold");
  });

  it("renders a 1.0 finding with NO candidate marker", () => {
    const { container } = table();
    const row = rowOf(container, confirmed);

    expect(row).toHaveAttribute("data-certainty", "confirmed");
    expect(within(row).queryByTestId("candidate-tag")).toBeNull();
    expect(row).not.toHaveTextContent(/confidence/i);
    expect(within(row).getByTestId("artefact-name").className).toContain("font-semibold");
  });

  it("gives a 0.6 finding the same treatment: anything below 1.0 is marked", () => {
    const { container } = table();
    const row = rowOf(container, unresolved);

    expect(row).toHaveAttribute("data-certainty", "candidate");
    expect(within(row).getByTestId("candidate-tag")).toBeInTheDocument();
    expect(row).toHaveTextContent("confidence 0.6");
  });

  it("names the marker in the legend beside Verified and Provisional", () => {
    table();
    expect(screen.getByTestId("legend-candidate")).toHaveTextContent(/candidate/i);
  });
});

describe("border and weight, never colour", () => {
  it("a Low candidate and a Low confirmed finding share their band colour exactly", () => {
    const { container } = table();
    const pill = (a: Artefact) => within(rowOf(container, a)).getByTestId("band-pill").className;
    const bar = (a: Artefact) => within(rowOf(container, a)).getByTestId("severity-bar").className;

    expect(pill(candidate)).toBe(pill(confirmed));
    expect(bar(candidate)).toBe(bar(confirmed));
  });

  it("the candidate marker itself carries no band colour", () => {
    const { container } = table();
    const row = rowOf(container, candidate);

    expect(within(row).getByTestId("candidate-tag").className).not.toMatch(BAND_COLOUR);
    expect(row.className).not.toMatch(BAND_COLOUR);
    expect(within(row).getByTestId("artefact-name").className).not.toMatch(BAND_COLOUR);
  });

  it("a Medium candidate keeps its Medium colour: severity still means severity", () => {
    const { container } = table();
    const row = rowOf(container, unresolved);

    expect(within(row).getByTestId("band-pill").className).toContain("text-medium");
    expect(within(row).getByTestId("severity-bar").className).toContain("bg-medium");
  });
});

describe("the drawer says how sure ECDAT is, and why", () => {
  it("a candidate: confidence 0.5, marked candidate, dashed, with the ADR-0034 reason", () => {
    render(<ArtefactDrawer artefact={candidate} onClose={() => {}} />);

    const badge = screen.getByTestId("certainty");
    expect(badge).toHaveAttribute("data-certainty", "candidate");
    expect(badge.className).toContain("border-dashed");
    expect(badge).toHaveTextContent(/candidate/i);

    const block = screen.getByTestId("confidence");
    expect(block).toHaveTextContent("0.5");
    expect(block).toHaveTextContent(/candidate/i);
    expect(block.className).toContain("border-dashed");

    const reason = screen.getByTestId("certainty-reason");
    expect(reason).toHaveTextContent(/high-entropy/i);
    expect(reason).toHaveTextContent(/crypto sink/i);
  });

  it("a confirmed finding: confidence 1.0, solid, confirmed", () => {
    render(<ArtefactDrawer artefact={confirmed} onClose={() => {}} />);

    const badge = screen.getByTestId("certainty");
    expect(badge).toHaveAttribute("data-certainty", "confirmed");
    expect(badge.className).not.toContain("border-dashed");
    expect(screen.getByTestId("confidence")).toHaveTextContent("1.0");
    expect(screen.getByTestId("confidence")).toHaveTextContent(/confirmed/i);
  });

  it("a 0.6 finding states 0.6 and does not claim to be a high-entropy literal", () => {
    render(<ArtefactDrawer artefact={unresolved} onClose={() => {}} />);

    expect(screen.getByTestId("certainty")).toHaveAttribute("data-certainty", "candidate");
    expect(screen.getByTestId("confidence")).toHaveTextContent("0.6");
    expect(screen.getByTestId("certainty-reason")).not.toHaveTextContent(/high-entropy/i);
  });

  it("the drawer's band chip is the same colour for a Low candidate and a Low confirmed finding", () => {
    const first = render(<ArtefactDrawer artefact={candidate} onClose={() => {}} />);
    const candidateChip = screen.getByTestId("band-chip").className;
    first.unmount();

    render(<ArtefactDrawer artefact={confirmed} onClose={() => {}} />);
    expect(screen.getByTestId("band-chip").className).toBe(candidateChip);
  });
});

describe("the candidates / confirmed filter", () => {
  it("offers both toggles with their counts, neither pressed by default", () => {
    table({ candidateCount: 6, confirmedCount: 31 });

    const candidates = screen.getByRole("button", { name: /candidates/i });
    const confirmedButton = screen.getByRole("button", { name: /confirmed/i });
    expect(candidates).toHaveAttribute("aria-pressed", "false");
    expect(confirmedButton).toHaveAttribute("aria-pressed", "false");
    expect(candidates).toHaveTextContent("6");
    expect(confirmedButton).toHaveTextContent("31");
  });

  it("pressing 'Candidates' asks for candidates only", async () => {
    const onFilters = vi.fn();
    table({ onFilters });

    await userEvent.click(screen.getByRole("button", { name: /candidates/i }));
    expect(onFilters).toHaveBeenLastCalledWith({ ...NO_FILTERS, certainty: "candidates" });
  });

  it("pressing the active toggle again clears it", async () => {
    const onFilters = vi.fn();
    table({ filters: { ...NO_FILTERS, certainty: "candidates" }, onFilters });

    const candidates = screen.getByRole("button", { name: /candidates/i });
    expect(candidates).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(candidates);
    expect(onFilters).toHaveBeenLastCalledWith({ ...NO_FILTERS, certainty: "all" });
  });

  it("the two toggles are exclusive: 'Confirmed' replaces 'Candidates'", async () => {
    const onFilters = vi.fn();
    table({ filters: { ...NO_FILTERS, certainty: "candidates" }, onFilters });

    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(onFilters).toHaveBeenLastCalledWith({ ...NO_FILTERS, certainty: "confirmed" });
  });

  it("narrows the real Inventory screen end to end", async () => {
    function Harness() {
      const [filters, setFilters] = useState<Filters>(NO_FILTERS);
      const view: ScanView = {
        scans: [scan],
        scan,
        artefacts,
        zYears: 11,
        loading: false,
        rescoring: false,
        error: null,
        setZYears: () => {},
        selectScan: () => {},
        reload: () => {},
      };
      return (
        <InventoryScreen view={view} filters={filters} onFilters={setFilters} selectedRef={null} />
      );
    }
    render(<Harness />);
    const rows = () =>
      screen.getAllByRole("row").filter((row) => row.hasAttribute("data-certainty"));

    expect(rows()).toHaveLength(37);

    await userEvent.click(screen.getByRole("button", { name: /candidates/i }));
    expect(rows()).toHaveLength(6);
    expect(rows().every((row) => row.getAttribute("data-certainty") === "candidate")).toBe(true);

    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(rows()).toHaveLength(31);
    expect(rows().every((row) => row.getAttribute("data-certainty") === "confirmed")).toBe(true);

    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(rows()).toHaveLength(37);
  });
});
