/**
 * Candidate vs everything else, ON SCREEN.
 *
 * The table tags ONE thing: a finding its rule flagged a CANDIDATE (ADR-0034),
 * one that might not be real key material. A finding that is real crypto with
 * one detail inferred -- a parameter that came through a variable, a binary
 * heuristic -- is NOT tagged: the table does not shout about it. Its
 * confidence is still on the page, in the drawer, with the reason. Nothing is
 * hidden; only what the table shouts changed (the follow-up to 0d22a73, which
 * tagged everything below 1.0).
 *
 * The discipline from the first version holds: border, weight and a word,
 * never colour. Severity classes are identical across candidate, inferred and
 * confirmed rows of one band.
 *
 * Every artefact comes from a document a real scan stored:
 * `cbom_candidate.json` (testdata/js_fixtures) and `cbom_binary.json`
 * (testdata/binary_fixtures, binary scanner only).
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import binaryDoc from "@/test/fixtures/cbom_binary.json";
import candidateDoc from "@/test/fixtures/cbom_candidate.json";
import scansDoc from "@/test/fixtures/scans.json";

import { parseCbom } from "@/api/parse";
import type { Artefact, Cbom, ScanSummary } from "@/api/types";
import { InventoryScreen } from "@/screens/Inventory";
import { NO_FILTERS, type Filters, type ScanView } from "@/state/inventory";
import { ArtefactDrawer } from "./ArtefactDrawer";
import { InventoryTable } from "./InventoryTable";

const artefacts = parseCbom(candidateDoc as unknown as Cbom);
const binary = parseCbom(binaryDoc as unknown as Cbom);
const scan = (scansDoc as unknown as ScanSummary[])[0];
const rulesOf = (artefact: Artefact) => artefact.occurrences.map((o) => o.detail);

/** 0.5, Low, flagged: the ADR-0034 candidate. */
const candidate = artefacts.find((a) => a.candidate)!;
/** 1.0, Low: a key that reached a sink, its candidate folded in. */
const confirmed = artefacts.find(
  (a) =>
    rulesOf(a).includes("rule=js-hardcoded-key") &&
    rulesOf(a).includes("rule=js-hardcoded-key-candidate"),
)!;
/** 0.6, Medium: an ECDSA JWT whose algorithm arrived through a variable. */
const unresolved = artefacts.find((a) => rulesOf(a).includes("rule=js-jwt-ecdsa"))!;
/** 0.6, Low: an HMAC JWT, the same kind of inferred detail. */
const lowInferred = artefacts.find((a) => rulesOf(a).includes("rule=js-jwt-hmac"))!;
/** 0.9, Low: a binary finding -- the linker resolved EVP_aes_256_gcm. */
const symbol = binary.find(
  (a) => a.confidence === 0.9 && rulesOf(a).includes("symbol=EVP_aes_256_gcm"),
)!;

/** Any band colour token. The candidate marker must carry none of them. */
const BAND_COLOUR = /\b(?:text|bg|border)-(?:critical|high|medium|low)\b/;

function table(overrides: Partial<Parameters<typeof InventoryTable>[0]> = {}) {
  const rows = [candidate, confirmed, unresolved, lowInferred, symbol];
  const props: Parameters<typeof InventoryTable>[0] = {
    rows,
    total: rows.length,
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

function Harness({ items }: { items: Artefact[] }) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const view: ScanView = {
    scans: [scan],
    scan,
    artefacts: items,
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

const rows = () => screen.getAllByRole("row").filter((row) => row.hasAttribute("data-certainty"));

describe("the fixtures are the cases this slice is about", () => {
  it("a Low candidate, a Low confirmed key, 0.6 findings in Medium and Low, and a 0.9 binary finding", () => {
    expect([candidate.band, candidate.confidence, candidate.candidate]).toEqual(["Low", 0.5, true]);
    expect([confirmed.band, confirmed.confidence, confirmed.candidate]).toEqual(["Low", 1, false]);
    expect([unresolved.band, unresolved.confidence, unresolved.candidate]).toEqual([
      "Medium",
      0.6,
      false,
    ]);
    expect([lowInferred.band, lowInferred.confidence, lowInferred.candidate]).toEqual([
      "Low",
      0.6,
      false,
    ]);
    expect([symbol.band, symbol.confidence, symbol.candidate]).toEqual(["Low", 0.9, false]);
  });
});

describe("the inventory row -- the tag is for candidates only", () => {
  it("a flagged candidate: a dashed 'candidate' tag, a lighter name, its confidence in words", () => {
    const { container } = table();
    const row = rowOf(container, candidate);

    expect(row).toHaveAttribute("data-certainty", "candidate");
    const tag = within(row).getByTestId("candidate-tag");
    expect(tag).toHaveTextContent(/candidate/i);
    expect(tag.className).toContain("border-dashed");
    expect(row).toHaveTextContent("confidence 0.5");
    expect(within(row).getByTestId("artefact-name").className).not.toContain("font-semibold");
  });

  it("a 1.0 finding has NO candidate marker", () => {
    const { container } = table();
    const row = rowOf(container, confirmed);

    expect(row).toHaveAttribute("data-certainty", "confirmed");
    expect(within(row).queryByTestId("candidate-tag")).toBeNull();
    expect(row).not.toHaveTextContent(/candidate|confidence/i);
    expect(within(row).getByTestId("artefact-name").className).toContain("font-semibold");
  });

  it("a 0.6 finding whose parameter came from a variable has NO candidate marker", () => {
    const { container } = table();

    for (const artefact of [unresolved, lowInferred]) {
      const row = rowOf(container, artefact);
      expect(row).toHaveAttribute("data-certainty", "inferred");
      expect(within(row).queryByTestId("candidate-tag")).toBeNull();
      expect(row).not.toHaveTextContent(/candidate|confidence/i);
      expect(within(row).getByTestId("artefact-name").className).toContain("font-semibold");
    }
  });

  it("a 0.9 binary finding has NO candidate marker", () => {
    const { container } = table();
    const row = rowOf(container, symbol);

    expect(row).toHaveAttribute("data-certainty", "inferred");
    expect(within(row).queryByTestId("candidate-tag")).toBeNull();
    expect(row).not.toHaveTextContent(/candidate|confidence/i);
  });

  it("a whole binary scan carries no candidate tag at all", () => {
    table({ rows: binary, total: binary.length });
    expect(screen.queryAllByTestId("candidate-tag")).toHaveLength(0);
  });

  it("names the marker in the legend beside Verified and Provisional", () => {
    table();
    expect(screen.getByTestId("legend-candidate")).toHaveTextContent(/candidate/i);
  });
});

describe("border and weight, never colour", () => {
  it("candidate, inferred and confirmed rows of one band share their band colour exactly", () => {
    const { container } = table();
    const pill = (a: Artefact) => within(rowOf(container, a)).getByTestId("band-pill").className;
    const bar = (a: Artefact) => within(rowOf(container, a)).getByTestId("severity-bar").className;

    for (const other of [confirmed, lowInferred, symbol]) {
      expect(pill(other)).toBe(pill(candidate));
      expect(bar(other)).toBe(bar(candidate));
    }
  });

  it("the candidate marker itself carries no band colour", () => {
    const { container } = table();
    const row = rowOf(container, candidate);

    expect(within(row).getByTestId("candidate-tag").className).not.toMatch(BAND_COLOUR);
    expect(row.className).not.toMatch(BAND_COLOUR);
    expect(within(row).getByTestId("artefact-name").className).not.toMatch(BAND_COLOUR);
  });

  it("a Medium inferred finding keeps its Medium colour and gains no marker", () => {
    const { container } = table();
    const row = rowOf(container, unresolved);

    // v2 (ADR-0039): the band badge and the rail carry the band as a class.
    expect(within(row).getByTestId("band-pill").className).toContain("badge-medium");
    expect(within(row).getByTestId("severity-bar").className).toContain("bg-medium");
    expect(within(row).queryByTestId("candidate-tag")).toBeNull();
  });
});

describe("the drawer shows confidence for EVERY finding", () => {
  it("a candidate: 0.5, marked candidate, dashed, with the ADR-0034 sentence", () => {
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

  it("a 0.6 inferred finding: its confidence and the 'inferred' sentence, not the candidate story", () => {
    render(<ArtefactDrawer artefact={unresolved} onClose={() => {}} />);

    const badge = screen.getByTestId("certainty");
    expect(badge).toHaveAttribute("data-certainty", "inferred");
    expect(badge).toHaveTextContent(/inferred/i);
    expect(badge).not.toHaveTextContent(/candidate/i);
    expect(badge.className).not.toContain("border-dashed");

    const block = screen.getByTestId("confidence");
    expect(block).toHaveTextContent("0.6");
    expect(block).toHaveTextContent(/inferred/i);
    expect(block).not.toHaveTextContent(/candidate/i);
    expect(block.className).not.toContain("border-dashed");

    const reason = screen.getByTestId("certainty-reason");
    expect(reason).toHaveTextContent(/inferred/i);
    expect(reason).not.toHaveTextContent(/high-entropy|candidate/i);
  });

  it("a 0.9 binary finding: 0.9 in the drawer, inferred, no candidate", () => {
    render(<ArtefactDrawer artefact={symbol} onClose={() => {}} />);

    expect(screen.getByTestId("certainty")).toHaveAttribute("data-certainty", "inferred");
    expect(screen.getByTestId("confidence")).toHaveTextContent("0.9");
    expect(screen.getByTestId("confidence")).not.toHaveTextContent(/candidate/i);
    expect(screen.getByTestId("certainty-reason")).toHaveTextContent(/inferred/i);
  });

  it("a confirmed finding: 1.0, solid, confirmed", () => {
    render(<ArtefactDrawer artefact={confirmed} onClose={() => {}} />);

    const badge = screen.getByTestId("certainty");
    expect(badge).toHaveAttribute("data-certainty", "confirmed");
    expect(badge.className).not.toContain("border-dashed");
    expect(screen.getByTestId("confidence")).toHaveTextContent("1.0");
    expect(screen.getByTestId("confidence")).toHaveTextContent(/confirmed/i);
  });

  it("the drawer's band chip is the same colour for a Low candidate, a Low inferred and a Low confirmed finding", () => {
    const chips: string[] = [];
    for (const artefact of [candidate, lowInferred, symbol, confirmed]) {
      const view = render(<ArtefactDrawer artefact={artefact} onClose={() => {}} />);
      chips.push(screen.getByTestId("band-chip").className);
      view.unmount();
    }
    expect(new Set(chips).size).toBe(1);
  });
});

describe("the candidates / confirmed filter", () => {
  it("the Candidates toggle counts only ACTUAL candidates; Confirmed counts the rest", () => {
    render(<Harness items={artefacts} />);

    const candidates = screen.getByRole("button", { name: /candidates/i });
    const confirmedButton = screen.getByRole("button", { name: /confirmed/i });
    expect(within(candidates).getByText("1")).toBeInTheDocument();
    // 37 findings, 1 flagged: the 31 at 1.0 AND the five inferred at 0.6.
    expect(within(confirmedButton).getByText("36")).toBeInTheDocument();
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

  it("narrows the real Inventory screen: Candidates shows the ONE flagged finding", async () => {
    render(<Harness items={artefacts} />);
    expect(rows()).toHaveLength(37);

    await userEvent.click(screen.getByRole("button", { name: /candidates/i }));
    expect(rows()).toHaveLength(1);
    expect(rows()[0]).toHaveAttribute("data-ref", candidate.bomRef);

    // Confirmed = everything that is NOT a flagged candidate: the 1.0 rows AND
    // the inferred 0.6 rows. Only the candidate is gone.
    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(rows()).toHaveLength(36);
    expect(rows().some((row) => row.getAttribute("data-certainty") === "candidate")).toBe(false);
    expect(rows().some((row) => row.getAttribute("data-ref") === candidate.bomRef)).toBe(false);
    expect(rows().some((row) => row.getAttribute("data-ref") === unresolved.bomRef)).toBe(true);

    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(rows()).toHaveLength(37);
  });

  it("on a binary scan, Candidates finds nothing and Confirmed shows every finding", async () => {
    render(<Harness items={binary} />);
    expect(rows()).toHaveLength(22);

    await userEvent.click(screen.getByRole("button", { name: /candidates/i }));
    expect(screen.queryAllByRole("row").filter((row) => row.hasAttribute("data-certainty"))).toHaveLength(0);
    expect(screen.getByTestId("empty-state")).toHaveAttribute("data-empty-kind", "filtered-out");

    await userEvent.click(screen.getByRole("button", { name: /confirmed/i }));
    expect(rows()).toHaveLength(22);
  });
});
