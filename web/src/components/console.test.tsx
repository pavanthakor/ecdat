/**
 * The two interactions this polish pass changed, at the DOM level.
 *
 * `presentation.test.ts` pins the arithmetic; these pin that the arithmetic
 * reaches the screen -- a readout wired to the wrong source and an empty state
 * that renders the generic message are both silent failures.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import App from "@/App";
import { parseCbom } from "@/api/parse";
import type { Cbom, ScanSummary } from "@/api/types";
import { InventoryTable } from "./InventoryTable";
import { NO_FILTERS } from "@/state/inventory";
import { emptyStateOf } from "@/state/presentation";

const scan = (scansDoc as unknown as ScanSummary[])[0];

afterEach(() => vi.restoreAllMocks());

function mockApi() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/scans")) {
        return new Response(JSON.stringify(scansDoc), { status: 200 });
      }
      if (url.endsWith("/cbom")) {
        return new Response(
          JSON.stringify(url.includes("rescored") ? z5Doc : z11Doc),
          { status: 200 },
        );
      }
      if (url.includes("/rescore?")) {
        return new Response(
          JSON.stringify({
            scan_id: "rescored-1",
            parent_scan_id: scan.id,
            kind: "rescore",
          }),
          { status: 201 },
        );
      }
      return new Response("{}", { status: 404 });
    }),
  );
}

function table(overrides: Partial<Parameters<typeof InventoryTable>[0]> = {}) {
  const props: Parameters<typeof InventoryTable>[0] = {
    rows: [],
    total: 0,
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

describe("the three empty states", () => {
  it("no scan selected -- no action offered", () => {
    table({ emptyState: emptyStateOf({ scan: null, total: 0, shown: 0 }) });

    const empty = screen.getByTestId("empty-state");
    expect(empty).toHaveAttribute("data-empty-kind", "no-scan");
    expect(empty).toHaveTextContent(/no scan selected/i);
    expect(screen.queryByRole("button", { name: /clear filters/i })).toBeNull();
  });

  it("scan found nothing -- no action, and no mention of filters", () => {
    // Offering "clear filters" here sends a reader after a control that
    // cannot help: the scan ran and the estate is empty.
    table({ emptyState: emptyStateOf({ scan, total: 0, shown: 0 }) });

    const empty = screen.getByTestId("empty-state");
    expect(empty).toHaveAttribute("data-empty-kind", "no-artefacts");
    expect(empty).toHaveTextContent(/found no cryptographic artefacts/i);
    expect(screen.queryByRole("button", { name: /clear filters/i })).toBeNull();
  });

  it("filters exclude everything -- says how many, and offers the fix", () => {
    const onClearFilters = vi.fn();
    table({
      total: 17,
      emptyState: emptyStateOf({ scan, total: 17, shown: 0 }),
      onClearFilters,
    });

    const empty = screen.getByTestId("empty-state");
    expect(empty).toHaveAttribute("data-empty-kind", "filtered-out");
    expect(empty).toHaveTextContent(/17 artefacts/);
    screen.getByRole("button", { name: /clear filters/i }).click();
    expect(onClearFilters).toHaveBeenCalled();
  });

  it("shows skeleton rows while loading, never an empty flash", () => {
    const { container } = table({
      loading: true,
      emptyState: emptyStateOf({ scan, total: 0, shown: 0 }),
    });

    expect(container.querySelectorAll("tbody tr").length).toBeGreaterThan(5);
    expect(screen.queryByTestId("empty-state")).toBeNull();
  });
});

describe("severity accent on the row", () => {
  it("marks EVERY row with an inset bar in its band colour, never a row fill", () => {
    // ADR-0032: the design puts the bar on every row, Medium and Low included
    // (ADR-0018 had it on Critical and High only).
    const rows = parseCbom(z11Doc as unknown as Cbom);
    const { container } = table({ rows, total: rows.length });
    const bar = (band: string) =>
      container.querySelector(`tr[data-band="${band}"] [data-testid="severity-bar"]`)!;

    expect(bar("Critical").className).toContain("bg-critical");
    expect(bar("High").className).toContain("bg-high");
    expect(bar("Low").className).toContain("bg-low");
    // An edge marker, not a fill: the row keeps its own background.
    const critical = container.querySelector('tr[data-band="Critical"]')!;
    expect(critical.className).not.toContain("bg-critical");
  });
});

describe("the filter bar (ADR-0032: band and view are selects)", () => {
  it("choosing a band narrows to that band", async () => {
    const onFilters = vi.fn();
    table({ onFilters });
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Band" }), "Critical");
    expect(onFilters).toHaveBeenLastCalledWith({ ...NO_FILTERS, bands: ["Critical"] });
  });

  it("'All bands' clears the band constraint rather than matching nothing", async () => {
    const onFilters = vi.fn();
    table({ filters: { ...NO_FILTERS, bands: ["Critical"] }, onFilters });
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Band" }), "All bands");
    expect(onFilters).toHaveBeenLastCalledWith({ ...NO_FILTERS, bands: [] });
  });
});

describe("the live consequence readout", () => {
  it("shows the band counts of what is on screen, and MOVES with the slider", async () => {
    mockApi();
    render(<App />);
    await waitFor(() =>
      expect(within(screen.getByTestId("live-readout")).getByTestId("live-Low"))
        .toHaveTextContent("14"),
    );

    const readout = () => screen.getByTestId("live-readout");
    expect(within(readout()).getByTestId("live-Critical")).toHaveTextContent("2");
    expect(within(readout()).getByTestId("live-High")).toHaveTextContent("1");
    expect(within(readout()).getByTestId("live-Medium")).toHaveTextContent("0");

    // Drag the horizon in. The numbers must follow the rescored document.
    const slider = screen.getByRole("slider");
    slider.focus();
    for (let i = 0; i < 6; i += 1) {
      await import("@testing-library/user-event").then(({ default: user }) =>
        user.keyboard("{ArrowLeft}"),
      );
    }

    await waitFor(
      () =>
        expect(
          within(screen.getByTestId("live-readout")).getByTestId("live-Medium"),
        ).toHaveTextContent("14"),
      { timeout: 3000 },
    );
    expect(within(readout()).getByTestId("live-Critical")).toHaveTextContent("3");
    expect(within(readout()).getByTestId("live-High")).toHaveTextContent("0");
    expect(within(readout()).getByTestId("live-Low")).toHaveTextContent("0");
  });
});
