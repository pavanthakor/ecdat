/**
 * Scan History reads the list a PAGE at a time (ADR-0035).
 *
 * `GET /scans` used to return every row ever stored -- and every Mosca slider
 * settle stores one. The screen now asks for one page, shows "a–b of total",
 * and asks the server for the next page rather than slicing a list it holds.
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import scansDoc from "@/test/fixtures/scans.json";

import type { ScanSummary } from "@/api/types";
import type { ScanView } from "@/state/inventory";
import { SCANS_PAGE_SIZE, ScansScreen } from "./Scans";

const base = (scansDoc as unknown as ScanSummary[])[0];
/** Sixty stored scans, newest first, as the store would order them. */
const ROWS: ScanSummary[] = Array.from({ length: 60 }, (_, index) => ({
  ...base,
  id: `${String(index).padStart(8, "0")}-0000-4000-8000-000000000000`,
  target: { ...base.target, ref: `repo/${index}` },
}));

function server() {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      const [path, query = ""] = url.split("?");
      if (!path.endsWith("/api/scans")) return new Response("{}", { status: 404 });
      const params = new URLSearchParams(query);
      const limit = Number(params.get("limit") ?? 50);
      const offset = Number(params.get("offset") ?? 0);
      const kind = params.get("kind");
      const matching = kind ? ROWS.filter((row) => row.kind === kind) : ROWS;
      return new Response(
        JSON.stringify({
          items: matching.slice(offset, offset + limit),
          total: matching.length,
          limit,
          offset,
        }),
        { status: 200 },
      );
    }),
  );
  return calls;
}

function view(): ScanView {
  return {
    scans: ROWS.slice(0, 50),
    scan: ROWS[0],
    artefacts: [],
    zYears: 11,
    loading: false,
    rescoring: false,
    error: null,
    setZYears: () => {},
    selectScan: () => {},
    reload: () => {},
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("Scan History -- one page at a time", () => {
  it("asks for one page, and shows its range against the server's total", async () => {
    const calls = server();
    render(<ScansScreen view={view()} />);

    expect(await screen.findByText(`Showing 1–${SCANS_PAGE_SIZE} of 60`)).toBeInTheDocument();
    expect(screen.getAllByTestId("scan-row")).toHaveLength(SCANS_PAGE_SIZE);
    expect(calls).toContain(`/api/scans?kind=scan&limit=${SCANS_PAGE_SIZE}&offset=0`);
  });

  it("Next asks the SERVER for the next page; Previous goes back; the last page is short", async () => {
    const calls = server();
    render(<ScansScreen view={view()} />);
    await screen.findByText(`Showing 1–${SCANS_PAGE_SIZE} of 60`);
    const previous = screen.getByRole("button", { name: /previous page/i });
    const next = screen.getByRole("button", { name: /next page/i });
    expect(previous).toBeDisabled();

    await userEvent.click(next);
    expect(await screen.findByText("Showing 26–50 of 60")).toBeInTheDocument();
    expect(calls).toContain(`/api/scans?kind=scan&limit=${SCANS_PAGE_SIZE}&offset=25`);
    expect(screen.getAllByTestId("scan-row")[0]).toHaveTextContent("repo/25");

    await userEvent.click(next);
    expect(await screen.findByText("Showing 51–60 of 60")).toBeInTheDocument();
    expect(screen.getAllByTestId("scan-row")).toHaveLength(10);
    expect(next).toBeDisabled();

    await userEvent.click(previous);
    expect(await screen.findByText("Showing 26–50 of 60")).toBeInTheDocument();
  });
});
