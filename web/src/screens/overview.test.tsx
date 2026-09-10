/**
 * The Overview's CRQC-horizon slider drives the whole screen through a REAL
 * rescore round trip (ADR-0016 -> ADR-0018 -> ADR-0031).
 *
 * What this pins: moving Z issues ONE debounced `POST /scans/{id}/rescore`
 * against the ORIGINAL scan, the new row's document is fetched, and every
 * band-derived number on the Overview follows it -- the metric cards, the live
 * readout and the horizon delta. A card wired to the stored row instead of the
 * live document would freeze at the old horizon, and would look fine.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import z5Doc from "@/test/fixtures/cbom_z5.json";
import scansDoc from "@/test/fixtures/scans.json";

import App from "@/App";
import type { ScanSummary } from "@/api/types";

const scan = (scansDoc as unknown as ScanSummary[])[0];

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  window.location.hash = "#/overview";
  fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.split("?")[0].endsWith("/api/scans")) {
      // A page, as GET /scans answers since ADR-0035.
      return new Response(
        JSON.stringify({ items: scansDoc, total: scansDoc.length, limit: 50, offset: 0 }),
        { status: 200 },
      );
    }
    if (url.endsWith("/cbom")) {
      return new Response(JSON.stringify(url.includes("rescored") ? z5Doc : z11Doc), {
        status: 200,
      });
    }
    if (url.includes("/rescore?")) {
      return new Response(
        JSON.stringify({ scan_id: "rescored-1", parent_scan_id: scan.id, kind: "rescore" }),
        { status: 201 },
      );
    }
    return new Response("{}", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

const value = (id: string) =>
  within(screen.getByTestId(`metric-${id}`)).getByTestId("metric-value");

describe("the Overview's Mosca slider", () => {
  it("re-scores the ORIGINAL scan and every band number follows the new document", async () => {
    render(<App />);
    await waitFor(() => expect(value("critical")).toHaveTextContent("2"));
    expect(value("high")).toHaveTextContent("1");
    expect(value("medium")).toHaveTextContent("0");
    expect(value("low")).toHaveTextContent("14");
    expect(screen.getByTestId("horizon-delta")).toHaveTextContent("-19");

    const slider = screen.getByRole("slider");
    slider.focus();
    for (let step = 0; step < 6; step += 1) await userEvent.keyboard("{ArrowLeft}");

    await waitFor(() => expect(value("medium")).toHaveTextContent("14"), {
      timeout: 3000,
    });
    expect(value("critical")).toHaveTextContent("3");
    expect(value("high")).toHaveTextContent("0");
    expect(value("low")).toHaveTextContent("0");
    expect(screen.getByTestId("horizon-delta")).toHaveTextContent("-25");
    expect(within(screen.getByTestId("live-readout")).getByTestId("live-Critical")).toHaveTextContent(
      "3",
    );

    const rescores = fetchMock.mock.calls
      .map(([input]) => String(input))
      .filter((url) => url.includes("/rescore?"));
    // Debounced: six key presses, one request -- against the original scan,
    // never chained off the previous rescore row.
    expect(rescores).toEqual([`/api/scans/${scan.id}/rescore?z_years=5`]);
  });

  it("the stored-row cards (artefacts, drift) do not pretend to move with Z", async () => {
    render(<App />);
    await waitFor(() => expect(value("total")).toHaveTextContent("17"));
    // Drift is read off the stored row and this scan collected one view:
    // the card must say drift cannot be assessed, not that there is none.
    expect(screen.getByTestId("metric-drift")).toHaveAttribute("data-state", "not-computed");
  });
});
