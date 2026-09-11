/**
 * The Overview, rebuilt on the v2 mockup (ADR-0038), still drives the whole
 * screen through a REAL rescore round trip (ADR-0016 -> ADR-0018 -> ADR-0031).
 *
 * What this pins:
 *
 * * moving Z issues ONE debounced `POST /scans/{id}/rescore` against the
 *   ORIGINAL scan, and every band-derived figure on the Overview follows the
 *   new document -- the live readout, the category bars, the peak gauge and
 *   the ORDER of the priority table. A panel wired to the stored row instead
 *   would freeze at the old horizon, and would look fine;
 * * the mockup's figures ECDAT does not compute (a trend over one scan, drift
 *   over one view) say "not computed", never a number;
 * * colour means severity and nothing else: every element painted in a band
 *   colour names that band in `data-band`, and no band colour is set inline.
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

const live = (band: string) => within(screen.getByTestId("live-readout")).getByTestId(`live-${band}`);
const value = (id: string) => within(screen.getByTestId(`metric-${id}`)).getByTestId("metric-value");
const bar = (category: string, band: string) =>
  within(screen.getByTestId(`category-${category}`))
    .getAllByTitle(new RegExp(`· ${band}:`))
    .find((el) => el.getAttribute("data-band") === band)!;
const rowBands = () => screen.getAllByTestId("priority-row").map((row) => row.getAttribute("data-band"));

async function loaded() {
  render(<App />);
  await waitFor(() => expect(live("Low")).toHaveTextContent("14"));
}

describe("the Overview's Mosca slider", () => {
  it("re-scores the ORIGINAL scan and every band figure follows the new document", async () => {
    await loaded();
    expect(live("Critical")).toHaveTextContent("2");
    expect(live("High")).toHaveTextContent("1");
    expect(live("Medium")).toHaveTextContent("0");
    expect(screen.getByTestId("horizon-delta")).toHaveTextContent("-19");
    expect(screen.getByTestId("peak-score")).toHaveTextContent("98");
    expect(bar("hash", "High")).toHaveAttribute("data-count", "1");
    expect(bar("kex", "Low")).toHaveAttribute("data-count", "4");
    expect(rowBands().slice(0, 3)).toEqual(["Critical", "Critical", "High"]);

    const slider = screen.getByRole("slider");
    slider.focus();
    for (let step = 0; step < 6; step += 1) await userEvent.keyboard("{ArrowLeft}");

    await waitFor(() => expect(live("Medium")).toHaveTextContent("14"), { timeout: 3000 });
    expect(live("Critical")).toHaveTextContent("3");
    expect(live("High")).toHaveTextContent("0");
    expect(live("Low")).toHaveTextContent("0");
    expect(screen.getByTestId("horizon-delta")).toHaveTextContent("-25");
    // The gauge, the bars and the queue ORDER all moved with the document.
    expect(screen.getByTestId("peak-score")).toHaveTextContent("100");
    expect(bar("hash", "Critical")).toHaveAttribute("data-count", "1");
    expect(bar("hash", "High")).toHaveAttribute("data-count", "0");
    expect(bar("kex", "Medium")).toHaveAttribute("data-count", "4");
    expect(rowBands().slice(0, 3)).toEqual(["Critical", "Critical", "Critical"]);

    const rescores = fetchMock.mock.calls
      .map(([input]) => String(input))
      .filter((url) => url.includes("/rescore?"));
    // Debounced: six key presses, one request -- against the original scan,
    // never chained off the previous rescore row.
    expect(rescores).toEqual([`/api/scans/${scan.id}/rescore?z_years=5`]);
  });
});

describe("the Overview says what it did not compute", () => {
  it("the stored-row cards (artefacts, drift) do not pretend to move with Z", async () => {
    await loaded();
    expect(value("total")).toHaveTextContent("17");
    // Drift is read off the stored row and this scan collected one view:
    // the card must say drift cannot be assessed, not that there is none.
    expect(screen.getByTestId("metric-drift")).toHaveAttribute("data-state", "not-computed");
  });

  it("a trend over ONE stored scan is not computed -- no line is drawn", async () => {
    await loaded();
    const trend = screen.getByTestId("risk-trend");
    expect(trend).toHaveAttribute("data-state", "not-computed");
    expect(trend).toHaveTextContent(/not computed/i);
    expect(trend).toHaveTextContent(/a trend needs two/i);
    expect(trend.querySelector("svg")).toBeNull();
  });

  it("the mockup's sample figures and people are nowhere on the page", async () => {
    await loaded();
    const text = document.body.textContent ?? "";
    for (const sample of ["Good morning", "Alex", "54.2", "63/100", "Elevated", "QuantumBank", "↑ 4 pts"]) {
      expect({ sample, found: text.includes(sample) }).toEqual({ sample, found: false });
    }
  });
});

describe("the priority table", () => {
  it("filters by band, and says so when a band is empty at this horizon", async () => {
    await loaded();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Priority band" }), "High");
    expect(rowBands()).toEqual(["High"]);
    expect(screen.getAllByTestId("priority-row")[0]).toHaveTextContent("MD5");

    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Priority band" }), "Medium");
    expect(screen.queryAllByTestId("priority-row")).toHaveLength(0);
    expect(screen.getByTestId("priority-empty")).toHaveTextContent(/no medium findings/i);
  });

  it("a row opens the Inventory drill-down for that artefact", async () => {
    await loaded();
    const first = screen.getAllByTestId("priority-row")[0];
    const ref = first.getAttribute("data-ref")!;
    await userEvent.click(first);
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(ref)).toBeInTheDocument();
    expect(window.location.hash).toBe(`#/inventory?ref=${encodeURIComponent(ref)}`);
  });
});

describe("colour means severity and nothing else (ADR-0031)", () => {
  const BAND_CLASS = /^(?:text|bg|border|fill|stroke|badge|band-bg|band-fg|band-stroke)-(critical|high|medium|low)(?:\/\d+)?$/;
  const BAND_INLINE = /var\(--(?:critical|high|medium|low)\)|#ef4444|#f59e0b|#eab308/i;

  it("every band-coloured element names its band, and no band colour is inline", async () => {
    await loaded();
    const coloured: Element[] = [];
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      const inline = ["style", "fill", "stroke", "color"].map((a) => el.getAttribute(a) ?? "").join(" ");
      expect({ el: el.outerHTML.slice(0, 120), inline: BAND_INLINE.test(inline) }).toEqual({
        el: el.outerHTML.slice(0, 120),
        inline: false,
      });
      const band = Array.from(el.classList)
        .map((token) => BAND_CLASS.exec(token)?.[1])
        .find(Boolean);
      if (!band) continue;
      coloured.push(el);
      expect({ el: el.outerHTML.slice(0, 120), band: el.getAttribute("data-band")?.toLowerCase() }).toEqual({
        el: el.outerHTML.slice(0, 120),
        band,
      });
    }
    // Not vacuous: the readout, the bars, the key, the gauge and the table rows.
    expect(coloured.length).toBeGreaterThan(20);
  });
});
