/**
 * Compare Scans on the v2 mockup (compare.html; ADR-0039): the two scans face
 * to face, four counts, the changed evidence with NEW / CHANGED / RESOLVED --
 * all from the server's diff, and all in ink: none of it is a band.
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import scansDoc from "@/test/fixtures/scans.json";

import type { CompareResponse, ScanSummary } from "@/api/types";
import { CompareScreen } from "@/screens/Compare";
import { colourIsSeverityOnly } from "@/test/v2";

const head = (scansDoc as unknown as ScanSummary[])[0];
const base: ScanSummary = { ...head, id: "base0000-scan-0000-0000-000000000000", created_at: "2026-09-01T06:00:00Z" };

const DIFF: CompareResponse = {
  base: { id: base.id, kind: "scan", created_at: base.created_at, system: base.target.system },
  head: { id: head.id, kind: "scan", created_at: head.created_at, system: head.target.system },
  new: [{ bom_ref: "n1", name: "RSA-4096", band: "High", score: 70, deadline: null }],
  resolved: [{ bom_ref: "r1", name: "SHA-1", band: "Medium", score: 50, deadline: null }],
  changed: [
    {
      bom_ref: "c1",
      name: "DH-2048",
      fields: ["score"],
      before: { band: "High", score: 78, deadline: null, quantum_status: null },
      after: { band: "Critical", score: 82, deadline: null, quantum_status: null },
      evidence_added: [],
      evidence_removed: [],
    },
  ],
  drift_introduced: [
    {
      bom_ref: "d1",
      name: "TLS",
      kind: "cipher-outside-declared-set",
      declared: "AES-GCM",
      observed: "3DES",
      cause: "the endpoint negotiated a cipher the policy does not declare",
    },
  ],
  drift_resolved: [],
  unchanged: 12,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Compare Scans (compare.html)", () => {
  it("two scan cards, four counts and the changed evidence -- from the server's diff", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes("/compare/")
        ? new Response(JSON.stringify(DIFF), { status: 200 })
        : new Response("{}", { status: 404 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<CompareScreen scans={[head, base]} current={head} />);

    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Base scan" }), base.id);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Head scan" }), head.id);

    const counts = await screen.findAllByTestId("compare-count");
    expect(counts.map((c) => within(c).getByText(/^[+−]?\d+$/).textContent)).toEqual(["+1", "−1", "1", "1"]);
    expect(screen.getByTestId("compare-base").querySelector(".compare-scan-id")).toHaveTextContent(base.id.slice(0, 8));

    const rows = screen.getAllByTestId("change-row");
    expect(rows.map((row) => row.getAttribute("data-tag"))).toEqual(["New", "Changed", "New", "Resolved"]);
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/scans/${base.id}/compare/${head.id}`))).toBe(true);

    // NEW / CHANGED / RESOLVED are border and weight, never a band's colour.
    expect(colourIsSeverityOnly()).toBe(0);
  });
});
