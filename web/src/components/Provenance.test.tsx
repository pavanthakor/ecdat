/**
 * The rendering RULE, not the layout: a fact scored on something nobody
 * checked must never look like a scored fact (ADR-0017 -> ADR-0018).
 *
 * This is the one piece of presentation worth testing, because getting it
 * wrong is invisible in a screenshot review -- a provisional deadline that
 * renders like a verified one reads as confirmed, and the whole point of the
 * verified-fact gate was that a caveat travels with its claim.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import provisionalDoc from "@/test/fixtures/cbom_provisional.json";
import z11Doc from "@/test/fixtures/cbom_z11.json";

import { parseCbom } from "@/api/parse";
import type { Cbom } from "@/api/types";
import { FactList, ProvenanceBadge } from "./Provenance";

const verified = parseCbom(z11Doc as unknown as Cbom).find(
  (a) => a.name === "RSA-2048",
)!;
const provisional = parseCbom(provisionalDoc as unknown as Cbom).find(
  (a) => a.name === "RSA-2048",
)!;

describe("ProvenanceBadge", () => {
  it("renders a verified verdict solid, with no caveat", () => {
    render(<ProvenanceBadge artefact={verified} />);

    const badge = screen.getByTestId("provenance");
    expect(badge).toHaveAttribute("data-provenance", "verified");
    expect(badge.className).not.toContain("border-dashed");
    expect(badge).toHaveTextContent(/verified/i);
  });

  it("renders a provisional verdict dashed, greyed and labelled", () => {
    render(<ProvenanceBadge artefact={provisional} />);

    const badge = screen.getByTestId("provenance");
    expect(badge).toHaveAttribute("data-provenance", "provisional");
    expect(badge.className).toContain("border-dashed");
    expect(badge).toHaveTextContent(/provisional/i);
  });

  it("names the unverified rules, so the caveat is actionable", () => {
    render(<ProvenanceBadge artefact={provisional} />);

    expect(screen.getByTestId("provenance")).toHaveAttribute(
      "title",
      expect.stringContaining("dst-cii-priority-migration"),
    );
  });
});

describe("FactList -- fired rules and their contribution", () => {
  it("presents a verified rule as having contributed its points", () => {
    render(<FactList artefact={verified} />);

    const row = screen.getByTestId("fact-quantum-shor-broken-asymmetric");
    expect(row).toHaveAttribute("data-provenance", "verified");
    expect(row.className).not.toContain("border-dashed");
    // A verified fact states its contribution as a fact.
    expect(within(row).getByTestId("fact-contribution")).toHaveTextContent("quantum");
  });

  it("presents an unverified rule as scoring ZERO, not as scoring", () => {
    // The load-bearing assertion. `dst-cii-priority-migration` fired and is
    // displayed -- demoted, never dropped -- and the console must say it
    // contributed nothing rather than showing it beside the scoring rules.
    render(<FactList artefact={provisional} />);

    const row = screen.getByTestId("fact-dst-cii-priority-migration");
    expect(row).toHaveAttribute("data-provenance", "provisional");
    expect(row.className).toContain("border-dashed");
    expect(within(row).getByTestId("fact-contribution")).toHaveTextContent(
      /scored 0/i,
    );
    expect(row).toHaveTextContent(/provisional/i);
  });

  it("still lists the unverified rule -- demoted, never dropped", () => {
    render(<FactList artefact={provisional} />);

    expect(screen.getByTestId("fact-dst-cii-priority-migration")).toBeInTheDocument();
  });

  it("does not mark a verified rule provisional on a provisional component", () => {
    // One unverified rule must not tar every other rule on the same component.
    render(<FactList artefact={provisional} />);

    expect(
      screen.getByTestId("fact-quantum-shor-broken-asymmetric"),
    ).toHaveAttribute("data-provenance", "verified");
  });

  it("shows the per-category contributions that actually scored", () => {
    render(<FactList artefact={verified} />);

    const categories = screen.getByTestId("category-breakdown");
    expect(categories).toHaveTextContent("quantum");
    expect(categories).toHaveTextContent("40");
    expect(categories).toHaveTextContent("criticality");
  });

  it("shows a demoted category at zero rather than omitting it", () => {
    // "Assessed, contributed nothing" and "never assessed" are different
    // answers (ADR-0016/0017), and the console must not collapse them.
    render(<FactList artefact={provisional} />);

    const categories = screen.getByTestId("category-breakdown");
    expect(within(categories).getByTestId("category-criticality")).toHaveTextContent(
      "0",
    );
  });

  it("flags a deadline that rests only on an unverified rule", () => {
    render(<FactList artefact={provisional} />);

    const deadline = screen.getByTestId("deadline");
    expect(deadline).toHaveAttribute("data-provenance", "provisional");
    expect(deadline).toHaveTextContent(/provisional/i);
  });

  it("does not flag a deadline every one of whose rules is verified", () => {
    render(<FactList artefact={verified} />);

    expect(screen.getByTestId("deadline")).toHaveAttribute(
      "data-provenance",
      "verified",
    );
  });
});
