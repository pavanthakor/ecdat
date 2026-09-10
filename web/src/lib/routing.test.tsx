/**
 * Navigation (ADR-0031): hash routes, because the API owns `/scans`.
 *
 * FastAPI mounts the API at the root as well as under `/api`, so a console
 * path of `/scans` would be answered by the API's JSON on reload. Hash routes
 * never reach the server, work offline, and need no catch-all changes.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import App from "@/App";
import { hrefFor, parseHash, ROUTES } from "./router";

beforeEach(() => {
  window.location.hash = "";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/scans")) {
        return new Response(JSON.stringify(scansDoc), { status: 200 });
      }
      if (url.endsWith("/cbom")) return new Response(JSON.stringify(z11Doc), { status: 200 });
      return new Response("{}", { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

const TITLES: Record<string, string> = {
  overview: "Overview",
  scans: "Scans",
  inventory: "Inventory",
  risk: "Risk Analysis",
  drift: "Cryptographic Drift",
  roadmap: "Migration Roadmap",
  fixes: "Verified Fixes",
  agility: "Crypto Agility",
  coverage: "Coverage",
  reports: "Reports",
  compare: "Compare Scans",
  settings: "Settings",
};

describe("the route table", () => {
  it("has every screen in the brief, grouped ANALYZE / PLAN / REPORT", () => {
    expect(ROUTES.map((r) => r.id)).toEqual(Object.keys(TITLES));
    const groups = (group: string) =>
      ROUTES.filter((r) => r.group === group).map((r) => r.title);
    expect(groups("analyze")).toEqual([
      "Overview",
      "Scans",
      "Inventory",
      "Risk Analysis",
      "Cryptographic Drift",
    ]);
    expect(groups("plan")).toEqual(["Migration Roadmap", "Verified Fixes", "Crypto Agility"]);
    expect(groups("report")).toEqual(["Coverage", "Reports", "Compare Scans"]);
  });

  it("parses a hash into a route and its params", () => {
    expect(parseHash("")).toMatchObject({ route: "overview" });
    expect(parseHash("#/drift")).toMatchObject({ route: "drift" });
    const parsed = parseHash("#/inventory?ref=abc&q=MD5");
    expect(parsed.route).toBe("inventory");
    expect(parsed.params.get("ref")).toBe("abc");
    expect(parsed.params.get("q")).toBe("MD5");
    expect(parseHash("#/nope").route).toBeNull();
    expect(hrefFor("inventory", { ref: "abc" })).toBe("#/inventory?ref=abc");
  });
});

describe("navigating the console", () => {
  it("every nav entry renders its screen and marks itself current", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "Overview" });
    const nav = screen.getByRole("navigation", { name: /primary/i });

    for (const [id, title] of Object.entries(TITLES)) {
      await user.click(within(nav).getByRole("link", { name: title }));
      await screen.findByRole("heading", { level: 1, name: title });
      expect(window.location.hash).toBe(`#/${ROUTES.find((r) => r.id === id)!.path}`);
      expect(within(nav).getByRole("link", { name: title })).toHaveAttribute(
        "aria-current",
        "page",
      );
    }
  });

  it("a deep link opens its screen directly", async () => {
    window.location.hash = "#/coverage";
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: "Coverage" })).toBeInTheDocument();
  });

  it("an unknown route says so and offers the way back — it does not guess", async () => {
    window.location.hash = "#/nope";
    render(<App />);
    const missing = await screen.findByTestId("route-not-found");
    expect(missing).toHaveTextContent("#/nope");
    expect(within(missing).getByRole("link", { name: /overview/i })).toHaveAttribute(
      "href",
      "#/overview",
    );
  });

  it("a finding link opens the Inventory drill-down for that artefact", async () => {
    const rsa = (z11Doc as { components: { "bom-ref": string; name: string }[] }).components.find(
      (c) => c.name === "RSA-2048",
    )!;
    window.location.hash = hrefFor("inventory", { ref: rsa["bom-ref"] });
    render(<App />);
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(rsa["bom-ref"])).toBeInTheDocument();
  });

  it("the top-bar search lands on a filtered Inventory", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "Overview" });
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent(/complete/i));

    await user.type(screen.getByRole("searchbox", { name: /search artefacts/i }), "MD5{Enter}");

    await screen.findByRole("heading", { level: 1, name: "Inventory" });
    expect(window.location.hash).toBe("#/inventory?q=MD5");
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("MD5");
  });
});
