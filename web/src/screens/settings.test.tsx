/// <reference types="node" />
/**
 * The Settings screen states how the console was built. Its "Fonts" row must
 * name the faces the console actually ships -- the ones src/styles/index.css
 * imports from @fontsource -- and no face it does not (ADR-0038 retired Space
 * Grotesk for Inter).
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SettingsScreen } from "@/screens/Settings";

/** @fontsource package -> the face's name. */
const FACE: Record<string, string> = {
  inter: "Inter",
  "jetbrains-mono": "JetBrains Mono",
  "space-grotesk": "Space Grotesk",
};

describe("Settings: the build facts", () => {
  it("the Fonts row names exactly the faces index.css imports", () => {
    const css = readFileSync(resolve(process.cwd(), "src/styles/index.css"), "utf8");
    const shipped = [...new Set([...css.matchAll(/@fontsource\/([a-z-]+)\//g)].map((m) => m[1]))];
    expect(shipped.length).toBeGreaterThan(0);

    render(<SettingsScreen scan={null} artefacts={[]} />);
    const row = screen.getByText(/self-hosted; no CDN/);

    for (const pkg of shipped) expect(row).toHaveTextContent(FACE[pkg] ?? pkg);
    for (const [pkg, name] of Object.entries(FACE)) {
      if (!shipped.includes(pkg)) expect(row.textContent).not.toContain(name);
    }
  });
});
