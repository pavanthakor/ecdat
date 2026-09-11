/// <reference types="node" />
/**
 * The console fetches nothing from the internet (ADR-0038).
 *
 * The v2 mockups link Google Fonts. An air-gapped estate cannot reach
 * fonts.googleapis.com, and a console that silently falls back to a system
 * face there looks broken in exactly the place it is meant to run. So the
 * shipped entry point, every stylesheet and every source file are scanned for
 * a remote URL: the faces come from @fontsource, bundled at build time.
 *
 * The files are read from disk, not imported: Vitest stubs a `.css` import to
 * an empty string, which would let this pass on nothing.
 *
 * The one `http://` the page may contain is the SVG namespace in the inline
 * favicon, which is an identifier, not a request.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest runs from web/ (npm test, and the config's root). Under jsdom,
// import.meta.url is not a file: URL, so the working directory is the anchor --
// and the first test checks it really is web/.
const WEB = process.cwd();
const read = (path: string) => readFileSync(resolve(WEB, path), "utf8");

const SOURCE = readdirSync(resolve(WEB, "src"), { recursive: true, encoding: "utf8" });
const stylesheets = SOURCE.filter((path) => path.endsWith(".css")).map((path) => `src/${path}`);
const sources = SOURCE.filter((path) => /\.tsx?$/.test(path) && !path.endsWith("offline.test.ts")).map(
  (path) => `src/${path}`,
);

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const REMOTE = /\bhttps?:\/\/[^\s"')]+/g;
const CDN = /googleapis|gstatic|cdnjs|jsdelivr|unpkg|esm\.sh|cdn\.tailwindcss/i;

function remoteUrls(text: string): string[] {
  return (text.match(REMOTE) ?? []).filter((url) => !url.startsWith(SVG_NAMESPACE));
}

describe("the console is offline by construction", () => {
  it("index.html loads nothing remote -- no font link, no script, no favicon URL", () => {
    expect(existsSync(resolve(WEB, "vite.config.ts"))).toBe(true);
    const html = read("index.html");
    expect(html).toContain("<title>");
    expect(remoteUrls(html)).toEqual([]);
    expect(html).not.toMatch(CDN);
    expect(html).not.toMatch(/<link[^>]+rel="(stylesheet|preconnect)"/);
  });

  it("no stylesheet imports or references a remote URL", () => {
    expect(stylesheets).toEqual(expect.arrayContaining(["src/styles/index.css", "src/styles/console-v2.css"]));
    for (const path of stylesheets) {
      const css = read(path);
      expect(css.length).toBeGreaterThan(0);
      expect({ path, urls: remoteUrls(css), cdn: CDN.test(css) }).toEqual({ path, urls: [], cdn: false });
    }
  });

  it("the faces the design names are the self-hosted @fontsource ones", () => {
    const index = read("src/styles/index.css");
    for (const face of ["inter/400", "inter/800", "jetbrains-mono/400"]) {
      expect(index).toContain(`@fontsource/${face}.css`);
    }
    const pkg = JSON.parse(read("package.json")) as { dependencies: Record<string, string> };
    expect(Object.keys(pkg.dependencies)).toEqual(
      expect.arrayContaining(["@fontsource/inter", "@fontsource/jetbrains-mono"]),
    );
  });

  it("no source file points the console at a CDN", () => {
    expect(sources.length).toBeGreaterThan(20);
    for (const path of sources) {
      expect({ path, cdn: CDN.test(read(path)) }).toEqual({ path, cdn: false });
    }
  });
});
