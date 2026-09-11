/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        // The v2 design's pairing (ADR-0038): Inter for the interface,
        // JetBrains Mono for anything a reader compares character by
        // character -- bom-refs, file:line locators, endpoints, versions,
        // diffs. Both self-hosted via @fontsource; nothing is fetched.
        sans: ['"Inter"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // The v2 surface (ADR-0038), the same values src/styles/console-v2.css
        // declares as variables: a near-black ground, two surface steps,
        // hairline borders and three text tiers. Kept in step so a screen not
        // yet rebuilt on the v2 classes still sits in the v2 frame.
        ground: "#08090b",
        panel: "#0e1114",
        "surface-2": "#121619",
        raised: "#171c21",
        line: "#242b31",
        "line-soft": "#181e23",
        ink: "#f5f6f8",
        "ink-dim": "#9ba7b2",
        "ink-faint": "#5f6b76",
        "ink-mono": "#b4bdc6",
        // A dark blue-slate SURFACE for status pills and the visibility
        // matrix. A surface tint, never a data mark.
        tint: "#111827",
        "tint-line": "#26324a",
        // Bands. The only saturated colours in the DATA, so a red pixel in a
        // table, chart or card always means the same thing (ADR-0031).
        critical: "#ef4444",
        high: "#f59e0b",
        medium: "#eab308",
        low: "#5f6b76",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
};
