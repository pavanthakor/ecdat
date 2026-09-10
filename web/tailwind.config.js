/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        // Space Grotesk for the interface and headings; JetBrains Mono for
        // anything a reader compares character by character -- bom-refs,
        // file:line locators, endpoints, versions, diffs. A considered pairing
        // (ADR-0031), kept when the layout was matched to the design
        // (ADR-0032). Both self-hosted via @fontsource; nothing is fetched.
        sans: ['"Space Grotesk"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // The console surface, matched to web/design/: a neutral near-black
        // ground, cards one step up, hairline borders. Flat -- no gradient.
        ground: "#0b0c0f",
        panel: "#111216",
        raised: "#17191e",
        line: "#25282e",
        "line-soft": "#1b1d22",
        ink: "#e6e7ea",
        "ink-dim": "#9ea3ad",
        "ink-faint": "#6b707a",
        // A dark blue-slate SURFACE for status pills and the visibility
        // matrix, as the design has them. A surface tint, never a data mark.
        tint: "#111827",
        "tint-line": "#26324a",
        // Bands. The only saturated colours in the DATA, so a red pixel in a
        // table, chart or card always means the same thing.
        critical: "#ef4444",
        high: "#f59e0b",
        medium: "#eab308",
        low: "#64748b",
        // The Q-orbit mark, and nothing else (ADR-0031). Confined to the logo.
        brand: "#f28c38",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
};
