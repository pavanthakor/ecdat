/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        // Space Grotesk for the interface and headings; JetBrains Mono for
        // anything a reader compares character by character -- bom-refs,
        // file:line locators, endpoints, versions, diffs. A considered pairing:
        // both are geometric-grotesque in construction, so the switch between
        // prose and an address reads as a change of register, not of style.
        // Both self-hosted via @fontsource; nothing is fetched at runtime.
        sans: ['"Space Grotesk"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // The console surface. Three steps of slate, not a gradient: a flat
        // dark ground is what makes a semantic colour mean something.
        ground: "#020617", // slate-950
        panel: "#0b1220",
        raised: "#111a2e",
        line: "#1e293b", // slate-800
        "line-soft": "#172033",
        ink: "#e2e8f0", // slate-200
        "ink-dim": "#94a3b8", // slate-400
        "ink-faint": "#64748b", // slate-500
        // Bands. The only saturated colours in the DATA, so a red pixel in a
        // table, chart or card always means the same thing.
        critical: "#ef4444",
        high: "#f59e0b",
        medium: "#eab308",
        low: "#64748b",
        // The Q-orbit mark, and nothing else (ADR-0031). Confined to the
        // logo in the chrome, never beside a value, so it cannot be read as a
        // High band.
        brand: "#fbbf24",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
};
