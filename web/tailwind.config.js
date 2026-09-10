/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        // Inter for the interface; JetBrains Mono for anything a reader might
        // need to compare character by character -- bom-refs, file:line
        // locators, versions, diffs. Both self-hosted via @fontsource.
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
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
        // NO accent colour. Interaction affordances use the slate ramp, so
        // the four band colours below are the only saturated pixels in the
        // application and a coloured pixel always means severity.
        // Bands. The ONLY saturated colours in the console, so a red pixel
        // always means the same thing.
        critical: "#f43f5e",
        high: "#f59e0b",
        medium: "#eab308",
        low: "#64748b",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
};
