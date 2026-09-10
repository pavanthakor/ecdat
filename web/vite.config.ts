import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Everything is bundled locally. No CDN, no runtime fetch of a font or a
// script: ECDAT's offline guarantee covers the console as well as the scan
// path, and a dashboard that phones out for a stylesheet breaks it in the one
// environment (an air-gapped estate) the tool is meant for.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  build: {
    outDir: "dist",
    // Fonts are woff2 from @fontsource; keep them as files rather than base64
    // so the browser can cache them per-face.
    assetsInlineLimit: 4096,
    sourcemap: false,
  },
  server: {
    port: 5173,
    // Dev only. The built app talks to the same origin FastAPI serves it from,
    // so nothing here ships.
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: true } },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
