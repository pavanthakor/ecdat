# ECDAT console (`web/`)

The dashboard: a dark SOC-style console over the CBOM the scanners produce.
React + Vite + TypeScript, Tailwind, Radix primitives, lucide-react.

## Build it before the demo

**The demo machine runs no Node.** FastAPI serves `web/dist/` as static files,
so the only step that needs npm happens ahead of time:

```bash
make web          # npm install + vite build -> web/dist/
make serve        # uvicorn on :8000, serving the API *and* the built console
```

Then open <http://127.0.0.1:8000/>. There is no `npm run dev` on stage, no
watcher, and nothing to fall over mid-presentation.

`web/dist/` is **git-ignored**, so a fresh clone must run `make web` once. If
you would rather the demo machine not need npm at all, build on a laptop and
copy `web/dist/` across — the API serves whatever is in that directory.

## Develop

```bash
make web-dev      # vite on :5173, proxying /api -> 127.0.0.1:8000
make web-test     # vitest, the data-logic suite
```

Run `make serve` in another terminal so the proxy has something to talk to.
The client always fetches relative `/api/...` paths, so the same code works
against the dev proxy and against the built bundle with no configuration.

## Offline by construction

No CDN, anywhere:

* **Fonts are vendored.** Inter and JetBrains Mono come from `@fontsource`,
  which ships the `woff2` files inside `node_modules`; Vite copies them into
  `dist/assets`. Nothing is fetched from Google Fonts at runtime.
* **No external scripts or stylesheets.** `dist/index.html` references exactly
  two hashed local assets.
* **Same-origin API only.** `src/api/client.ts` has no configurable base URL —
  the console can only talk to the server that served it.

This matters because ECDAT is meant for air-gapped estates. A dashboard that
phones out for a stylesheet is broken in the one environment the tool exists
for.

## Layout

```
src/
  api/       types.ts    the REAL wire shapes (written against captured responses)
             parse.ts    CBOM -> the rows the console renders
             client.ts   typed fetch, same-origin, no base URL
  state/     inventory.ts  filters, sort, and the Mosca rescore round trip
  components/  SummaryStrip, InventoryTable, ArtefactDrawer, Provenance, ui/
  test/fixtures/  real documents from real scans — see below
```

### The fixtures are real

`src/test/fixtures/*.json` are captured from actual runs, not hand-written:

| file | what it is |
|---|---|
| `cbom_z11.json` | a QuantumBank scan at the default 11-year horizon |
| `cbom_z5.json` | the same estate after a REAL `POST /scans/{id}/rescore?z_years=5` |
| `cbom_z20.json` | and at 20 years |
| `cbom_drift.json` | all three views merged, so drift is present |
| `cbom_provisional.json` | scored with the India DST pack demoted (ADR-0017) |
| `scans.json` | a `GET /scans` row, with its denormalised summary |

Regenerate them by scanning `testdata/quantumbank` and copying the stored
documents. Hand-written fixtures would test the parser against the shape one
imagined, which is always the shape that works.

## What is tested

Data logic and interaction only — 68 tests. Filtering that silently drops rows, a rescore that
leaves a stale table, and a provisional fact rendered as a verified one are all
invisible in a screenshot review. Column order is not.

* `api/parse.test.ts` — the real wire shapes parse into typed models.
* `state/inventory.test.ts` — band/view/drift filters, sorting, and the debounced
  rescore round trip against real before/after documents.
* `components/Provenance.test.tsx` — the verified/provisional rendering RULE.
* `state/presentation.test.ts` — the live band readout, the three empty states,
  and the auditable footer line.
* `components/console.test.tsx` — those two at the DOM level, plus the severity
  row accent: the live readout is driven through the real slider and must
  follow the rescored document.
