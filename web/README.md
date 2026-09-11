# ECDAT console (`web/`)

**ECDAT — Cryptographic Security Console**: ECDAT's dashboard, a dark SOC-style
console over the CBOM the scanners produce. React + Vite + TypeScript, Tailwind,
Radix primitives, lucide-react. [ADR-0018](../docs/adr/0018-dashboard.md) is the
first slice; [ADR-0031](../docs/adr/0031-qorbit-dashboard.md) is the full
console and its honesty rule; [ADR-0032](../docs/adr/0032-qorbit-design-match.md)
matched its layout to the design screenshots in `web/design/`;
[ADR-0038](../docs/adr/0038-v2-console-design.md) rebuilds it on the v2 mockups
in `web/design-v2/` (git-ignored, reference only — nothing there is bundled),
screen by screen. The v2 design system is `src/styles/console-v2.css`.

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

## One database, or the dashboard is empty

ECDAT writes to `./ecdat.db` unless `ECDAT_DB` says otherwise. **The scanner and
the server must agree**, and nothing reconciles them for you — two processes
using two databases is a legitimate thing to want, so the tool makes the path
visible rather than guessing.

```bash
# Pick one database and export it in EVERY shell you use.
export ECDAT_DB="$PWD/ecdat.db"

ecdat scan-system testdata/quantumbank/system.yaml   # prints  db=/abs/path
ecdat scans                                          # lists what is in it
make serve                                           # logs    "database": "/abs/path"
```

If the console is empty, run `ecdat scans`. It prints the absolute path it
opened and the rows it found — comparing that with the `db=` the scan printed
and the `database` in the server's startup log identifies the mismatch in one
command. `make kpi` deliberately uses its own `.ecdat-kpi.db`, so its scans will
never appear in the console.

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

* **Fonts are vendored.** Inter (the interface) and JetBrains Mono
  (bom-refs, locators, endpoints, diffs) come from `@fontsource`, which ships
  the `woff2` files inside `node_modules`; Vite copies them into `dist/assets`.
  Nothing is fetched from Google Fonts at runtime — the v2 mockups link it, and
  that link was deliberately not copied (ADR-0038). `src/test/offline.test.ts`
  fails on any remote URL in `index.html`, a stylesheet or a source file.
* **No external scripts or stylesheets.** `dist/index.html` references two
  hashed local assets, and the favicon is an inline `data:` URI.
* **Same-origin API only.** `src/api/client.ts` has no configurable base URL —
  the console can only talk to the server that served it.
* **Hash routes.** Screens live at `#/scans`, `#/drift`, … because FastAPI
  mounts the API at `/` as well as `/api`: a console path of `/scans` would be
  answered by the API's JSON on reload.

This matters because ECDAT is meant for air-gapped estates. A dashboard that
phones out for a stylesheet is broken in the one environment the tool exists
for.

## The honesty rule

Every number on screen is a **stored value**, a **count** of stored facts, or a
**ratio** of two counts with both shown. Anything else renders **"Not
computed"** with its reason — never a zero, never a placeholder bar.
`state/metrics.ts` returns `Measured<T>`; `components/Honest.tsx` is the only
thing that renders one. ADR-0031 §2 lists, screen by screen, what is real today
and what says it is not computed.

## Screens

| Group | Route | Screen |
|---|---|---|
| Analyze | `#/overview` | metric cards, CRQC-horizon slider (live rescore), risk distribution, histogram, priority queue, coverage pulse |
| | `#/scans` | scan history off the denormalised rows; **New scan** |
| | `#/inventory` | the table, filters and drill-down (`?ref=<bom-ref>` opens a drawer, `?q=` filters) |
| | `#/risk-analysis` | honest placeholder — not computed by the backend |
| | `#/drift` | Declared → Shipped → Observed per drift finding |
| Plan | `#/roadmap` | deadline Gantt; undated artefacts listed, not placed |
| | `#/fixes` | the verified-fix queue from `GET /scans/{id}/fixes` |
| | `#/agility` | configurable share (real); key store and protocol (not computed) |
| Report | `#/coverage` | scanner cards and the visibility matrix |
| | `#/reports` | the three PDFs and the offline export formats |
| | `#/compare` | `GET /scans/{a}/compare/{b}`, joined on bom-ref |
| | `#/settings` | read-only facts about this console |

The user menu names the API key the console holds and its role, and signs out
([ADR-0035](../docs/adr/0035-api-hardening.md)).

## Signing in

Every API request carries a key. Issue one on the server, then paste it into
the console's sign-in:

```bash
ecdat api-key create --name ops --role admin   # prints the key ONCE
```

The console asks for a key only when the server refuses it, and it checks a
key with `GET /auth/whoami` before storing it (in localStorage, until you sign
out). A **viewer** key reads everything except verified patches. An **admin**
key also runs scans and fix passes. Scans and fix passes are jobs: the console
polls `GET /jobs/{id}` until the scan is stored. PDFs and the CBOM are fetched
with the key rather than linked, because a link cannot send a header.

## Layout

```
src/
  api/        types.ts    the REAL wire shapes (written against captured responses)
              parse.ts    CBOM -> the rows the console renders
              client.ts   typed fetch, same-origin, no base URL
  lib/        router.ts   hash routes, the nav table
              format.ts   band colours, dates, short refs, two-digit counts
              download.ts local file saves (CSV / JSON exports)
  state/      inventory.ts     filters, sort, and the Mosca rescore round trip
              metrics.ts       every derived number, as Measured<T>
              presentation.ts  live band counts, empty states, footer line
              remote.ts        per-screen loaders; errors stay local
  components/ shell/      Logo (the Q-orbit mark), Sidebar, TopBar, StatusStrip,
                          UserMenu, status.ts
              Honest.tsx  MetricCard / NotComputed / EmptyPanel
              Panel.tsx   ScreenHeader, Panel, Button, Tag
              InventoryTable, ArtefactDrawer, NewScanDialog, Provenance, ui/
  screens/    one file per route
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
| `cbom_candidate.json` | `testdata/js_fixtures` scanned after ADR-0034: one 0.5 candidate, 31 confirmed findings, and five at 0.6 whose captured parameter did not resolve |
| `cbom_binary.json` | `testdata/binary_fixtures`, binary scanner only (`--kind directory --scanner binary`): 22 components, every one below 1.0 by design, none a candidate |
| `scans.json` | a `GET /scans` row, with its denormalised summary |

Regenerate them by scanning `testdata/quantumbank`, and copying the stored
documents. The two exceptions are `cbom_candidate.json`, which comes from
`testdata/js_fixtures`, and `cbom_binary.json`, which comes from
`testdata/binary_fixtures`. Hand-written fixtures would test the parser against
the shape one imagined, which is always the shape that works.

## What is tested

Data logic and interaction — 209 tests. Each of these failures is invisible in
a screenshot review: filtering that silently drops rows, a rescore that leaves
a stale table, a provisional fact rendered as a verified one, a candidate
rendered as a confirmed finding, and a metric nobody computed rendered as a
number. Column order is not.

* `state/certainty.test.ts` covers candidate / inferred / confirmed /
  unrecorded, the reason in words, and the candidates / confirmed filter, all
  against real documents.
* `components/certainty.test.tsx` covers the candidate tag, which appears on
  flagged candidates only and never on a 0.6 or binary finding, and is never a
  band colour. It also covers the drawer's confidence for every finding and
  the filter end to end.

* `api/parse.test.ts` — the real wire shapes parse into typed models.
* `state/inventory.test.ts` — filters, sorting, and the debounced rescore round
  trip against real before/after documents.
* `state/metrics.test.ts` — every derived number against real documents, and
  every place it refuses to invent one.
* `state/presentation.test.ts` — the live band readout, the three empty states,
  and the auditable footer line.
* `components/Provenance.test.tsx` — the verified/provisional rendering RULE.
* `components/console.test.tsx` — empty states, the severity bar on every row,
  the band select, and the live readout driven through the real slider.
* `lib/format.test.ts` — the table date format, "last scanned" age, two-digit
  counts.
* `components/honesty.test.tsx` — **the honesty rule at the DOM level**: a
  not-computed metric renders no digit; a computed zero renders "0"; agility,
  drift, roadmap, fixes, compare and coverage each render their empty state
  faithfully.
* `screens/overview.test.tsx` — the slider re-scores the ORIGINAL scan once and
  every Overview card follows the new document.
* `lib/routing.test.tsx` — every nav entry, deep links, unknown routes, finding
  links into the drawer, and the top-bar search.
* `api/client.test.ts` — the key on every request, a 401 that raises the
  sign-in and a 403 that does not, pages, and job polling (done, failed,
  aborted).
* `state/auth.test.tsx` — the sign-in gate through the real `<App />`, the user
  menu, sign-out, and what a viewer key is and is not offered.
* `components/NewScanDialog.test.tsx` — a scan as a job: queued, running, the
  scan id handed on only when done, the server's reason when it fails.
* `screens/scans.test.tsx` — Scan History pages from the server.
