# ADR-0038: The v2 console design — design system, shell, and the Overview

**Status:** Accepted
**Date:** 2026-09-11
**Slice:** v2 design rebuild. This is screen 1 of 10, the Overview; the rest follow screen by screen.
**Depends on:**
- ADR-0031: the honesty rule and the colour lock.
- ADR-0032: the first design match, whose layout this replaces.
- ADR-0016: live rescore.
- ADR-0034: candidate and confidence.
- ADR-0035: keys, not accounts.

## Context

`web/design-v2/ecdat-console-v2/` holds ten static HTML mockups of the console. They are git-ignored and used for reference only. The brief:
- match each mockup faithfully (layout, cards, tables, panels, spacing, colour, type);
- wire every screen to the real API, never to the mockups' sample figures;
- keep the honesty rule and the offline guarantee;
- keep every existing function (the Mosca slider, filters, the drill-down drawer, drift detail, the ADR-0035 key);
- work in this order: Overview, Drift, Fixes, Inventory, then the rest. Commit after each screen, and stop after the Overview for review.

## Decision

### 1. One design system, scoped

The mockups' shared stylesheet ("tokens + base components") is ported to `src/styles/console-v2.css`, scoped under `.v2`.
- The tokens are identical: ground `#08090B`, surfaces `#0E1114`, `#121619` and `#171C21`, hairlines `#242B31` and `#181E23`, three text tiers, and the four band colours.
- The components are the mockups' own: the sidebar, nav items, topline, crumb, chips, search box, status and profile chips, stat cards, panels, the queue table with its tick meter, the bar chart, the gauge, and the empty states.

The Tailwind palette moves to the same values. A screen that is not yet rebuilt therefore sits in the v2 frame with v2 colours, and keeps its current layout until its turn comes.

### 2. Fonts are self-hosted: Inter and JetBrains Mono

The mockups load Inter from `fonts.googleapis.com`. That link is **not** copied: an air-gapped estate cannot reach it.
- Inter (400–800) and JetBrains Mono (400–600) come from `@fontsource`, and Vite bundles them into `dist/assets`.
- Space Grotesk, the ADR-0032 face, is removed as a dependency.
- `src/test/offline.test.ts` reads `index.html`, every stylesheet and every source file from disk and fails on any remote URL or CDN host. It reads from disk because Vitest stubs a `.css` import to an empty string.
- The one `http://` allowed is the SVG namespace inside the inline favicon.

### 3. The shell follows the mockup, and nothing it carried is lost

The mockup draws no top bar. The breadcrumb, context chips, search, status and profile sit in each page's topline, beside the title. So:

| ADR-0032 shell element | v2 home |
|---|---|
| Q-orbit logo and collapse control | the ECDAT brand block (white "E" mark, "CRYPTOGRAPHIC SECURITY CONSOLE"). The collapse control is gone; the mockup has none. |
| Grouped nav, Settings pinned | v2 nav items: the real routes only, grouped Analyze / Plan / Report, with Settings after them |
| Connection box | sidebar foot: a dot and what is actually known ("API connected", "Connecting", "Request failed") |
| Cosmetic operator block | the analyst row, showing the key's name and role (ADR-0035) |
| TopBar: SYSTEM / SCAN crumb with `<select id="scan-select">` | topline crumb "ECDAT / {system} / {scan select}" |
| TopBar: Sector / Exposure / Data class chips | topline chips. An unrecorded value is a **dashed** chip that says "not recorded". |
| TopBar: search | topline search box, still `role="search"`. The mockup's ⌘K hint is made true: Ctrl/⌘+K focuses the box. |
| TopBar: status pill (`data-testid="status"`) | topline status chip |
| TopBar: user menu | topline profile chip (same menu, same Sign out) |
| StatusStrip: engine versions and mismatch; scan id and age | sidebar foot, the mockup's engine-version line |

`ScreenHeader` reads the frame from `ConsoleContext`. A screen rendered on its own, as the screen tests do, gets its title and actions and no frame, so those tests need no provider.

`TopBar.tsx`, `StatusStrip.tsx` and `Logo.tsx` are deleted. The rest of the rebrand:
- the title is "ECDAT — Cryptographic Security Console";
- the favicon is an inline "E" mark;
- download filenames are `ecdat-*`;
- the sign-in page says "Sign in to ECDAT".

### 4. The Overview, mapped panel by panel

| Mockup | What renders | Source |
|---|---|---|
| Topline: crumb, "Good morning, Alex", chips, search, bell, status, profile, **Run scan** | The frame above, H1 "Cryptographic Security Overview", **Run scan**, and Export snapshot. Run scan opens the real NewScanDialog and is disabled for a viewer key with the NEEDS_ADMIN reason. | ADR-0035 job API |
| Stat row: Artefacts, Quantum vulnerable, Drift findings, Coverage, Crypto agility | The same five cards, same order, same icons | the live document; drift from the stored row, or "Not computed" when fewer than two views were collected |
| Risk trend: average score over 8 scans | **Critical + High per stored scan** of this target, last 8 | `GET /scans` rows' `band_counts` |
| Findings by category: Sig / KEx / Sym / Hash / TLS | Sig / KEx / Sym / Hash / **Proto**, plus Other when non-zero. Four band bars per group. | CycloneDX `primitive` / `assetType`, live document |
| Overall risk gauge "63/100 Elevated" | **Peak risk**: the highest artefact score, with the arc in that artefact's band colour, linking to it | live document |
| Priority findings table, with an "All bands" select | Same table: artefact, location, score tick-meter, risk, band badge. The select is a real band filter. A row opens the Inventory drawer. | live document, `priorityQueue` |
| Crypto agility: 72%, "↑ 4 pts", line | Share %, a neutral "N of M assessed" pill, and a configurable / hard-coded / not-assessed split bar | `agility()` |
| *(not in the mockup)* | The **CRQC horizon** (the Mosca slider, live readout, x / y / Δ terms), in the ops column above agility | rescore, ADR-0016 |

### 5. Where the mockup would have us lie, it doesn't get its way

- **No sample figures.** Every number is computed from the API, and a test fails if the mockup's samples appear ("54.2", "63/100", "Elevated", "↑ 4 pts", the analyst's name).
- **No deltas.** The mockup's pills ("+6", "+2", "↑ 4 pts") are deltas against a baseline, and nothing computes one (PUNCHLIST). The pill states the figure's basis, and the full basis shows on hover.
- **A trend needs two points.** With one stored scan of the target, the panel says "Not computed — a trend needs two", and no line is drawn.
- **No weighted estate score exists**, so the gauge is the peak, and says so.
- **"TLS" becomes "Proto".** The category is the CycloneDX protocol asset type, which is not only TLS.
- **No bell and no "Week" select.** A notification that never fires, or a granularity control with one option, is a control that lies (ADR-0032).
- **No greeting.** ECDAT knows a key's name, not a person (ADR-0035).

### 6. Colour means severity, and only severity

The mockup uses colour for more than severity:
- green for "System Operational" and for improving deltas;
- red for the drift nav badge;
- amber for the trend's current point.

None of that is ported:
- status dots, the drift badge and every pill are neutral ink;
- the trend is white on grey;
- "At risk" and a negative horizon delta are shown by **weight and border**, not red.

The one non-band red kept is a failed request, as before: it is an error, not a finding.

On the Overview, every band-coloured mark gets its colour **from a class** (`band-bg-*`, `band-fg-*`, `band-stroke-*` or `badge-*`) and carries `data-band`. `overview.test.tsx` walks the rendered page and fails if a band-coloured element does not name its band, or if a band colour is set inline. The walk finds more than 20 such elements, so it cannot pass vacuously.

Certainty and provenance stay border and weight (ADR-0034):
- a **candidate** is a dashed mark and a lighter name;
- an **inferred** finding is a solid mark;
- a **provisional** verdict is a dashed mark.

### 7. Rollout

The screens are rebuilt one at a time, and each is committed on its own:
- Overview is done here.
- Next come Cryptographic Drift, Verified Fixes and Inventory, **after review of this one**.
- Then Scans, Roadmap, Agility, Coverage, Reports and Compare.

Until its turn, a screen keeps its ADR-0032 layout inside the v2 frame and palette.

## Consequences

- `web/dist` bundles the Inter and JetBrains Mono `woff`/`woff2` files. A build has no CDN reference and no Space Grotesk.
- `MetricCard` is the v2 stat card; its `data-testid`s and the not-computed rendering are unchanged. `NotComputed` uses the v2 classes.
- The old Overview's risk-distribution histogram and coverage pulse are gone, because the v2 Overview has neither. The same facts remain on the Coverage and Inventory screens.
- **Still owed:** a visual check of the rendered console against the mockups. The build machine has no headless browser, so the human's screenshot is the first look.
