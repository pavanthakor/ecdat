# ADR-0032: The Q-orbit console, matched to its design — and its dead code removed

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** design match + dead-code removal (fixup for ADR-0031)
**Depends on:** ADR-0031 (the console, its honesty rule and its locks), ADR-0018

## Context

ADR-0031 built every screen from a WRITTEN description, because the design
images had not reached the build machine. They have now: twelve screenshots in
`web/design/`. This slice makes the console's structure match them, and removes
frontend code that nothing uses.

| file (`web/design/`) | screen |
|---|---|
| `…19.41.16.jpeg`, `…19.41.17.jpeg` | Overview (top, scrolled) |
| `…19.41.17 (1).jpeg` | Scans |
| `…(2)` | Inventory |
| `…(3)` | Risk Analysis |
| `…(4)` | Cryptographic Drift |
| `…(5)` | Migration Roadmap |
| `…(6)` | Verified Fixes |
| `…(7)` | Crypto Agility |
| `…(8)` | Coverage |
| `…(9)` | Reports |
| `…(10)` | Compare Scans |

There is no Settings screenshot. Settings uses the same card language as the
other screens.

## Decision

### 1. The design governs structure; ADR-0031's locks govern colour, type and honesty

The images were followed for layout, spacing, card grids, table columns and
panel arrangement. The locked items were kept:

- the Q-orbit mark
- Space Grotesk and JetBrains Mono, self-hosted
- semantic colour only
- verified vs provisional carried by the border
- offline, built to static
- the honesty rule

Where the mockup shows a populated panel whose value the backend does not
compute, the LAYOUT is matched and the panel keeps its not-computed state.

### 2. Per-screen deltas applied

| Screen | The design showed | Changed to |
|---|---|---|
| **Shell** | logo + collapse at the top of the sidebar; a status box; grouped nav with a bordered active item and chevron; Settings and the operator pinned at the foot; top bar with a text breadcrumb, bordered chips, large search, a rounded status pill and a user box; a status strip; rounded cards on a neutral near-black ground | all of it. The SCAN crumb is a real `<select>` styled as text. The status box reports the API connection. The strip carries engine versions and the provisional count, replacing ADR-0018's footer. |
| **Page header** | `Q-ORBIT / ANALYSIS WORKSPACE` eyebrow, large title, subtitle, short rule, actions on the right | shared `ScreenHeader`. Titles follow the design ("Scan History", "Cryptographic Inventory", "Scanner Coverage"); nav labels are unchanged. |
| **Overview** | 5+4 rounded metric cards with white, zero-padded numbers; risk distribution (segmented bar, legend with counts, histogram with 0/25/50/75/100 ticks) beside the CRQC horizon (a year, an affected count, AT RISK, year-ticked slider, four band columns, shelf-life / migration / delta); two-line priority rows; coverage pulse with a big % | all of it. The horizon is shown as a calendar year labelled *assumed* (this year + z); the slider still sends z to `/rescore`. "Affected findings" is the real count where x + y > z. |
| **Scans** | the table inside an "execution log" card, a LATEST pill, two-line scan cell, `18 Nov 2024 · 09:12` dates, `View ›` | all of it. "Started" still says *not recorded*. The derived-rows toggle and a refresh icon sit in the card header, because every slider move stores a rescore row. |
| **Inventory** | Filters and Export; a full-width search, band and view selects, a Drift-only toggle with its count; a count line with a VERIFIED/PROVISIONAL legend; a separate BOM REF column; outlined view and band badges; a DRIFT badge; a severity bar on every row | all of it. Filter logic is unchanged (`inventory.ts`); band and view are single-choice selects. Provenance is a filled dot or a dashed ring beside the name, plus the word "provisional" in the sub-line. |
| **Risk Analysis** | a card with a pill and a centred lock empty-state with "Open inventory →" | all of it. The pill reads *Prototype · not computed*. |
| **Drift** | per finding: a relationship card with three view boxes (icon, source type, value, locator, provenance) and DIVERGES/OBSERVED captions, a DRIFT DETECTED callout with tags, confidence and next check; three per-view summary cards | all of it, one card per finding (none hidden). The locator is the sighting the drift cites for that view. The per-view cards show real counts and collected / not-collected. |
| **Roadmap** | Export roadmap; year columns with the current one highlighted; two-line labels (`name usage` / `current → target`); the bar with its date inside; band and HYBRID on the right; deadline-cluster cards | all of it. The overdue column stays (the design's data had none). Export writes a CSV of the dated rows. |
| **Verified Fixes** | a remediation-queue card; per fix: name, FIPS and size tags, a `current → target` line, rounded diff, Copy / View Finding / Re-scan | all of it. The target is the template name: the fix result carries no structured target. |
| **Agility** | a large thick gauge; four breakdown rows (label, %, full-width bar, sub-line); "where to improve next" | all of it, for what is real. Key-store and protocol rows say *not computed* and draw no bar. Methodology opens an explanation of what is and is not computed. |
| **Coverage** | "Scanner Coverage": large cards on three columns (status icon, mono status, sub-line, provenance badge); a three-cell tinted visibility matrix with big percentages | all of it. Status is SELECTED / NOT RUN / UNKNOWN, never COMPLETE (ADR-0031 §4). |
| **Reports** | three cards (icon, format tag, title, sub-line, View + Generate); four format tiles | all of it. The format tag is PDF for all three. HTML is a dashed *not available* tile. |
| **Compare** | A-vs-B selectors in the header; four count cards; one "changed evidence" list with NEW / CHANGED / RESOLVED tags | all of it, fed by the ADR-0031 endpoint. Drift-resolved and unchanged counts sit in captions. Export diff saves the response as JSON. |

### 3. What the design shows that was deliberately not copied

- **Orange as an interaction accent.** The design uses it for the active nav
  item, primary buttons, the title underline, the slider thumb, the gauge arc
  and selected cards. The semantic-colour lock keeps orange in the logo, so
  those elements have the design's shape in slate. **Owner's decision:**
  allowing a chrome-only accent is a change to one token plus about six class
  lists, never inside data regions. It is not made here, because it would
  change a locked rule.
- **Red and amber on non-band things.** This covers diverging drift values,
  compare counts, PARTIAL status and the "current" word on fixes. Colour here
  means a band.
- **The mockup's sample data.** None of these are backed by anything the
  backend computes:
  - "target 80%" and "+4 pts since baseline"
  - per-component agility percentages
  - key-store 81% and protocol 64%
  - COMPLETE scanner cards with work counts
  - ML-DSA-65 parameter sets
  - "FINDING DR-007" ids and a priority column separate from band

  Each is real or *not computed* here, and PUNCHLIST names the backend work.
- **The notifications bell.** Nothing raises notifications, so it is left out
  rather than shown silent.
- **The glow on the slider thumb** (the no-glow rule).

### 4. ADR-0018/0031 decisions changed by the design

- **Severity bar on every row.** It was on Critical and High only. The accent
  test now pins every band's bar, and still that it is not a row fill.
- **Rounded cards with gaps.** They were square and hairline-joined.
- **Neutral near-black palette.** It was navy slate-950. A dark blue-slate
  *surface* tint is used for status pills and the matrix.
- **Footer moved.** It became the status strip.
- **Logo and collapse.** The logo moved into the sidebar, and the sidebar
  collapses to icons.
- **Diff colours.** Added lines are now full-contrast (they were emerald);
  removed lines stay red.

### 5. Dead code removed

| Removed | Why |
|---|---|
| `@radix-ui/react-slot`, `@radix-ui/react-tooltip`, `class-variance-authority` | imported nowhere |
| `tailwindcss-animate` | not in the Tailwind plugin list |
| `@vitest/coverage-v8` | no script or config uses it |
| `getScan` (api/client) | never called. The endpoint stays; only the unused client function went. |
| `SheetTrigger`, `SheetClose` | unused shadcn re-exports |
| `parseScanSummaries` | a pass-through used only by its own test. Its wire-shape assertions now read the fixture directly, and null vs `[]` is pinned where it renders (`scanStatus`, `scannerCoverage`, the Coverage honesty test). |
| `.provisional` CSS class | no class-string use. The treatment lives in `Tag` and `Provenance`. |
| `MetricCard.sub`, `Panel.testId` | no callers |
| `downloadText` exported from a screen | moved to `lib/download.ts`, so screens no longer import each other |

The five dependencies came out with 63 packages from `node_modules`. None of
them was ever in the bundle, so the gain is install footprint and the vendoring
rule, not bundle size.

**Kept and flagged:**
- `ApiError`: thrown by the client, exported for callers.
- Exports used inside their own module: harmless.
- `@testing-library/dom`: a required peer of `@testing-library/react`.
- `@types/node`: types `vite.config.ts`.

### 6. Tests

There are 131 Vitest tests, up from 126:

| Change | Tests |
|---|---|
| Format helpers | +3 |
| Filter select | +2 |
| Roadmap CSV | +1 |
| `parseScanSummaries` tests replaced by one wire-shape test | −1 net |

The accent test now asserts every row. The routing test pins each screen's
design heading beside its nav label. The honesty, rescore-drives-Overview and
nav-routing tests are unchanged in substance, and all pass. tsc is clean.

## Consequences

**Good.** The console's structure follows the design on every screen that has a
screenshot. The honesty rule, the fonts, the mark and the colour lock are
unchanged, and the frontend's dependency list is only what it imports or
requires.

**Costs and limits.**

- **Still not visually verified.** No headless browser is installed on the build
  machine. The owner's screenshot of the running build is the first look at the
  result.
- **The orange accent is an open decision** (§3).
- **Bundle grew.** It went from 332 KB to 347 KB JS (102 → 106 KB gzipped) and
  50 → 52 KB CSS, from the richer layout. There is still no chart library.
- **Design images are committed.** `web/design/` holds 1.4 MB of JPEGs, the
  reference this ADR cites. They sit outside `src/` and `public/`, so they never
  reach `web/dist`.
