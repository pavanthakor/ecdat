# ADR-0018: The console — React + Vite, built to static, served by FastAPI

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** dashboard slice 1 (core console)
**Depends on:** ADR-0016 (denormalised scan rows, rescore endpoint), ADR-0017
(the verified-fact gate)

## Context

Everything ECDAT knows has lived in a CBOM, a CLI and an API. That is enough to
prove the tool works and not enough for anyone to *use* it: a 17-component
QuantumBank document is 73KB of JSON, and the estate this is aimed at has
thousands. The dashboard is where an operator forms a judgement, which makes it
the place where a misleading pixel does the most damage.

Two prior decisions constrain it before any design question is asked. ADR-0016
put a denormalised verdict summary on the scan row precisely so a list view
would not parse every document. ADR-0017 made unverified facts unscoreable and
gave them a *provisional* marking — a marking that only means something if the
surface a human reads honours it.

## Decision

### 1. Built to static, served by FastAPI. No Node at demo time.

`vite build` produces `web/dist/`; FastAPI mounts `/assets` and serves
`index.html` from a SPA catch-all. `make web` is the only step that needs npm,
and it runs ahead of time.

A dev server on stage is a watcher, a websocket and a rebuild between the
presenter and the thing being presented. Serving pre-built files also means the
console has exactly the same availability as the API — one process, one port.

The catch-all **404s inside API prefixes** rather than returning `index.html`
for everything unmatched. A SPA fallback that answers a mistyped endpoint with
an HTML 200 turns the mistake into a `JSON.parse` failure three frames away.

### 2. One API surface, mounted twice

Routes are defined once on an `APIRouter` and included at both `/` and `/api`.
The console fetches relative `/api/...` paths — the same paths the Vite dev
proxy forwards — so one client works in development and against the built
bundle with no configuration and no base URL to point somewhere else.

The bare mount is the documented surface every existing test uses; nothing had
to change to add the prefixed one.

### 3. Offline by construction, like the rest of the tool

* **Fonts vendored.** Inter and JetBrains Mono via `@fontsource`, whose `woff2`
  files live in `node_modules` and are copied into `dist/assets` by Vite.
* **No external script or stylesheet.** `dist/index.html` references two hashed
  local assets and nothing else.
* **Same-origin only.** `client.ts` has no configurable base URL: the console
  can only talk to the server that served it.

ECDAT is for air-gapped estates. A dashboard that fetches a stylesheet from a
CDN is broken in the one environment the tool exists for, and it would break
silently — as a font that renders wrong, not as an error.

### 4. The console reads. It does not score.

Every band, score, count and deadline is lifted out of the stored document or
the scan row exactly as written. Nothing is recomputed in the browser.

A dashboard that derived its own numbers could disagree with the CBOM it is
displaying, and the disagreement would be invisible to the person reading it —
they would have no reason to check. The summary strip reads `band_counts`,
`max_score`, `drift_counts` and `scanners_ran` off the row (ADR-0016), so it is
O(1) per scan and cannot drift from the document.

`scanners_ran` is rendered three ways, because it has three meanings:
`null` → "unknown — not recorded for this scan", `[]` → "no scanner ran", a
list → the ids. Collapsing the first two would turn "never looked for binaries"
into "binaries were clean".

### 5. Verified vs provisional is a first-class visual

The engine already refuses to let an unverified fact move a number. This is the
other half: **a fact nobody checked must never LOOK like a checked one.**

| | verified | provisional |
|---|---|---|
| border | solid, `border-line` | **dashed**, `border-ink-faint` |
| fill | `bg-raised` | transparent |
| text | full contrast | desaturated |
| contribution | `criticality · 20` | **`provisional · scored 0`** |
| deadline | `2027-12-31 · verified` | `2027-12-31 · provisional — unconfirmed source`, struck through in the table |

**The treatment is deliberately not a colour.** Colour in this console means
severity and nothing else, so provenance is carried by border style and weight.
And the word "provisional" is always in the *text*, never only in a tooltip: a
caveat that needs a hover is a caveat that will be missed on a projector.

The demoted rule is still listed. Demoted, never dropped — the same rule
ADR-0017 applies to the score, applied to the surface. `Provenance.test.tsx`
asserts both directions, including that one unverified rule does not tar the
verified rules on the same component.

### 6. Data-dense, not decorative

Refined in the polish pass against how real security consoles (Wiz, Snyk,
Semgrep, Datadog) actually present a findings table:

* **Severity is an edge marker, not a fill.** Critical and High rows carry a
  2px left border; Medium and Low carry a transparent one so the gutter stays
  aligned. A background fill washes out the row's own content and stacks badly
  when several are adjacent — an edge lets the eye run down the left margin
  without competing with anything in the cells.
* **Hairline separators, no zebra striping.** Striping encodes nothing and
  fights the severity accent for attention.
* **Numbers right-aligned and tabular.** Scores and deadlines line up on their
  digits, so a column is scanned rather than read.
* **The artefact name is the strongest thing in its row**; the bom-ref beside
  it is 10px muted mono, because it is an address, not a label.
* **No inline explainers.** The Mosca explanation moved into an `(i)` affordance.
  A console that narrates its own widgets on the main view reads as a tutorial;
  the people who use one daily already know, and the people who do not can
  hover.
* **Context is quiet.** Sector/exposure/data-class are muted label + value
  pairs in the top bar, not highlighted text — they are context, not alerts.
* **A live consequence readout** beside the slider, recomputed from the
  artefacts ON SCREEN rather than from `scan.band_counts`. Reading the row
  would freeze the headline numbers at the stored horizon while the table
  beneath them changed.
* **Three empty states, not one.** Nothing selected / scan found nothing /
  filters exclude everything — and only the third offers an action. Offering
  "clear filters" to somebody whose scan genuinely found no cryptography sends
  them after a control that cannot help.
* **Skeleton rows, never a flash of empty**, so the table keeps its shape
  through a scan change or a rescore.
* **An auditable footer**: scanned date, engine versions from
  `engine_versions` (ADR-0017), and how many facts are provisional.

Compact rows, hairline borders, square corners, and monospace tabular numerals
for every technical value (bom-ref, endpoint, deadline, score) so columns align
and can be scanned vertically.

Four saturated colours in the whole application, all of them bands. There is no
accent token: interaction affordances (slider, focus rings) use the slate ramp,
so a coloured pixel always means severity. The single exception is documented
where it sits — `+`/`-` in a rendered diff, which is a git convention rather
than a severity claim.

No gradients, no glow, no oversized cards, no centred hero, no emoji, and no
icon that is not doing work. The reference is a security console someone works
in for eight hours, not a landing page.

### 7. One field added to the API, for the footer

`ScanSummary` gained `engine_versions` and `engine_warning` — already columns on
the row since ADR-0017, simply not exposed. The footer needs them to say which
engine produced the view a reader is looking at. A tool that can name the
version behind a conclusion is one somebody can audit; one that cannot is
asking to be trusted.

### 8. Tests cover data logic and interaction, not layout

68 Vitest tests over parsing, filtering, sorting, the rescore flow and the
provenance rendering rule. Layout is not tested.

The split is by *failure visibility*: a column in the wrong place is obvious in
a screenshot; a filter that silently drops rows, a rescore that leaves a stale
table, a readout wired to the stored row instead of the live one, and a
provisional fact rendered as verified are not.

**Every fixture is a real document.** `cbom_z11.json` and `cbom_z5.json` are the
same estate before and after an actual `POST /scans/{id}/rescore`;
`cbom_provisional.json` came out of the policy engine with the DST pack demoted;
`cbom_drift.json` has all three views merged. Hand-written fixtures test the
parser against the shape one imagined, which is always the shape that works.

## Consequences

**Good.**

- The Mosca slider works against the real endpoint. Moving Z from 11 to 5 issues
  one debounced `POST /scans/{id}/rescore?z_years=5`, fetches the new linked
  row's document, and re-scores **15 of 17 components across a band boundary** —
  MD5 High→Critical, thirteen TLS/SSH artefacts Low→Medium. Nothing is
  re-scanned and the parent row is untouched.
- A failed rescore keeps the last good table and shows the error. Blanking the
  console would replace a true inventory at the old horizon with nothing.
- Rescores always derive from the ORIGINAL scan, never from the previous
  rescore row, so an estate's score cannot depend on how many times somebody
  dragged the slider.

**Costs and limits, stated plainly.**

- **The slider only re-colours in one direction on this fixture.** Pulling Z in
  moves 15 components; pushing it out to 20 lowers every score by the same 13
  points and crosses no threshold, because every QuantumBank component shares
  one data class and their Mosca terms move together. The table re-renders
  either way. `parse.test.ts` asserts both, so the limit is recorded rather
  than discovered on stage.
- **The relative ORDER is stable across a rescore, for the same reason.** The
  brief expected re-ordering; what actually happens is re-scoring and
  re-colouring. An estate with mixed data classes would re-order.
- **No stored scan carries drift.** Drift needs all three views in one document,
  and `run_scan` takes one target — the KPI harness merges three scans by hand
  (ADR-0014). So the drift column, the drift-only filter and the drift section
  are built and tested against a real merged fixture, and will show nothing
  against a scan the console can currently load. A "scan a system, not a target"
  entry point is owed.
- ~~The bundle is 619KB, most of it Recharts.~~ **242KB (78KB gzipped)** after
  the polish pass. The score distribution became a labelled div-based bar chart
  with a baseline and axis end-labels — at ten buckets that is more precise than
  a charting library and needs no dependency — so Recharts was removed. Slice 2's
  roadmap timeline and agility gauge can add it back in one command if they
  genuinely need it.
- **`web/dist/` is git-ignored**, so a fresh clone needs `make web` once before
  `make serve` shows anything. The API returns a 503 naming the exact command
  rather than a bare 404, but it is still a step that can be forgotten.
- **No authentication.** The console inherits the API's existing gap — it now
  serves an estate's full inventory *and* its verified fix diffs over
  unauthenticated localhost. Already the largest open item in PUNCHLIST; the SPA
  widens the blast radius rather than adding a new hole.
- **The `frontend-design` skill was not available on this machine**
  (`/mnt/skills/public/frontend-design/SKILL.md` does not exist), so the visual
  decisions above follow the brief's constraints and the stated SOC-console
  reference rather than that guidance. Worth a second look by someone who has
  it.
- **Slice 2 is deferred**: roadmap timeline, agility gauge, the fixes-apply
  view, and the drift graph. The fix data is already parsed and the drawer
  renders a verified diff when a `kind: "fix"` row is selected — but there is no
  dedicated view, and no way to trigger a fix pass from the console.
