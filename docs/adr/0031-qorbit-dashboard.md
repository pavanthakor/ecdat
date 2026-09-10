# ADR-0031: The Q-orbit security console — every screen, real data or "not computed"

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** full console build (one slice; a fixup/error-check slice follows)
**Depends on:** ADR-0016 (denormalised rows, rescore), ADR-0017 (verified facts),
ADR-0018 (console slice 1), ADR-0020 (reports), ADR-0026 (`configurable`),
ADR-0030 (target labels)

## Context

ADR-0018 shipped one screen — summary strip, Mosca slider, inventory, drawer —
and owed a second slice: roadmap, agility, fixes, drift. This slice builds the
whole console as **Q-orbit — Security Console**: eleven screens and Settings,
grouped ANALYZE / PLAN / REPORT, wired to the real API.

The brief's governing constraint is the honesty rule from ADR-0017/0020/0026,
applied to a surface: **every panel is wired to real data or shows an honest
"not computed" state — no invented numbers, no fake bars.** On a dashboard
that rule is harder to keep than anywhere else, because a plausible number
looks exactly like a true one and nobody re-derives what they are shown.

Two inputs were not available. The design screenshots the brief refers to
reached neither the repository nor this session, so the layout follows the
brief's written description of each screen. And the `frontend-design` skill
is not installed here (as in ADR-0018). The fixup slice is where the console
is first compared with the design by eye.

## Decision

### 1. The honesty rule, made checkable

Every number the console shows is exactly one of:

1. a **stored value** — a score, band, deadline or count on the scan row;
2. a **count** of stored facts in the loaded document; or
3. a **ratio** of two such counts, rendered with both of them visible.

Anything else is `not-computed`. `state/metrics.ts` returns
`Measured<T> = {status: "computed", value, basis} | {status: "not-computed",
reason}`, and `components/Honest.tsx` is the one renderer: a computed metric
shows its value **and** its basis; a not-computed one shows "Not computed" and
why. There is no third rendering — a not-computed metric is never a zero, and a
computed zero is never "not computed". Both directions are pinned in
`honesty.test.tsx`, including that a not-computed card contains **no digit at
all**.

Nothing in `metrics.ts` feeds a score. The one place arithmetic touches Mosca
terms, the horizon delta `z − (x + y)`, is the inequality itself, evaluated on
the stored per-component terms and rendered with them.

### 2. Real vs honest-empty, per screen

| Screen | Wired to real data | Honest empty / not computed |
|---|---|---|
| **Overview** | artefact and band counts from the LIVE document (they follow the slider), quantum-broken count, view coverage %, configurable share, x/y ranges and horizon delta, risk distribution, score histogram, priority queue, coverage pulse; slider → `POST /rescore` | the drift card says *not computed* when fewer than two views were collected |
| **Scans** | every row field (ADR-0016 columns); status derived from the row with its rule on hover; **New scan** → `POST /scans` or `POST /systems/scan` | **Started**: not recorded — the store keeps the save time only |
| **Inventory** | all columns, band/view/drift filters, verified/provisional, drill-down drawer, fix from `GET /fixes`, CSV | — |
| **Risk Analysis** | — | the whole screen: an honest placeholder that sends the reader to Inventory → Drift → Roadmap |
| **Cryptographic Drift** | Declared → Shipped → Observed per drift, cause, confidence, evidence, peers | *cannot be assessed* with fewer than two views; **next check**: not scheduled (no monitoring job exists) |
| **Migration Roadmap** | a bar per DATED artefact, overdue column, deadline clusters, target from the pack's label, hybrid flag | undated artefacts are listed, never placed on the axis; no label → "no target labelled" |
| **Verified Fixes** | `GET /fixes`, diff for verified fixes only, FIPS tag from the template citation, patch size, Copy / View finding / Re-scan, **Run fix pass** | "no fix pass has been run"; a failed fetch renders as a failure, not as an empty queue |
| **Crypto Agility** | configurable / hard-coded / not-assessed counts and the configurable share (`ecdat:configurable`), where-to-improve list | **key store** and **protocol negotiation**: not computed |
| **Coverage** | scanner cards (SELECTED / NOT RUN / UNKNOWN), artefacts attributed per scanner, provisional counts, engine installed or UNAVAILABLE, visibility matrix, `coverage_gaps` | whether a selected scanner applied, ran or failed (§4); packs applied (not exposed by the API) |
| **Reports** | the three PDFs (View / Generate), CBOM JSON download, CSV (a browser-side projection, labelled as such) | **HTML**: not available — no renderer exists |
| **Compare Scans** | new endpoint `GET /scans/{a}/compare/{b}` (§3); default pair from parent/child links | "select two scans" when there is no pair |
| **Settings** | read-only facts: API base, build, auth status, scoring context, engines | nothing is editable yet |

The agility **configurable share** is real: 11 of 17 components on
QuantumBank carry `configurable=true`, so it reads 65%. Components with no
configurability finding are left out of the denominator and counted as *not
assessed*, because "no scanner could tell" is not "hard-coded".

### 3. Compare is a backend endpoint, not a browser diff

`GET /scans/{scan_id}/compare/{other_id}` (`core/compare.py`), joined on the
content-addressed bom-ref. **New** / **resolved** are bom-refs present on one
side only; **changed** is the same bom-ref with a different band, score,
deadline, quantum status or evidence, returned with BOTH sides; **drift
introduced / resolved** are drift records present on one side only, counted
once however many peers witnessed them.

It is server-side because the console reads and does not compute (ADR-0018),
and the join rule belongs with the code that minted the identity. It is exact
within what that identity can join, and that is its stated limit: a moved line
keeps its bom-ref and is changed evidence, while an artefact seen in a new
PLACE gets a new bom-ref and reports as resolved + new. Nothing fuzzy-matches
the two — a guessed pairing would be a diff nobody could audit.

Writing its tests caught a wrong assumption, not a bug: a Sovereign-data scan
re-scored from z=3 to z=30 changes nothing (x=50 keeps it exposed at both), and
compare correctly reported no change. The test now uses pii data (z=5→20).

### 4. `scanners_ran` records what was OFFERED — so the console says SELECTED

Wiring Coverage turned up a backend fact the design had assumed away. `run_scan`
stores `scanner_records(scanners)` — every scanner offered — while the
orchestrator's own ran / skipped / failed split goes only to the log. A
`minimal_repo` scan's row lists `binary`, `container` and `runtime-spool`,
all three of which were skipped. A Coverage card reading "RAN — binary" would
claim ECDAT looked for binaries where it did not, which is exactly the failure
ADR-0016's null / `[]` / list distinction exists to prevent.

So the console's vocabulary is **SELECTED / NOT RUN / UNKNOWN**, never "ran",
and the attributed-artefact count carries the real signal: a sighting from a
scanner proves that scanner looked. The coverage PDF still prints "— ran" for
every entry. Persisting the outcome is backend work, recorded in PUNCHLIST
rather than done here.

### 5. Hash routes, because the API owns `/scans`

FastAPI mounts the API at `/` as well as `/api`, so a console path of `/scans`
is answered by the API's JSON on a reload (verified). Routes are `#/scans`,
`#/drift`, …: they never reach the server, need no change to the SPA
catch-all, and cannot collide with an endpoint added later. `lib/router.ts` is
about eighty lines, not a dependency. An unknown route renders "No screen at
#/…" rather than silently showing the Overview. The open artefact lives in the
URL (`#/inventory?ref=…`), so a finding link on any screen lands on its drawer.

### 6. Branding: the Q-orbit mark

One tilted elliptical ring — the Q's bowl and an orbit — with a small filled
node on the ring at lower right; the Q's tail is a short stroke through that
node, crossing the ring, so the node is both the satellite and the joint where
the tail leaves the letter. Monoline 1.75 units on a 32-unit grid (≈1.5px at
28px), no gradient, no glow. The node's position is computed (the point at
t = 60° on an 11 × 9.5 ellipse rotated −20°), not eyeballed. The wordmark is
"Q-orbit" in Space Grotesk with SECURITY CONSOLE in letter-spaced caps beneath.
The favicon is the same mark as an inline `data:` URI, so even that is not a
request.

`brand` (amber-400) is used by the mark and nothing else. It sits in the chrome,
never beside a value, so it cannot be read as the High band. The mark renders
in muted slate when no analysis is loaded.

### 7. Typography: Space Grotesk + JetBrains Mono, self-hosted

Space Grotesk for the interface and headings, JetBrains Mono for anything
compared character by character — bom-refs, locators, endpoints, versions,
diffs. Both are geometric grotesques in construction, so moving from prose to
an address reads as a change of register rather than of style. Both come from
`@fontsource` (Space Grotesk pinned at 5.1.1, matching JetBrains Mono), and
Vite copies the files into `dist/assets`. Inter is removed.

### 8. Colour, borders, and one change of token

Semantic colour only: Critical red, High amber, Medium yellow, Low slate.
Critical moved from rose-500 to red-500, as the brief specifies. Drift markers are
now neutral ink (they were amber in slice 1): drift is a finding, not a band.
Verified vs provisional stays a border — solid for verified, dashed for
provisional, dotted for unknown — and never a colour. The two exceptions stay
where they are documented: `+`/`-` in a diff, and the brand mark.

### 9. Scan status is derived, with its rule stated

The row carries no status. The Scans table derives one and shows the rule on
hover: **DERIVED** for a rescore or fix row (its coverage is its parent's);
**UNKNOWN** when `scanners_ran` is null; **PARTIAL** when no scanner was selected
or `coverage_gaps > 0`; **COMPLETE** otherwise. Given §4, COMPLETE claims only
what the row supports.

### 10. The drift panel knows which view the "observed" side is

`ecdat:drift:observed` is the OTHER side of a disagreement, and for
`shipped-cannot-do-declared` that side is the shipped image, not a handshake.
A table keyed on the correlator's kind constants puts each value in the right
cell; an unknown kind falls back to the views its evidence cites. Each cell is
STATED, DIVERGES, "not compared by this rule" or "not collected in this scan".
A confirmed observation is solid; an unconfirmed one (confidence 50%) is dashed.

### 11. The roadmap's target is a label, never a parameter set

The target column reads `target-ml-dsa` / `target-ml-kem` /
`target-depends-on-usage` off the component (ADR-0030). The brief's example
"RSA-2048 → ML-DSA-65" names a parameter set that no pack chooses, so the
console shows the family the pack stated and nothing more specific.

### 12. The user menu is cosmetic

ECDAT has no authentication. The menu opens, and every entry is disabled with
a sentence saying why: it is cosmetic until the Tier-3 auth work lands, and the
API is unauthenticated on localhost. **Superseded by ADR-0035:** the menu now
names the API key the console holds and its role, and "Sign out" works.

## Consequences

**Good.**

- Every screen in the brief exists and reads the real API. Where the backend
  computes nothing, the screen says so in words and draws nothing.
- The Mosca slider drives the whole Overview through one debounced rescore of
  the ORIGINAL scan; `overview.test.tsx` pins the request and every card.
- Two backend honesty defects were found by wiring a surface to them: §4, and
  a stale coverage-report gap list (PUNCHLIST).
- 126 Vitest tests (68 before), plus 15 Python tests for compare. `tsc` is clean.
  The build is 332 KB JS / 102 KB gzipped and 50 KB CSS, with no chart library:
  gauge, histogram and Gantt are SVG or divs.

**Costs and limits.**

- **Nothing was visually reviewed.** There were no design images, and no
  headless browser is installed on the build machine, so no screenshot was
  taken. Layout is untested by design (ADR-0018 §8). The fixup slice exists
  for this.
- **The bundle grew from 242 KB to 332 KB** (78 → 102 KB gzipped) — twelve
  screens instead of one. The seven `http(s)` strings inside it are library
  constants (React's error-decoder link, a Radix docs link in a dev warning,
  XML namespaces) and are never fetched; `dist/index.html` references only
  `/assets/` and `data:` URIs.
- **New scan, Run fix pass and Re-scan are synchronous** on the server — the
  request returns when the row is stored. The job model is still owed
  (ADR-0003); the dialogs say they are waiting rather than showing progress
  they do not have.
- **Every slider settle stores a rescore row** (ADR-0016's design). The Scans
  table hides derived rows by default and says how many there are.
- **CSV is generated in the browser** from the loaded CBOM. It is a projection
  of stored values, not a server report, and the Reports screen labels it that
  way.

## Addendum (2026-09-10): candidate and confidence on screen (ADR-0034)

ADR-0034 gave the source scanner a way to say "not sure": a **candidate** at
`ecdat:confidence: 0.5` with `ecdat:param:candidate: True`, for a key-ish name
holding a high-entropy literal that nobody saw reach a crypto sink. The console
rendered it exactly like a 1.0 finding. That presented an uncertain claim as a
confident one, in the Inventory, where a reviewer looks. The console now
carries the doubt onto the screen, under §1's and §8's rules.

**The rule.** A **candidate** is a finding its rule FLAGGED
(`ecdat:param:candidate`): a key-ish name holding a high-entropy literal nobody
saw reach a crypto sink. It might not be real key material. A finding below
1.0 without the flag is **inferred**: real crypto with one detail not read
outright, such as a parameter that came through a variable or a binary
heuristic. Exactly 1.0 with no flag is **confirmed**. If the document records
no confidence, the artefact is **unrecorded**. The console does not invent
certainty or doubt for a missing property. The classification lives in
`state/certainty.ts`.

**Border, weight and a word, never colour.** The treatment reuses §8's
provenance vocabulary exactly:

| | Table row | Drawer |
|---|---|---|
| confirmed (1.0) | name full-weight; no marker | solid "Confirmed 1.0" badge; solid confidence block |
| candidate (flagged) | lighter name (`font-medium text-ink-dim`); a dashed `candidate` tag; `· confidence 0.5` in the sub-line | dashed "Candidate 0.5" badge; dashed block reading "candidate — not confirmed"; the ADR-0034 reason |
| inferred (< 1.0, not flagged) | no marker: the table does not shout | solid, lighter "Inferred 0.6" badge; a block reading "inferred — not read outright"; the reason |
| unrecorded | no marker | dotted "Confidence not recorded" |

The severity bar and the band pill are untouched. Candidate, inferred and
confirmed rows of one band render identical band classes, and a Medium inferred
finding keeps its Medium colour. `components/certainty.test.tsx` asserts both,
and that no band-colour token appears on any candidate marker.

**Why, in words.** The drawer shows the confidence of EVERY finding and states
a reason for it. A flagged candidate gets ADR-0034's reason: a high-entropy
literal, not seen reaching a crypto sink, not confirmed key material. An
inferred finding gets a sentence saying the scanner inferred part of it,
through a heuristic technique or a parameter that did not resolve. The console
does not know which of those it was, and the sentence does not claim to.

**A filter.** "Candidates" and "Confirmed" toggles sit beside "Drift only".
They are exclusive and each shows its count. "Candidates" is the flag and
nothing else. "Confirmed" is everything else: 1.0 findings, inferred ones, and
rows with no recorded confidence. The two toggles partition the table, and the
drawer still gives every row its confidence and reason. (Until ADR-0035 §6,
"Confirmed" meant exactly 1.0. That left every inferred finding in neither
toggle, including all 22 on a binary scan.)

**Revised the same day: a candidate is a flag, not a number.** The first
version (0d22a73) tagged every finding below 1.0. In the captured
`cbom_candidate.json` that was 6 of 37 components, and only ONE of them was an
ADR-0034 candidate. The other five were 0.6 findings whose algorithm is certain
and whose captured parameter was a variable name. In `cbom_binary.json` it was
all 22 components, because every binary-scanner finding is below 1.0 by design
(ADR-0025). "Candidate" means *might not be real crypto*, not *real, one detail
inferred*. The table now tags the flag alone: 1 of 37 in the JS scan, 0 of 22
in the binary one. Nothing was hidden, because every confidence is still in the
drawer.

**Limits** (PUNCHLIST):

- The treatment covers the Inventory and its drawer only. The Overview's lists,
  the Roadmap, Drift, Agility and Compare still list artefacts without it.
- The CSV export and the PDFs carry neither the confidence nor the flag.
- Nothing was visually reviewed. There is no headless browser on this machine,
  so the human takes the screenshot.
- Tests: 181 in Vitest (131 before this addendum).
