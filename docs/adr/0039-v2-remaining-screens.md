# ADR-0039: The v2 console design — the remaining nine screens

**Status:** Accepted
**Date:** 2026-09-11
**Slice:** v2 design rebuild, screens 2–10. These are Drift, Fixes, Inventory, Scans, Roadmap, Agility, Coverage, Reports and Compare.
**Depends on:**
- ADR-0038: the v2 design system, the shell, and the Overview.
- ADR-0031: the honesty rule and the colour lock.
- ADR-0034: candidate and confidence.
- ADR-0035: keys, jobs, pages.

## Context

ADR-0038 rebuilt the shell and the Overview on `web/design-v2/ecdat-console-v2/`. This slice applies the same pattern to the other nine mockups, one commit per screen:
- the mockup's layout and classes;
- the screen's existing API wiring, unchanged;
- real data, or "Not computed";
- colour only for a band.

Risk Analysis and Settings have no v2 mockup. They keep their layout inside the v2 frame and palette.

## Decision

### 1. One shared stylesheet, one kit, one audit

- **The stylesheet.** The rest of the mockups' shared stylesheet is ported into `src/styles/console-v2.css` (part 2): filters, drift chain, Gantt, fix card and diff, lifecycle, bar metrics, scanner grid, layer rows, report cards, compare, timeline.
- **The kit.** `src/components/v2.tsx` holds the pieces every screen reuses: `PanelHead`, `BandTag`, `Prov`, `EmptyState`, `Notice`, `tone()` and `useGrown()`.
- **The audit.** `src/test/colour.ts` walks a rendered screen. It fails if an element painted in a band colour does not name that band in `data-band`, or if a band colour is set inline. Every v2 screen test runs it and asserts the exact count of coloured elements, so it cannot pass on an empty page.

### 2. Colour means severity: the mockups' other colours are replaced

The mockups use colour for things that are not severity. Each is replaced by ink, border or weight:

| Mockup | Here |
|---|---|
| Green "verified" dot and amber "provisional" dot on the `.prov` chips | A solid dot on a solid border; a hollow dashed ring on a dashed border; dotted for unavailable or unknown |
| Red mismatch node and red arrow in the drift chain | A brighter, heavier border, and the word **diverges** under the arrow |
| Red / green diff lines | A removed line is dimmed, an added line is full ink; the leading −/+ says which. This also changes the drawer's diff, which ADR-0032 had kept red as "git's convention". |
| Green (done) / amber (current) lifecycle dots | Filled for done, a ring for current, dashed for failed |
| Green NEW / amber CHANGED change tags; red "drift introduced" count | NEW is an outline, CHANGED is bold ink, RESOLVED is muted; the counts are ink |
| Amber "hard-coded" bar; green agility gauge | A dimmer neutral bar; a white arc |

What keeps colour is what IS a band:
- the badges;
- the Inventory's severity rail;
- the Roadmap's bars (a provisional date is a dashed band outline);
- the Scans table's Critical / High counts.

Each carries `data-band`.

### 3. Run scan is on every screen

Every v2 mockup ends its topline with **Run scan**. ADR-0038 said it appeared only on the Overview; that was wrong. The shell now hosts one `NewScanDialog`, opened from any screen's topline, and disabled with the NEEDS_ADMIN reason for a viewer key. The Scans screen's own "New scan" button is removed in its favour.

### 4. The screens, and what each keeps honest

**Cryptographic Drift.**
- *Layout:* the selected finding's Declared → Shipped → Observed chain, with its cause, tags, confidence and Re-scan, beside the list of drift findings, then evidence-layer coverage.
- *Honest-empty / not computed:*
  - A node that does not speak says "not compared by this rule" or "not collected in this scan".
  - Confidence says "not recorded" when the drift record has none.
  - "Next check: not scheduled."
  - With one view collected, the screen says drift cannot be assessed, never "no drift".
  - The mockup's cause tags become the drift kind, its peers and its sightings.

**Verified Fixes.**
- *Layout:* a fix card per proposal: Current / Target, the verified diff, the lifecycle, and Copy patch · View finding · Re-scan.
- *Honest-empty / not computed:*
  - Target is the pack's label (ADR-0030), or "no target labelled by a pack".
  - The lifecycle marks only Proposed and the sandbox verdict. "Applied externally" and "Re-scanned" are never marked done, because nothing tracks them.
  - An unverified fix shows its reason and no patch.
  - The mockup's finding numbers are shown as the bom-ref.

**Inventory.**
- *Layout:* the filter bar, four stat cards, then the nine-column table with Export CSV. The drawer is unchanged.
- *Honest-empty / not computed:*
  - "Drifted" is Not computed when fewer than two views were collected.
  - "Deadline ≤ year+2" counts against a stated cutoff.
  - No deltas.
  - No "Internet-facing" chip: exposure is recorded per scan, not per artefact.

**Scan History.**
- *Layout:* four stat cards, the scan timeline (click a node to load that scan), then the history table with paging.
- *Honest-empty / not computed:*
  - **Avg. duration** and **Started** are not computed / not recorded: the row has no start time.
  - Complete and Partial / unknown count **this page** and say so.
  - Failed scans cannot be counted: a failed job stores no row.
  - No "Last 12 weeks" or "All systems" menus.

**Migration Roadmap.**
- *Layout:* the Gantt in band colours with deadline cards, the two highest-risk dated artefacts in detail, then the undated.
- *Honest-empty / not computed:*
  - An artefact with no deadline is listed, never placed on the axis.
  - Targets come from pack labels only.
  - No one-choice "Sort by deadline" menu.

**Crypto Agility.**
- *Layout:* the configurable share with its breakdown bars, a gauge, then "Where to improve next".
- *Honest-empty / not computed:*
  - **Key-store flexibility** and **protocol negotiation** are Not computed and draw no bar.
  - No "Target 80%", no "Moderately adaptable" rating, no "last 6 scans" trend: the gauge is this scan's share.
  - Per-component agility % becomes the component's **risk score**, labelled as such.

**Scanner Coverage.**
- *Layout:* the coverage headline with a card per scanner and the policy engine, then evidence-layer rows.
- *Honest-empty / not computed:*
  - The headline is views collected of three: there is no "expected artefacts" denominator.
  - Status is SELECTED / NOT RUN / UNKNOWN as a chip, with no work counts.
  - No TLS / SSH probe card, because no probe scanner exists.
  - An uncollected view says how to collect it, and draws no bar.

**Reports.**
- *Layout:* three report cards (View / Generate), then the artifact rows.
- *Honest-empty / not computed:*
  - The HTML row is Not computed: there is no HTML renderer.
  - The format tags say PDF: the mockup's "HTML" and "CSV" tags are not reproduced.

**Compare Scans.**
- *Layout:* the two scans face to face, each with its own picker, four counts, then the changed evidence.
- *Honest-empty / not computed:*
  - With no pair, the screen asks for two scans and never invents a baseline.
  - Counts and tags are ink, not colour.

### 5. Kept, everywhere

- The Mosca slider and its live rescore (Overview).
- Every filter and sort.
- The drill-down drawer.
- The drift detail.
- Fix diffs with Copy patch and Re-scan.
- Report View / Generate.
- The compare diff.
- The API key on every request.
- Server-side paging.

## Consequences

- There are per-screen v2 tests: `src/screens/*.v2.test.tsx` and `v2-screens.test.tsx`. Each covers the mockup's structure, real data, the not-computed states, and the colour audit.
- Existing tests changed only where the layout did:
  - Drift is now one chain at a time, chosen from the list.
  - The Inventory band pill is a `badge-*` class.
  - "New scan" became "Run scan".
- `FileButton` on a v2 screen is `bare` with a v2 button class, so the old Tailwind chrome does not mix in.
- **Still owed:** a visual check of the rendered console against the mockups. The build machine has no headless browser, so the human's screenshot is the first look.
