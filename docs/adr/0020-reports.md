# ADR-0020: Reports from a stored scan, and making the database visible

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** reports export + DB-path consistency
**Depends on:** ADR-0016 (self-describing rows), ADR-0017 (the verified-fact
gate), ADR-0019 (the system scan)

## Context

Two unrelated-looking problems, both about a stored scan.

**Reports.** `reports/` was an empty directory. Everything ECDAT knew lived in a
CBOM, a CLI, an API and a console — none of which is the artefact that leaves
the building. An auditor gets a PDF; a board gets two pages; a reviewer gets the
evidence.

**The database.** `ecdat scan` writes wherever `ECDAT_DB` points (or
`./ecdat.db`), `uvicorn` opens whatever `ECDAT_DB` points at *in its own shell*,
and `make kpi` deliberately uses `.ecdat-kpi.db`. Get those out of step and the
scan succeeds, the server starts, and the console is empty — with nothing
anywhere saying why. On a demo machine, that is a five-minute outage in front of
an audience.

## Decision

### Part A — make the path visible, do not resolve it

**No magic.** Two processes legitimately using two databases is a real thing to
want, and a tool that quietly reconciled them would be guessing at which one the
operator meant. The default stays `./ecdat.db`; `ECDAT_DB` still wins.

What was actually missing is that the path was invisible on both sides, so the
mismatch could not be diagnosed without `sqlite3`. So:

* `store.database_location()` returns the **absolute** path, resolved without
  requiring the file to exist — a relative path in a log line only means
  something with the working directory beside it, and the failure this exists
  to diagnose is precisely the one where two shells have different working
  directories.
* `ecdat scan` and `ecdat scan-system` print `db=/abs/path` beside the scan id.
* The API logs `"database": "/abs/path"` in its `api_started` line.
* **`ecdat scans`** lists what is actually in the current database — id, kind,
  component count, drift count, created — with the path printed above the rows,
  so the answer and the question arrive together.

An empty database prints `no scans in this database` rather than nothing:
silence and "there is nothing here" are different answers to the same question.

The operational rule — one `ECDAT_DB` for scanning and serving — is documented
in `web/README.md`, `docs/ONBOARDING.md` and the README, with the exact command
sequence.

### Part B — three reports, from the stored CBOM

**Nothing re-scans.** Every number, deadline and citation is read off the
`ecdat:*` properties the policy engine and the correlator already wrote. Two
consequences worth having: a report and the dashboard cannot disagree about the
same scan, and a report issued last quarter regenerates from the row that
produced it.

| kind | for | contains |
|---|---|---|
| `executive` | a decision | headline metrics, band distribution, top 5 by risk with actions, the DST framing with its source, provenance |
| `technical` | a reviewer | drift first, then every artefact by band with evidence, fired rules, per-category scores, verified fix diffs |
| `coverage` | honesty | which scanners ran, which views were and were not collected, incomplete correlation groups, and the standing "what ECDAT cannot detect" list |

**The coverage statement is the important one.** Every other output says what was
found; this one says what could not have been found. A view that was not
collected is reported as *not collected* with the remedy that would collect it —
never as clean — because "we found no observed crypto" and "we never observed
anything" are different sentences and only one of them is reassuring.

Its known-gap list is deliberately **not** derived from the scan. Those limits
(Python-only source scanning, four of seven scanner families, libssl-only
runtime coverage, whiteouts ignored, unverified PQC floors) hold for every scan
ECDAT runs, and a reader holding a PDF has neither PUNCHLIST nor the KPI output
beside them.

**Provisional stays provisional.** ADR-0017's rule travels into the artefact
that leaves the building: an unverified rule is labelled `[PROVISIONAL — scored
0]` in the *text*, and the executive report carries a section naming what is not
yet confirmed. A reader with a printout has no tooltip to hover, and a deadline
that reads as confirmed is one they will plan around.

### Determinism

The same scan renders byte-identical bytes. A report that changed on every
render could not be checksummed, attached to a ticket, or compared against the
copy somebody was sent. Two reportlab defaults fight that and both are pinned:
`invariant=1` stops the random file identifier, and the document dates are set
to the **scan's** timestamp rather than `now()` — which is the date the report
is actually about.

### reportlab, not weasyprint

The slice brief expected reportlab to be an existing dependency from "earlier
PDF work". There was none: `reports/` was empty with no history, and nothing
PDF-capable was installed or in `requirements.txt`. `weasyprint` was importable
as a package and **could not actually import** — it needs cairo/pango at the OS
level, which are not present.

reportlab is added: a pure-Python wheel with no system libraries. That is the
deciding property, not familiarity — a report generator that cannot run on an
air-gapped box is no use to the estates ECDAT is for.

### One `UnknownScanError`

`core.orchestrator` already had one, for a derived pass asked about a missing
scan; the reports needed the same condition. It now lives in `core.store` — the
thing that does or does not have the row — and both re-export it. A second
exception type with the same meaning is a second `except` clause somebody will
forget.

## Consequences

**Good.**

- `ecdat scans` turns "why is the dashboard empty?" into one command that prints
  both the path and the contents.
- Three artefacts a real engagement needs, generated from data already stored,
  with no second source of truth to drift from the first.
- The coverage statement makes ECDAT's limits an *output* rather than a
  footnote in a repository nobody reading the PDF has.

**Costs and limits.**

- **The styling is functional, not designed.** Helvetica, rules, a two-column
  grid. It is an artefact you can hand to an auditor, not a brochure; a designed
  template is later work.
- **The mismatch itself is not solved, only diagnosable.** Two shells with
  different `ECDAT_DB` values still produce an empty console; the difference is
  that one command now says so. That is the deliberate choice, and it means the
  operational rule has to be documented and followed.
- **The technical report grows with the estate.** QuantumBank's 26 components
  produce ~88KB and a dozen pages; a thousand-component estate would produce
  something nobody reads. It wants filtering (by band, by system) before it is
  run against anything real.
- **Fix diffs are truncated** to the first 14 lines. A full patch belongs in the
  `.patch` file `ecdat fix --out` writes, not in a PDF.
- **No report covers a fix pass or a rescore row directly.** Both are ordinary
  scan rows and will render, but nothing frames "here is what changed" — a
  comparison report between two scans is the obvious next one.
- **reportlab has no type stubs**, so `reports/layout.py` is an untyped edge.
  It is confined to that one module by design.
- **`make reports` resolves its default SCAN inside the recipe**, not with
  `$(shell ...)`. Make expands `$(shell)` at parse time, so the obvious version
  opened the database on `make -n reports` — a dry run that writes a file, and
  the source of a stray `ecdat.db` in the working tree. Worth knowing before
  anybody adds another `$(shell)` that touches the store.
