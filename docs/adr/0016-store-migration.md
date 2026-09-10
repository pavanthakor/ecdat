# ADR-0016: Self-describing, re-runnable scan rows

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** store migration (closes six punch-list items, unblocks the dashboard)
**Amends:** ADR-0003 (the scan pipe) and ADR-0015 (fix-it) — the fix pass now
has somewhere to land.

## Context

`store.Scan` held the CBOM, four target fields and a timestamp. Everything else
about a run lived only in a log line, and six punch-list items were the same
underlying complaint from six directions:

1. **`scanners_ran` was not persisted.** So "was this estate ever scanned for
   binaries, or does it just have no binary findings?" could not be answered
   from the database, and the two states rendered identically in a dashboard.
2. **`sector`, `exposure`, `z_years` were not persisted.** They reach the CBOM
   as per-component properties, but nothing on the row said what context the
   scan ran in, so re-running anything meant the caller remembering it.
3. **`GET /scans` parsed every stored CBOM** to compute band counts — O(scans ×
   document size) for a bar chart.
4. **There was no rescore entry point.** `apply_policy` is idempotent and was
   designed for exactly this, but nothing exposed it, so a guidance change
   meant a re-scan.
5. **`ecdat fix` did not update the store**, so the dashboard could not see
   fixes at all.
6. **`ecdat fix` re-took `--sector`/`--exposure`** because the row did not keep
   them — and its defaults (`other`/`unknown`) are the *permissive* ones, so a
   fix run without flags was judged more leniently than the scan that found the
   problem. A fix introducing a Critical could be accepted because the context
   that made it Critical had been forgotten.

The sixth is the one that matters most. It is not an inconvenience; it is a
silently weaker safety gate on the one part of ECDAT that produces changes.

## Decision

### 1. A row records what ran, in what context, and what it concluded

| column | why |
|---|---|
| `scanners_ran` | JSON `[{"id", "version"?}]` — what was *offered*, so a scanner that ran and found nothing still counts as having looked |
| `sector`, `exposure`, `z_years` | the scoring context, so a derived pass reproduces the original judgement |
| `band_counts`, `max_score`, `drift_counts`, `coverage_gaps` | the denormalised verdict summary |
| `parent_scan_id`, `kind` | lineage |

`scanners_ran` is derived from the scanner **selection**, not from which
plugins produced findings. The question the column exists to answer is "did
anything look here?", and a clean scanner has still looked.

### 2. `NULL` and `[]` mean different things, and must never be collapsed

- `NULL` — **unknown.** A row written before the column existed. We cannot say.
- `[]` — **known, and empty.** Nothing ran: an empty `--scanner` selection, or
  a rescore.

A column that collapsed these would be worse than no column, because it *looks*
like an answer. `test_an_unknown_scanner_set_and_a_known_empty_one_are_distinguishable`
and its API counterpart pin this, and the migration deliberately leaves old
rows `NULL` rather than backfilling a plausible-looking `[]`.

The same rule governs the context columns: `sector`/`exposure`/`z_years` on a
migrated row stay `NULL`, because they are not derivable from anything stored.
A migration that guessed `sector` would put a number in the dashboard nobody
ever measured.

### 3. Fix and rescore write NEW linked rows. The parent is immutable.

A fix pass and a rescore create a row with `parent_scan_id` set and
`kind` of `fix` or `rescore`. Nothing ever `UPDATE`s the parent.

This is the same refusal ADR-0015 makes about the filesystem, applied to the
database. An inventory someone acted on is a record of what was true when they
acted; revising it in place destroys the ability to answer "what did we know in
March?". Keeping both rows makes "we re-prioritised against a 30-year horizon"
an auditable statement rather than a silently different number.

`store._derived()` reads the parent only to inherit its target, and issues no
`UPDATE` at all — the immutability is structural, not a convention. Two tests
defend it (`..._leaves_the_parent_untouched` for fix, `..._byte_identical` for
rescore) plus a mutation test that performs the in-place amend itself and
asserts the byte comparison notices, so the guard is demonstrably load-bearing
rather than vacuously true.

### 4. Context resolution: explicit flag > parent row > default

`resolved_context()` is one function with one order, shared by the CLI and the
API. The **middle term is the point**. Falling straight from "not supplied" to
`other`/`unknown` is the permissive direction; the defaults now apply only to a
row that genuinely never recorded a context.

The CLI's `--sector`/`--exposure`/`--crqc-years` on `fix` therefore default to
`None`, not to `"other"`/`"unknown"`. That distinction — "unsupplied" versus
"supplied as the default" — is what makes inheritance possible at all, and it
is why those defaults could not simply be left as they were.

`cli._inherited_context` is a named seam so
`test_mutation_ignoring_the_parent_context_reintroduces_the_lenient_default`
can disable inheritance and assert the permissive default comes straight back.

### 5. Additive column migration, introspection-driven. Not Alembic.

`init_db()` reads `PRAGMA table_info(scans)` and issues
`ALTER TABLE scans ADD COLUMN` for anything in `ADDED_COLUMNS` that is absent.

**Why not Alembic.** Alembic's value is ordered, reversible, branch-aware
migrations across environments that cannot all be upgraded at once. ECDAT today
has one SQLite file per developer, no deployed installations, no downgrade
requirement, and one table. Adding Alembic now would buy a `versions/`
directory, an `alembic.ini`, a migration-authoring step in every schema slice
and a second source of truth about the schema — in exchange for a guarantee
nothing currently needs. The models are written so it can be adopted later
without rework: no SQLite-only types, application-generated ids, and every
added column nullable or defaulted.

**The rule that keeps this honest: additive only.** Nothing here drops, renames
or retypes a column. The moment a change needs any of those — or needs to run
against a database somebody else owns — this approach has reached its limit and
Alembic is the answer, not a bigger `ADDED_COLUMNS`. That is recorded in
PUNCHLIST rather than left as folklore.

Every entry must be nullable or carry a non-null `DEFAULT`: SQLite can only add
a `NOT NULL` column when a default is supplied, and more importantly an existing
row has no value to put there. `kind` gets `DEFAULT 'scan'`, which is true of
every row that predates the concept.

### 6. The verdict summary is computed once, where the bytes are written

`core/summary.py` holds the one definition. `store._row()` calls it at save
time, beside the document it describes, so the columns cannot disagree with the
bytes next to them — there is exactly one place that writes both. The API reads
the columns and **never parses a stored CBOM** in the list path.

This is a deliberate deviation from the slice as framed, which put the
computation in the orchestrator: computing it in the store means *every* caller
of `save_scan` gets consistent columns, including tests and future callers,
rather than only the one path that remembered to.

The migration **backfills** the summary for pre-existing rows, because it is
derivable from bytes already on the row — reconstructing it is reading, not
inventing. A row whose document will not parse keeps its `NULL`s rather than
gaining a zeroed summary that would read as "scanned, nothing found".

`drift_counts` and `coverage_gaps` are denormalised alongside `band_counts` and
`max_score`, which the frame did not list. They had to be: they were part of the
same per-row parse, and leaving them out would have meant the list endpoint
still parsed every CBOM, which is the thing being removed.

The test that defends this does not spy on a call — it **corrupts the stored
document** and asserts the summary is unchanged. A regression to parsing cannot
pass it, and the paired mutation test reintroduces the parse and asserts the
corrupted row then blows up.

### 7. `ecdat rescore <scan-id> [--z-years N]`

Re-applies the scoring pipeline to the **stored** document. No scanner runs —
`test_rescore_changes_scores_without_running_any_scanner` patches every
registered scanner's `scan` and asserts none was called.

Scoring is now one function, `score_and_correlate()`, shared by `run_scan` and
`run_rescore`, so a re-scored document is produced exactly the way the original
was. It strips the correlator's properties before re-running policy: `apply_drift`
remembers each component's *pre-drift* score so that re-running replaces rather
than compounds, and that carried value is stale the moment policy re-scores
under a different horizon — it would amplify the old number. This was a real bug
found while wiring rescore, not a hypothetical.

## Consequences

**Good.**

- A stored scan is now reproducible: what ran, in what context, with what
  verdict. `ecdat fix` and `ecdat rescore` both re-derive from the row.
- The lenient-fix gap is closed, and closed with a test that fails if it
  reopens.
- `GET /scans` is O(rows) instead of O(rows × document size).
- The dashboard has its Mosca slider (`POST /scans/{id}/rescore`) and its fix
  view (`POST /scans/{id}/fix`, `GET /scans/{id}/fixes`).
- Opening an older database works, keeps its data, and honestly reports what it
  cannot know.

**Costs and limits.**

- **Still no auth and no pagination on the API.** `GET /scans` now serves an
  estate's inventory *and* its fix diffs over plain localhost CORS, and returns
  every row. Deferred deliberately and still owed — it is the largest open item
  in PUNCHLIST.
- **`POST /scans/{id}/fix` is synchronous**, and slower than a scan: verifying
  a fix copies the target and re-scans it twice per finding. Same job model
  `POST /scans` has owed since ADR-0003.
- **`parent_scan_id` is not a database foreign key.** SQLite enforces those
  only with a per-connection pragma, so declaring one would advertise a
  guarantee that is not switched on. The link is maintained by the one module
  that writes it. A real FK belongs with the PostgreSQL move.
- **Derived rows are listed with ordinary scans by default.** Hiding them would
  make a fix pass invisible in the one place an operator looks; `?kind=` narrows
  and every summary carries `kind` and `parent_scan_id`. A long fix history will
  want the dashboard to group by lineage.
- **The backfill parses every un-summarised CBOM once, at init.** One-off and
  bounded by the number of pre-migration rows, but it does make the first open
  of a large legacy database slower than the ones after it.
- **Chains are possible but unexplored.** Nothing stops a rescore of a rescore,
  or a fix against a fix row. The columns permit it; no code walks a lineage
  deeper than one level, and no test covers it.
