# ADR-0003: The scan pipe — failure isolation, verbatim storage, portable schema

- Status: accepted
- Date: 2026-09-08
- Slice: Phase 0 — orchestrator, store, API, stub scanner
- Follows: [ADR-0001](0001-architecture.md), [ADR-0002](0002-cbom-normaliser.md)

## Context

ADR-0001 fixed the pipeline's shape and ADR-0002 built the normaliser. This
slice joins them into something that runs: select scanners, collect findings,
normalise, persist, serve. Doing that forces three decisions that will be
expensive to change once six scanner families exist.

## Decision

### 1. A broken plugin degrades a scan; a bad CBOM aborts it

The orchestrator draws a hard line between two kinds of failure:

- **A scanner raising is an expected condition.** Scanner plugins parse hostile
  input — other people's binaries, container layers, packet captures. One of
  them falling over on a malformed ELF header must not cost the operator the
  other five families' results. The failure is caught, logged with the plugin
  id, phase, exception type and message, and the scan continues.
- **A normalisation or validation failure is a real failure.** It means ECDAT
  itself produced something that is not a valid CycloneDX 1.6 document. There is
  nothing partial to salvage, so it propagates and nothing is written to the
  store. `run_scan` deliberately has no `try` around `normalise`.

`supports()` is guarded too: a plugin that cannot even decide whether it
applies is broken in the same way, and is skipped rather than allowed to abort.

**Findings yielded before a scanner died are kept.** A scanner is a generator,
so it can fail halfway. Evidence it already produced is real evidence, and
dropping it would violate ADR-0001's "nothing silently dropped". The truncation
is visible instead: the `scanner_failed` event carries `findings_kept`.

Every run logs `scanners_ran`, `scanners_failed` and `scanners_skipped`, so
"the CBOM looks thin" is always answerable from the log.

### 2. The CBOM is stored as text and served verbatim

`Scan.cbom_json` is a `Text` column holding the exact string the normaliser
produced. It is not decomposed into rows, and `GET /scans/{id}/cbom` returns it
through a raw `Response`, never through FastAPI's response model.

This is not laziness. ADR-0002's guarantee is about *bytes*: the same input
produces a byte-identical document, and the golden test asserts exactly that.
Re-encoding through any JSON serialiser — different key order, different
separators, different float formatting — would silently break that guarantee at
the API boundary, which is precisely where a consumer would diff two scans to
find drift.

The relational columns beside it (`target_*`, `created_at`, `component_count`)
exist for listing and filtering only. `component_count` is derived from the
stored document rather than passed in, so it cannot disagree with it.

### 3. The schema is written for PostgreSQL, run on SQLite

SQLite is the demo-friendly default; an estate-scale deployment will want
PostgreSQL. Nothing in `core/store.py` blocks that move: ids are
application-generated UUID strings rather than `AUTOINCREMENT`, timestamps are
timezone-aware UTC, the document lives in a plain `Text` column, and there are
no SQLite-only constructs. The only SQLite-specific line is the URL built in
`database_url()`.

Engines are cached per URL rather than created once at import, so repointing
`ECDAT_DB` takes effect — which is what lets every test run against its own
temporary database, enforced by an autouse fixture so no test can reach the
developer's real `ecdat.db`.

### 4. Structured logs go to stderr, the CBOM goes to stdout

One JSON object per line, every record carrying an `event` name. stderr, not
stdout, because the CLI writes the CBOM to stdout and a log line in the middle
of the document would corrupt it. `ecdat scan . > cbom.json` therefore produces
a file containing only the document, while the operator still sees the summary.

## Consequences

Good:

- A new scanner is still purely additive, and a buggy one is contained.
- Drift detection can diff two stored documents byte-for-byte, because the API
  hands back the same bytes the normaliser produced.
- Moving to PostgreSQL is a URL change plus a migration, not a rewrite.

Costs, accepted:

- `POST /scans` runs the scan synchronously. Fine for a stub; a real repo or
  image scan will hold the request open. Needs a job model. See PUNCHLIST.
- The API has no authentication and `GET /scans` is unpaginated, though it
  serves an estate's full cryptographic inventory. See PUNCHLIST.
- `list_scans()` orders by `(created_at DESC, id DESC)`. The id tiebreak makes
  the order total, but two scans committed within the same microsecond would
  order by UUID rather than by insertion. Acceptable until scans are batched.
- A scanner that fails *every* time still produces a scan, just a thinner one.
  That is the intended trade; the log is what makes it visible, so whatever
  consumes these logs has to actually surface `scanners_failed`.

## Alternatives rejected

- **Let a scanner failure abort the scan.** Simple and loud, but it makes the
  whole tool only as reliable as its least reliable parser. Rejected.
- **Swallow normalisation failures too, and store what we can.** Would put
  documents in the store that are not valid CBOMs, so every downstream consumer
  would have to re-validate. Rejected — it inverts ADR-0002's guarantee.
- **Discard findings from a scanner that died mid-iteration.** Cleaner to
  reason about, but it silently throws away real evidence. Rejected in favour of
  keeping them and reporting the truncation.
- **Store the CBOM decomposed into component/evidence tables.** Better for
  queries, but then the served document is a reconstruction, and byte-level
  determinism is gone. The right time for that is when the API needs to query
  *inside* the CBOM — and then it is an index alongside the text, not a
  replacement for it. Rejected for now.
