# ADR-0033: The source scanner tolerates unparseable files — and says which

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** source scanner resilience (Tier-2 robustness)
**Depends on:** ADR-0003 (one broken input must not end the batch), ADR-0004
(the semgrep source scanner), ADR-0016 (coverage told honestly), ADR-0025 (the
binary scanner's coverage report)

## Context

Scanning OWASP Juice Shop, the source scanner raised `SemgrepOutputError` on
`data/static/codefixes/registerAdminChallenge_*.ts`. Those are intentionally
malformed TypeScript challenge snippets. The source scanner kept **zero**
findings, and the whole codebase yielded one dependency finding.

The orchestrator's plugin isolation did what it was built to do: it logged the
source scanner as failed and stored the scan. That produced the worst possible
result. The inventory was nearly empty and still looked like a result.

Real repositories almost always contain something unparseable: generated code,
vendored junk, broken-on-purpose fixtures. As written, ECDAT was nearly blind on
exactly the codebases it is for.

## STEP 0 — what semgrep 1.176.1 OSS actually does (measured, not assumed)

Each case ran with the scanner's exact command line against the full rule
pack:

| Case | Exit | Results | `errors[]` |
|---|---|---|---|
| valid crypto `.ts` + broken `.ts` | **0** | the valid file's finding | `type: "Syntax error"`, `level: warn`, `path` = the broken file |
| every file broken | 0 | none | the same, per file |
| valid + broken, with `--strict` | **3** | the valid file's finding | the same |
| a schema-invalid rule in the pack | **7** | none | `InvalidRuleSchemaError` + `SemgrepError`, both `level: error` |
| a missing config path | **7** | none | `SemgrepError`, `level: error` |
| Python or Java: crypto, then a hard break | 0 | **none from that file** | `"Syntax error"` — the whole file is rejected |
| Go or TS: crypto, then a break | 0 | **the crypto is returned** | `type: ["PartialParsing", [locations]]` — a *list*, not a string |

What that means:

1. **Semgrep already skips an unparseable file.** It exits 0 and returns the
   good files' results. ECDAT's `_parse_semgrep_json` treated *every* entry in
   `errors` other than a Timeout as fatal, raised, and threw away results
   semgrep had already produced. The blindness was ours.
2. **No flag does better than the default.** `--strict` makes it worse
   (exit 3). The command line is unchanged.
3. **`paths.scanned` lists files that failed to parse.** Coverage must come
   from the errors. Believing "scanned" would record a file nobody read as a
   file that came back clean.
4. **There are two outcomes, not one.** Some files are rejected whole
   (`Syntax error`, and nothing can come from them). Others parse partially
   (`PartialParsing`): findings from the readable part are real, and the rest
   is unexamined.
5. **Semgrep's parsers sometimes recover silently.** They report no error and
   still produce findings. Two of this slice's first "unparseable" Python
   fixtures (`def f(:` over a valid body line) turned out to be exactly that.
   Semgrep found their crypto and said nothing. ECDAT can only report the gaps
   semgrep reports.
6. **Real failures are distinguishable two ways.** They exit 7, and they
   report `level: error`.

## Decision

### 1. Tolerate exactly one thing: a per-file parse error

An error is tolerated only when **all three** hold:

- it has `level: warn`;
- its type is on an allowlist: `Syntax error`, `Lexical error`,
  `Other syntax error`, `AST builder error`, or `PartialParsing` (read from
  the list form);
- it names a file.

The list is an **allowlist on purpose**. An error type nobody listed fails
loud; it is never quietly skipped. STEP 0 observed two of the five names. The
other three are the same family in semgrep's output schema. If one were
misspelt here, the cost would be a loud failure, never a silent skip.

Everything else keeps failing loud, unchanged:

- an `error`-level entry, an unknown type, or an error that names no file
  raises `SemgrepOutputError`;
- an exit code outside 0 and 1 (a broken rule pack or missing config exits 7)
  raises `SemgrepFailedError`;
- a missing binary raises `SemgrepUnavailableError`.

Timeouts keep their existing treatment (tolerated), which PUNCHLIST now
records as silent.

### 2. Two gap kinds, one per file

`unparsed` means nothing could come from the file. `partially-parsed` means
its findings are kept and the rest went unexamined. If semgrep reports a file
both ways, `unparsed` wins.

### 3. A per-scan coverage log on the context, not on the scanner

The `Scanner` protocol yields findings, and a file that could not be read is
not an artefact. Inventing a component for it would inflate every count.

So `ScanContext` gains `coverage: CoverageLog | None`. `run_scan` and
`scan_system` hand every scan a **fresh** log (`dataclasses.replace`). The
registry's scanner instances are process-wide, and FastAPI runs sync endpoints
on a threadpool. A list stored on the scanner would let two concurrent scans
share their gaps.

The field is excluded from equality and hashing. `None` means nobody is
collecting: the scanner still logs what it skipped, but has nowhere durable to
record it.

### 4. The gap goes into the CBOM as metadata

| property | value |
|---|---|
| `ecdat:coverage:unparsed` | count of unparsed files |
| `ecdat:coverage:unparsed:file` | one entry per unparsed file |
| `ecdat:coverage:partially_parsed` | count of partially parsed files |
| `ecdat:coverage:partially_parsed:file` | one entry per partially parsed file |
| `ecdat:coverage:source:examined` | files the source scanner examined, readable or not |
| `ecdat:coverage:note` | e.g. "*source: 2 of 5 files examined could not be parsed and 1 was only partially parsed; findings from what could not be read are absent, not clean.*" — or, when nothing parsed, "*source: nothing could be parsed — 2 of 2 files examined failed to parse, so this document says nothing about them. It is not a clean result.*" |

These properties are written **only when a gap exists**, so every existing
document keeps its bytes. Gaps are folded into the content serial number, again
only when present: a document that says two files could not be read is a
different document. CycloneDX keeps these in a sorted set, so the order is
deterministic.

### 5. Logged as well as recorded

The scanner emits a `source_files_unparsed` warning with the counts, and the
paths up to 20. `scan_completed` gains `files_unparsed` and
`files_partially_parsed`.

### 6. The same discipline as the rest of the tool

This is ADR-0003's rule — one bad input degrades a scan, it does not end it —
applied *inside* the source scanner. It is also ADR-0025's rule: what could not
be read is reported separately from what was found.

## Consequences

**Good.**

- A Juice-Shop-shaped repository scans. Every parseable file's findings come
  back, the broken files are named in the stored document, and a repository
  where nothing parsed says so rather than looking clean.
- Real engine failures are still loud. A missing binary and a broken rule pack
  both raise, and neither is recorded as a skip. A table-driven test pins the
  boundary from both sides.
- The clean packs are unchanged at exactly 1.0 recall and precision: Python,
  Go, JS/TS and Java answer keys, and the QuantumBank KPI. Each is held at
  `== 1.0` in `tests/test_source_resilience.py`, whatever floor its own
  module still carries.
- 25 tests; the red run was 18 failed / 6 passed. The six that passed before
  are the fail-loud boundary cases and the no-metadata guard, which exist to
  stop the fix over-tolerating.

**Costs and limits.**

- **The console and the coverage PDF do not read the new metadata yet.** A scan
  in which nothing parsed still *looks* empty in the Inventory and Scans
  screens and in the PDF. The document says otherwise; the surfaces do not.
  PUNCHLIST.
- **Silent parser recovery is invisible** (STEP 0, point 5).
- **Timeouts stay tolerated and unrecorded**, as they were before this slice.
- **Gap paths use semgrep's spelling**, which is the same spelling the
  findings' evidence uses. They are relative when the target is given
  relatively, absolute when it is given absolutely.
- **Only the source scanner records gaps.** The binary scanner logs
  `binary_unparseable` and continues; that does not reach the document yet.
