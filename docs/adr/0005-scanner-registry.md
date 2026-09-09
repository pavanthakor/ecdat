# ADR-0005: A scanner registry, and the end of the stub

* Status: accepted
* Date: 2026-09-09
* Slice: scanner registry / stub retirement
* Extends: [ADR-0001](0001-architecture.md) (scanner contract),
  [ADR-0003](0003-scan-pipe.md) (the pipe), [ADR-0004](0004-source-scanning-semgrep.md)
  (Scanner A)

## Context

`scanners/stub` existed to prove the pipe before any detection did. It returned
one hand-written RSA-2048 finding for every target. Scanner A landed in
ADR-0004, so its reason to exist is gone.

Deleting it was awkward for a reason worth fixing rather than working around:
**which scanners run was written down twice**, once in `api/app.py` and once in
`cli.py`, each as a literal list. With six scanner families planned (source,
deps, container, binary, runtime, network), that is five more chances for the
two lists to disagree — and a disagreement is silent. The CLI would find crypto
the API did not, and the only symptom would be a CBOM that looks complete.

## Decision

### One list, in `core/registry.py`

A `Registry` holds `id -> Scanner`. The module exposes `register`,
`get_scanners(ids)` and `available_ids()` over a process-wide default instance.
The built-in scanners are registered at the bottom of the file, under a comment
saying so.

**Adding a scanner is one import and one `register(...)` line. Nothing in
`api/` or `cli.py` changes.** That is the whole point of the module and the
property the next five slices depend on.

### Registration is an explicit call, not discovery

No entry points, no `pkgutil` walk, no import-time side effect buried in a
package `__init__`. A call is visible to mypy — so a plugin that does not
satisfy the `Scanner` protocol fails typechecking rather than at scan time —
and visible to a reader, who can answer "what runs?" from one block. Plugin
discovery buys third-party extensibility this project does not have and costs
the traceability it does.

### `core` imports `scanners`, deliberately

`core/registry.py` is the only module in `core` that imports from `scanners`.
That inversion *is* the registry: it is the wiring layer, so the wiring lives in
one place. The constraint ADR-0001 actually cares about still holds — no
scanner imports the orchestrator, so the scanners package stays independently
testable.

### `None` means all; `[]` means none

`get_scanners(None)` returns everything registered — the default for a scan.
An explicit list selects a subset. An explicit **empty** list selects nothing
and is honoured as written rather than being treated as "unset", so
`{"scanners": []}` is a scan that runs no plugins rather than a scan that
quietly runs all of them.

### Results are always id-sorted

Whatever order a caller lists ids in, and whatever order registration happened
in, `get_scanners` returns them sorted and de-duplicated. A CBOM must not
depend on how a request was phrased.

### An unknown id is refused, not ignored

`UnknownScannerError` from the registry becomes a 400 in the API and exit code
2 in the CLI, and the message names both the bad id and the available ones.
Silently narrowing the scanner set would still produce a valid CBOM, and that
CBOM would look like a complete inventory of an estate that had never been
fully scanned. Refusing is the safe failure.

### Duplicate ids are refused

Every `Finding` carries `scanner_id` so a claim traces back to its producer.
Two plugins under one id would misattribute evidence, so the second
registration raises rather than overwriting.

## Consequences

* `POST /scans` accepts an optional `scanners: [ids]`; `GET /scanners` lists
  what is available, so the dashboard does not need its own copy of the list.
  `--scanner ID` (repeatable) and `--list-scanners` do the same for the CLI.
* **The API's `get_scanners` FastAPI dependency is gone.** Scanner selection is
  resolved inside the handler from the request body, so
  `app.dependency_overrides` can no longer be used to swap the scanner set. No
  test used it, and selecting via the `scanners` field exercises the real path
  instead of bypassing it.
* **Test scanners moved into the tests.** The orchestration tests needed "a
  scanner that yields one predictable finding", which is what the stub was
  really being used for. That is now a `FixedScanner` inside
  `tests/test_orchestrator.py`, where a test double belongs — not a package
  shipped in `scanners/`.
* **The end-to-end pipe test now runs a real scan.** It was repointed to the
  source scanner over `testdata/minimal_repo` (two crypto call sites, so exact
  component counts stay assertable) rather than deleted with the stub. The API
  and CLI tests were repointed the same way, which also fixed a latent oddity:
  they had been "scanning" `/srv/quantumbank`, a path that does not exist and
  that the stub never looked at.
* `tests/test_registry.py` parses the AST of every module in the repo and fails
  if anything imports `scanners.stub` again. It caught a stale
  `scanners/stub/__pycache__` that `git rm` left behind.
* **The registry is not yet a scan-time record.** Which scanners ran is in the
  structured log but not in the stored scan row, so "was this estate scanned
  for binaries?" cannot be answered from the database. Punchlisted.

## Alternatives considered

* **Entry-point / `importlib.metadata` discovery.** Rejected: invisible to
  mypy and ruff, and it makes "what runs here?" a runtime question. ECDAT has
  no third-party plugin story to justify the cost.
* **A `SCANNERS` list constant in `core/scanner.py`.** Simpler, but it puts a
  concrete dependency on `scanners.*` into the module that defines the
  protocol, and it gives no place for id lookup, validation or error messages.
* **Leaving the lists and just deleting the stub.** Rejected: it removes the
  symptom and keeps the cause, and the cause gets worse with every scanner
  family added.
