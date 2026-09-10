# ADR-0019: The system scan — three views into one CBOM, so drift is real

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** unified system scan
**Depends on:** ADR-0002 (cross-view non-merge), ADR-0010 (the spool seam),
ADR-0012 (the correlator), ADR-0016 (self-describing scan rows)

## Context

Pillar 2 — three-view drift — has been built and tested since ADR-0012, and the
product has never used it.

`run_scan` takes **one target of one kind**. A repo scan produces only
`declared` components; an image scan only `shipped`; a spool scan only
`observed`. The correlator ran on every one of those documents and correctly
found nothing, because **drift is a property of the union, not of any view.** A
config promising a post-quantum group and an image that cannot negotiate one
are each individually unremarkable; only a document containing both is a
finding.

So the one place the three views ever met was `kpi/harness.py`, which merges
three separate scans by hand to make its measurement possible. Drift existed as
a number in a benchmark and as an empty column in the dashboard — not because
the estate agreed, but because nothing ever put the views in the same document.
ADR-0018 had to record that as a limitation of the console; it was never a
console problem.

## Decision

### 1. A system manifest is the primary interface

```yaml
system: quantumbank
sector: bfsi
exposure: internet
data_class: Personal
targets:
  - { kind: repo,  ref: testdata/quantumbank }
  - { kind: image, ref: testdata/quantumbank/images/payments.tar }
  - { kind: spool, ref: testdata/quantumbank/spool }
```

A durable file, checked in beside the system it describes, rather than a
command line somebody has to remember. An estate's shape changes rarely and its
scan should be reproducible by anyone who clones the repo.

**The context is system-level, not per-target.** One system has one sector, one
exposure and one data classification; scoring a component differently depending
on which target it happened to turn up in would be incoherent.

**Paths are used as given**, resolved against the working directory exactly as
`ecdat scan <ref>` does. Manifest-relative resolution would be more portable and
is in PUNCHLIST; using the same convention as every other path was the smaller
surprise.

### 2. Refusals are loud, and they name what was wrong

* An unknown `kind` is a **load error naming the target** — a typo'd
  `contianer` would otherwise drop the entire shipped view and leave a CBOM
  that looks complete.
* An unknown `sector` is refused rather than defaulted to `other`. Silently
  defaulting would under-score an entire CII estate with nothing in the output
  to say why.
* A **missing target fails the scan**, naming it. Degrading to "we scanned what
  we could" produces a document that looks like an inventory and is silently
  missing a view.

A broken **scanner** still degrades rather than aborting — the orchestrator's
existing discipline (ADR-0003). The distinction is deliberate: a missing target
is an operator error the operator can fix, and a plugin falling over on hostile
input is a Tuesday.

### 3. ONE normalisation over ALL the findings

Not three normalisations merged afterwards, which is what the KPI harness does.
Merging documents leaves de-duplication per-target, so two targets producing the
same artefact would yield two components sharing a `bom-ref` — an invalid CBOM
and a correlator seeing double. Normalising once makes identity global and
uniqueness structural.

**The system root is the first `repo`/`directory` target in manifest order.**
Identity folds in an artefact's path relative to the target root, so this is
what keeps a component's `bom-ref` **identical** between `ecdat scan <repo>` and
`ecdat scan-system`. A different root would give the same artefact two
identities depending on which entry point found it, and nothing would say so.

**The cross-view non-merge from ADR-0002 still holds**, and is now load-bearing
rather than theoretical: the declared `X25519MLKEM768` and the observed
`x25519` stay two components. Merging them would destroy the exact disagreement
the correlator exists to find.

The document also gains `metadata.component`, naming the system it describes —
the correlator groups on it, and a CBOM that cannot say what estate it is about
is one nobody can file. Written in `scan_system` rather than the normaliser so
single-target CBOMs keep their existing bytes.

### 4. The observed view is a committed spool fixture

`scan-system` reads `testdata/quantumbank/spool/`, which is checked in. That
makes a system scan **deterministic, offline and root-free** — three properties
the scan path has everywhere else and would lose the moment it needed an eBPF
attach.

The live agent stays exactly where it is: `make prove-pillar2`, a separate
showpiece that needs `sudo`. A scan must never ask for privileges, and a demo
must never depend on a uprobe attaching on someone else's kernel.

**The spool is copied into the scratch directory before it is read.** The
runtime-spool scanner moves what it ingests into `consumed/` (ADR-0010), which
is right for a live seam and would eat a committed fixture the first time
anybody ran a system scan — the observed view would silently vanish on the
second run. A test asserts the fixture survives.

### 5. Synchronous

It runs the scanners and returns. The job model `POST /scans` has owed since
ADR-0003 is still owed and a system scan wants it more — QuantumBank takes ~1.5s
but a real estate will not. Deferred deliberately rather than half-built.

### 6. One validator, shared by the CLI and the API

`POST /systems/scan` types `kind`, `sector` and `exposure` as plain strings and
lets `core.system.parse_manifest` do the checking. A pydantic `Literal` would
refuse a bad `kind` with FastAPI's own 422 *before* ECDAT's validator ran —
two validators that can disagree, and a manifest that loads from a file but not
from the API. One validator, one message, identical refusals from both.

## Consequences

**Good.** On `testdata/quantumbank/system.yaml`:

```
scan_id=0b7f919c system=quantumbank targets=3 component_count=26 drift_count=6
  drift cipher-outside-declared-set=2
  drift declared-pqc-observed-classical=2
  drift shipped-cannot-do-declared=2
```

26 components across all three views (17 declared, 4 shipped, 5 observed), and
the headline drift on the endpoint the demo turns on:

| kind | endpoint | declared | observed |
|---|---|---|---|
| `shipped-cannot-do-declared` | `payments…:443` | X25519MLKEM768 | OpenSSL 3.0.2 (not PQC-capable) |
| `declared-pqc-observed-classical` | `payments…:443` | X25519MLKEM768 | x25519 |

`GET /scans` reports `drift_counts` summing to 6, so the console's DRIFT metric
and its "Drift only" filter finally have something to show. A control test
asserts a single-target scan still finds **no** drift — if that ever changes,
the correlator has started inventing comparisons out of one view.

**Costs and limits.**

- **Synchronous.** ~1.5s on QuantumBank; a real estate will need the job model.
- **`kpi/harness.py` still merges by hand.** It predates this module and does
  the same thing worse. It should be rewritten on top of `scan_system` — which
  would also let the KPI measure the code path the product actually runs. Not
  done here to keep the KPI's numbers comparable across this change.
- **Paths are working-directory relative**, so a manifest is only runnable from
  the repository root. Manifest-relative resolution is the better default and
  would change every committed ref; deferred.
- **The system root is "the first path target"**, which is unambiguous for one
  repo and arbitrary for two. A manifest with several checkouts would want an
  explicit `root:` key.
- **The observed view is a fixture, not a measurement.** The committed spool is
  a recording of one real handshake; a system scan does not observe anything
  live, and must not be presented as though it does. `make prove-pillar2` is
  where the live claim lives.
- **Drift on `legacy:8443` is still unattributable** (ADR-0012/0014): the
  observed view carries no endpoint, so a handshake wildcard-joins every
  declared endpoint in the system. Two of the six drifts here are that known
  consequence, and the console shows them like any other. Socket-level
  attribution in the probe is the fix, and it is still owed.
