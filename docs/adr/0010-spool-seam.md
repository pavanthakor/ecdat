# ADR-0010: The spool seam — observed findings reach the store

* Status: accepted (root-free half proven; agent-to-spool half awaits a human run)
* Date: 2026-09-09
* Slice: the spool seam (Pillar 2; precondition for the correlator)
* Extends: [ADR-0001](0001-architecture.md) (scanner contract),
  [ADR-0002](0002-cbom-normaliser.md) (cross-view non-merge),
  [ADR-0005](0005-scanner-registry.md) (registry),
  [ADR-0009](0009-ebpf-agent-slice1.md) (the agent)

## Context

ADR-0009 proved a uprobe attaches and delivers events. The findings then went to
stdout and nowhere else, so the `observed` view existed but could not reach the
CBOM — and the correlator, which is the entire point of three views, had nothing
to correlate against.

The gap is a process boundary with a privilege drop across it. The agent must be
root: eBPF attach needs it. The scan path must not be: everything else in ECDAT
runs as an ordinary user against files, deliberately.

## Decision

### A file spool, not authenticated HTTP

The obvious design is `POST /findings`. Rejected, for three reasons that
compound:

* **It requires the sensor to hold a credential.** A root process with an API
  token is a root process whose compromise is also a compromise of the
  inventory. The whole reason the scan path is unprivileged is to keep the
  blast radius of each part small, and handing the privileged part a key
  undoes it.
* **The API has no authentication** (PUNCHLIST), so the alternative today is an
  *unauthenticated* write endpoint that anything on the host can post findings
  to. That is worse than no transport.
* **It is a network call in a system that is offline by construction.** CLAUDE.md
  makes the scan path air-gapped; adding a socket for internal traffic is the
  kind of exception that stops being an exception.

A directory needs no credential, no listener and no port. The **filesystem is
the producer/consumer trust boundary**, enforced by ownership and permissions
the operating system already checks. Production HTTP transport, for the
distributed case, is a later slice and is punchlisted.

### The spool is a SCANNER, not a service

`scanners/runtime_spool` is an ordinary plugin with `id="runtime-spool"` and
`view="observed"`, registered with one line. That reuses the Finding contract,
the registry, the orchestrator's per-plugin isolation, the policy pipeline and
the store — and, more importantly, means **there is no second way for a finding
to enter the system.** A parallel ingest path would be a parallel set of
validation rules to keep in step.

`Target` gains `kind="spool"` rather than the scanner special-casing a
directory. Routing is then exclusive in both directions and testable: the source
and container scanners decline a spool target, and the spool scanner declines
everything else.

### Atomic by temp-and-rename, guarded twice

The producer writes `.tmp-<uniq>.partial` and `os.rename`s it into place.
Rename within a directory is atomic on POSIX, so a consumer polling a directory
it does not coordinate with can never observe a half-written record. The file is
`fsync`ed before the rename, or a crash could rename an empty inode into place —
readable, and partial, which is exactly what the dance exists to prevent.

An in-progress file is excluded by **two independent guards**: the `.tmp-`
prefix *and* not ending in a spool suffix. `pathlib.Path.glob("*.jsonl")`
matches dotfiles, unlike a shell glob, so a temp file named `.tmp-x.jsonl` would
be picked up by any consumer reaching for the obvious pattern. Two guards means
getting this wrong takes two mistakes. (A test caught exactly this.)

Filenames are `<host>-<pid>-<timestamp_ns>-<seq>`: unique across hosts,
concurrent agents and re-runs, so a later record can never overwrite an earlier
one the consumer has not read. The nanosecond timestamp makes filename order
arrival order, which is what makes ingest deterministic.

### Move to `consumed/`, and `rejected/` for bad producers

An ingested file is renamed into `consumed/`. Re-scanning finds nothing new, so
ingest is idempotent — **double-counting an estate's cryptography is worse than
missing some, because it looks like growth.** The file is moved, not deleted:
the raw record is the evidence behind the finding.

A file that yields *no* valid findings moves to `rejected/` and is counted. A
producer emitting nothing usable is a fact about the estate; deleting the
evidence would make it a blind spot nobody knows they have.

A name collision in either directory gets a numeric suffix rather than a
clobber, because two agent runs can legitimately produce the same filename.

### Untrusted input by construction

The producer is a root process decoding kernel perf buffers, so a truncated or
malformed line is a question of when, not if. A bad line costs one line, is
logged with a reason, and is counted; the good lines in the same file still
ingest. The mapping is `agent.to_finding.event_to_finding` — the same function
the agent uses for `--findings`, so producer and consumer cannot disagree about
what an event means.

`agent/spool_format.py` holds the three things both halves must agree on (temp
prefix, temp suffix, spool suffixes, filename scheme). It imports nothing, so
the agent can still import it on the system interpreter where bcc lives and
pydantic does not (ADR-0009).

### The spool is chowned to the invoking user

The agent is root, but the consumer must not be — and the consumer has to *move*
files into `consumed/`, which needs write permission on the directory, not just
the files. A root-owned spool would mean the only way to ingest it is to run the
scan as root too, dragging privilege back into the part of the system kept
clear of it. So under `sudo` the agent chowns the spool and its records to
`SUDO_UID`. Best-effort and silent when not running under sudo.

### The proof is deliverable one

ADR-0009's lesson, applied rather than restated: `scripts/prove_pillar2.sh`
(`make prove-pillar2`) runs the whole chain in one command — agent attaches and
handshakes as root, drops to the invoking user to scan the spool, prints the
observed component. Nothing to sequence, so "it does not work" and "we ran it
wrong" cannot be confused.

## Consequences

* **This unblocks the correlator.** All three views can now land in one store,
  and `test_three_views_of_one_algorithm_stay_three_components` proves ADR-0002's
  cross-view non-merge holds with real declared, shipped and observed findings
  rather than hand-built ones. That is the correlator's input, available now.
* Observed findings flow through the policy engine like any other, so a runtime
  TLS observation gets a band, a deadline and a Mosca term for free.
* **Occurrences on one host merge to one artefact.** `_drop_position` strips
  `:pid<N>` for the observed view, so handshakes in two processes become one
  "TLS on host X" component with both occurrences retained as evidence. That is
  ADR-0002's existing design and it is right for an inventory — a PID is
  ephemeral and is not a distinct cryptographic artefact — but it means per-
  process attribution lives in the evidence, not in the component list.
* The spool grows without bound: `consumed/` and `rejected/` are never pruned.
  Fine for a demo, wants a retention policy. Punchlisted.
* Enrichment is still pending: observed findings carry `pending_enrichment`
  because the probe does not yet read the negotiated version and cipher
  (ADR-0009). The seam carries them the moment slice 2 fills them in — a test
  pins that today with a synthetic enriched event.

## Alternatives considered

* **`POST /findings` with a bearer token.** The natural design for the
  distributed case and the wrong one for now: see above. It is the later slice,
  not the discarded option.
* **A Unix domain socket.** No credential and no port, but it needs the
  consumer to be running when the agent observes. A spool decouples them in
  time, which matters when the agent runs continuously and scans are periodic.
* **The agent writing to SQLite directly.** Skips the seam entirely and puts a
  root process inside the store's schema, with two writers and no validation
  boundary. The Finding contract exists precisely to avoid that.
* **Deleting consumed files.** Simpler, smaller, and throws away the raw
  evidence behind every observed finding the moment it is used.
