# ADR-0012: The correlator and three-view drift detection

* Status: accepted — **completes Pillar 2**
* Date: 2026-09-09
* Slice: correlator + drift detection
* Extends: [ADR-0002](0002-cbom-normaliser.md) (cross-view non-merge),
  [ADR-0010](0010-spool-seam.md) (observed reaches the store),
  [ADR-0011](0011-enrichment.md) (observed carries real version/cipher)

## Context

Every slice so far was building toward one question: **does what a system
declares match what it ships and what it actually does?** ADR-0002 kept the
three views deliberately separate so their disagreement would survive; ADR-0010
got all three into one store; ADR-0011 gave the observed view real negotiated
values. This is where they are joined.

## Decision

### A post-policy CBOM pass, not a scanner

The correlator reads components and captures nothing — every fact it uses was
put there by a scanner. It runs **after** policy scoring and **before** the
store, because drift is a statement about components that *amends their score*,
so it has to see the verdict it is raising. A stored CBOM therefore carries
findings, verdicts and drift together.

It is not a `Scanner` because it has no target: it is a pass over a document,
not a probe of a thing.

### Config-declared ↔ observed is the primary axis

A config file says what a service should negotiate; a handshake says what it
did. That is the story, and both are endpoint-oriented, so they correlate on
`(system, endpoint, role)`.

**Source-code declared findings are a SECONDARY signal.**
`rsa.generate_private_key` in `app/keys.py` is not attached to a listening
socket. It correlates on `(system, role)` and answers a different question —
declared versus *shipped* — rather than the config-versus-runtime one.

A view that names no endpoint (the observed view does not: a uprobe sees a
process, not an nginx server block) joins every endpoint in its system. That is
a deliberate over-join, and its limit is stated: when a system exposes several
endpoints with **different** configurations, an unattributed observation cannot
be assigned to one of them. Punchlisted.

**Components sharing no key are simply uncorrelated** and reported as coverage.
A join invented to produce a comparison is a comparison nobody should believe.

### Four rules, and R1 leads

| | Rule | Needs |
|---|---|---|
| **R1** | shipped-cannot-do-declared | declared + shipped |
| R2 | declared-pqc-observed-classical | declared + observed |
| R3 | protocol-downgrade | declared + observed |
| R4 | cipher-outside-declared-set | declared + observed |

**R1 leads because it is the most reliable finding in the tool.** A config
asking for `X25519MLKEM768` against a shipped OpenSSL 3.0.2 is provably broken
from the image alone — no handshake to catch, nothing running, no timing. It
uses the real facts ADR-0006 measured: `ubuntu:22.04` ships libssl3 3.0.2 and
`alpine:3.22` ships 3.5.7, against the 3.5.0 ML-KEM floor in
`knowledge/libraries.yaml`.

R1 is also careful about *not knowing*: the library pack leaves `pqc_capable`
**absent** where it has not verified a floor (GnuTLS, libgcrypt — ADR-0006), and
absent must not read as incapable. No flag, no finding.

### Missing view = coverage gap, never drift

Telling an operator their config disagrees with runtime when there **is** no
runtime observation is the fastest way to make the whole report ignorable.
Absence is reported as absence: `ecdat:coverage:views` and
`ecdat:coverage:missing` are written whether or not anything drifted, because
"they agree" and "we did not look" are different answers and a dashboard must
be able to tell them apart.

### A partial observation yields a weaker claim, not a hard one

When the process never asked libssl which group it negotiated (ADR-0011's
coverage limit), the finding is
`declared-pqc-observed-unconfirmed` at confidence 0.5, whose cause says in as
many words: *this is NOT evidence of a downgrade — it is evidence the
configuration is unverified at runtime.*

Calling that a downgrade would be a false positive, and one false positive of
this kind teaches an operator to disbelieve the entire report. The confidence
gap between 1.0 and 0.5 is what keeps the two distinguishable downstream, and a
test asserts a partial can never produce the hard kind.

### Peer attribution comes from the evidence, not the identity

ADR-0002's `_drop_position` folds a client and a server on one host into one
component — correct for an inventory, since a PID is not a distinct
cryptographic artefact. So "the *server* negotiated classical" is read from the
occurrence detail (`:: nginx via libssl`) and written as `ecdat:drift:peer`,
rather than being forced into the component key.

### The drift effect: ×1.25 and a floor of High

A drifted component's score is multiplied by 1.25 and its band floored to
**High**, because **an inventory error is worse than a known weakness.** A
documented RSA-2048 is something you can plan a migration around; a system that
says it negotiates ML-KEM and does not is a system whose *entire inventory* is
now suspect — you cannot plan around a description that is wrong, and you do not
know what else is wrong.

The two halves do different jobs. The multiplier keeps ordering sensible: a
serious artefact that also drifts outranks a trivial one that does. The floor is
the load-bearing half — the multiplier alone would leave a Low component Low,
and a wrong description of a low-risk asset is still a wrong description. A test
asserts a score-4 component that drifts still reaches High.

### Determinism

Byte-stable and idempotent, like `policy.apply`. Three things had to be pinned,
and each was a real bug caught by the shuffle test:

* components **within** a correlation group are sorted, or evidence order
  follows the order scanners happened to emit them;
* drifts per component are sorted by `(kind, declared, observed)`;
* the component array itself is sorted by `bom-ref` before serialising —
  `sort_keys` sorts dict keys, not list elements. This preserves the
  normaliser's own identity ordering.

Idempotency needed care: re-running must score from the **original** score, not
the already-raised one, or the multiplier compounds. `ecdat:drift:pre_drift_score`
is read back before stripping for exactly that.

## Consequences

* **Pillar 2 is complete.** Declared, shipped and observed now correlate into
  named drift with a cause, a confidence and evidence from each contributing
  view.
* `GET /scans` carries `drift_counts` by kind and `coverage_gaps`.
* **There is no config scanner yet.** The primary axis needs config-declared
  components (nginx.conf, sshd_config, a TLS terminator's settings) and nothing
  produces them: the source scanner emits source-code declared, which this ADR
  classes as secondary. The correlator works on whatever components exist, and
  the tests supply config-declared components in the shape a config scanner
  will emit — but until that scanner is written, R2/R3/R4 have no producer for
  their declared side in a real scan. **Punchlisted, and the largest gap
  remaining in Pillar 2's story.**
* Drift is written as `ecdat:drift:*` properties rather than by splicing
  foreign-view occurrences into the affected component's evidence. That was the
  frame's suggestion and it would make `ecdat:view` a lie — a declared
  component's evidence is what the *declaring* scanner saw. The contributing
  sightings are cited as `ecdat:drift:evidence` = `view|locator` instead.

## Alternatives considered

* **Correlate by merging components across views.** The obvious thing, and
  precisely what ADR-0002 refuses: merging destroys the disagreement.
* **A `Scanner` plugin for correlation.** It would inherit the registry, and it
  has no target to scan and must run after policy — the plugin contract fits
  badly enough that pretending would cost more than it saves.
* **Drift as new synthetic components.** Cleaner separation, and it doubles the
  component count and detaches a drift from the artefact it is about. Properties
  on the affected component keep the two together.
* **Emitting drift when a view is missing, at low confidence.** Rejected
  outright. It is the failure mode most likely to make the tool ignored.
