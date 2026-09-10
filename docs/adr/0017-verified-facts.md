# ADR-0017: The verified-fact gate — the tool *cannot* score on an unchecked fact

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** verified-fact mechanism + engine pin
**Amends:** ADR-0007 (policy engine), ADR-0008 (Mosca/DST/NIST packs), ADR-0004
(semgrep determinism)

## Context

CLAUDE.md says there are no uncited crypto facts, and ADR-0007 enforced it: a
rule without a `citation` does not load. That gate turned out to check a weaker
property than anyone intended.

**A citation says where an idea came from. It does not say anybody checked it.**

`policy/packs/india_dst.yaml` had impeccable citations — "DST/NQM roadmap (May
2026): quantum-vulnerable cryptography in critical information infrastructure …
carries the earlier 2028 migration deadline" — for four facts that had been
supplied verbatim and encoded verbatim. The pack header said so. PUNCHLIST said
so. And the engine scored them anyway: `dst-cii-priority-migration` was
contributing **20 points of `criticality`** to every Shor-broken component in a
CII sector.

A warning comment does not stop arithmetic. The same is true of
`knowledge/libraries.yaml`, where `pqc_capable_from` was left `null` for GnuTLS
and libgcrypt *by discipline* — nothing prevented a future contributor from
filling in a plausible version and having it silently start driving drift
verdicts.

Two separate problems, one shape: **the honesty lived in prose, and prose is not
enforced.**

## Decision

### 1. Every rule and every scoreable knowledge fact carries `verified` and `source`

```yaml
- id: dst-cii-priority-migration
  effect: { score: 20, category: criticality, deadline: 2028-12-31, ... }
  citation: >-
    DST/NQM roadmap (May 2026): ...          # where the idea came from
  verified: false
  source: >-
    FILL: confirm against the published DST / National Quantum Mission
    post-quantum migration roadmap text, then set verified: true and replace
    this marker with the document, version and section confirmed.
```

`citation` and `source` are deliberately **two fields** because they are two
different claims. `citation` is provenance, required since ADR-0007. `source` is
the record of an act: what somebody actually opened and read. The DST rules
prove the two can diverge completely.

`verified` defaults to **false**. Silence is not verification; a pack author
opts in.

### 2. Only a verified rule may move a number

In `policy/engine.py`, `_scores(rule) -> rule.verified` gates exactly one line:
the `subtotals[category] += contribution`. Everything else an unverified rule
does still happens.

| output | verified rule | unverified rule |
|---|---|---|
| score contribution | added | **zero** |
| fires / `fired_rules` | yes | yes |
| label | `CII` | `CII (provisional -- unverified against source)` |
| deadline | contributes | contributes, `ecdat:deadline_provisional: true` |
| action | as written | prefixed `PROVISIONAL (unverified against source): ` |
| `quantum_status` | asserted | **not asserted** (see below) |
| category | registered | registered at `0` |

**Demoted, never dropped.** Dropping an unverified rule would be the easy
implementation and the wrong one: a fact nobody checked would become a fact
nobody sees, and the DST deadline is genuinely useful information *labelled as
unconfirmed*. `_fires()` is a named function that always returns `True`,
precisely so a mutation test can turn it into dropping and show what would be
lost.

The suffix goes **in the label text**, not only in a sibling property, because
labels are what get copied into a slide, a ticket and an email. The caveat has
to travel with the claim it qualifies.

### 3. An unverified rule may not assert `quantum_status` — closing the laundering path

`quantum_status` is not display. It is a **derived fact** that second-pass rules
select on (`dst-cii-priority-migration` fires on `quantum_status: broken`). If
an unverified rule could assert it, an unchecked fact would move a number
*indirectly* by causing a verified rule to fire — the gate would leak.

So derived facts come only from verified rules. This changes nothing today
(every `quantum.yaml` rule is verified) and closes the hole before somebody
walks through it. `test_an_unverified_rule_cannot_launder_a_score_through_quantum_status`
is the guard.

### 4. A category is registered even when it contributes zero

`criticality=0` appears in `ecdat:category_score` rather than the category
vanishing. "Assessed, contributed nothing" and "never assessed" are different
answers — the same distinction ADR-0016 draws between `NULL` and `[]` for
`scanners_ran` — and a dimension that silently disappears reads as the second
when it is the first.

### 5. `verified: true` without a `source` does not load

A bare `verified: true` would restore scoring while recording nothing, which is
the exact move this gate exists to prevent. It is a `PackValidationError`.

### 6. The knowledge pack gets the same treatment

`libraries.yaml` entries gain `pqc_capable_verified` and `pqc_capable_source`,
and `_is_pqc_capable()` returns `None` — "the pack does not know" — for an
unverified floor. So filling in a plausible version *without* confirming it
produces no `pqc_capable` parameter at all, rather than a drift verdict nobody
checked.

### 7. semgrep is pinned, and the engine that ran is recorded on the scan

`requirements.txt` moves from `semgrep>=1.176,<2` to `semgrep==1.176.1`. A
range made ECDAT's determinism promise a range too: "same input + same knowledge
packs → byte-identical CBOM" depends on the matcher, and the matcher is an
external binary ECDAT does not control.

Pinning alone is not enough — a developer's `PATH` is not `requirements.txt`. So
`store.Scan` gains `engine_versions` and `engine_warning`:

```json
{"ecdat": "0.1.0",
 "source": {"pinned": "1.176.1", "installed": "1.176.1", "matches": true}}
```

A mismatch **warns loudly and does not fail**. Blocking a teammate whose semgrep
is one patch ahead costs more than it buys; what actually matters is that a
surprising detection result can be *traced* to the engine rather than argued
about. The divergence goes to the structured log and onto the row.

Version probing is an **optional capability**, read via `getattr` rather than
added to the `Scanner` protocol: most plugins are pure Python and have no
external engine to pin. Versions are collected from the scanners that *ran*, not
the offered set — a skipped source scanner did not involve semgrep.

## What this cost, measured

This is the number the slice exists to surface, so it is recorded here rather
than in a commit message.

The demo's headline component — RSA-2048, hard-coded, BFSI, internet-facing,
Personal data — **was 98/Critical and is now 78/High.**

| category | before | after |
|---|---|---|
| quantum | 40 | 40 |
| mosca | 28 | 28 |
| exposure | 10 | 10 |
| **criticality** | **20** | **0** |
| **total** | **98 (Critical)** | **78 (High)** |

**20% of a Critical verdict was resting on a fact nobody had looked up.** The
2028-12-31 deadline is still displayed, marked provisional, with the two rules
that produced it named in `ecdat:provisional_rule`.

Criticality remains reachable without any DST fact: quantum 40 + mosca 30 +
exposure 10 = 80, for a Sovereign-classified asset. The headline guard
`test_the_same_algorithm_is_critical_or_medium_by_context` was rebased onto that
case and now additionally asserts `criticality == 0`, so it proves the band
comes from three checked facts and no unchecked one.
`test_the_personal_case_is_now_high_because_dst_demoted` pins the 78 explicitly,
so the cost is a tested fact rather than a memory.

## Consequences

**Good.**

- The honesty guarantee is now **structural**. It is not possible to score on an
  unverified fact by forgetting a comment; it requires editing `_scores()`,
  which two mutation tests defend.
- Restoring a fact is a data change, not a code change: confirm it, write the
  `source`, flip the flag, re-sign. `test_flipping_verified_to_true_makes_the_rule_score_again`
  proves the mechanism is the gate, not a hard-coded skip of DST rule ids.
- Every unverified rule carries a `FILL:` marker naming the document that would
  settle it, so the outstanding work is enumerated rather than remembered.
- A scan can say which engine produced it, which is what the determinism claim
  actually needs.

**Costs and limits, stated plainly.**

- **The demo number went down**, and the India-roadmap pillar currently
  contributes labels and deadlines rather than score. That is the correct state
  of affairs and it is temporary: it is one afternoon with the published roadmap
  away from being restored. It should be said out loud in any demo — the pack
  demonstrates the *mechanism* for roadmap compliance, and the specific dates
  await confirmation.
- **`verified: true` is an assertion by whoever edits the pack.** Nothing checks
  that the `source` string describes a real document, or that the person read
  it. The gate raises the cost of an unchecked fact from "say nothing" to "write
  a specific false citation and sign the pack"; it does not make lying
  impossible. A second reviewer, or a verification date and verifier identity
  per fact, would be the next increment.
- **`dst-aes-128-uplift` is marked unverified too**, though its substance
  (Grover halves AES-128) is verified elsewhere. Its primary citation is the DST
  symmetric-uplift guidance, which is unchecked like the rest of the pack. It
  scores 0 either way, so the conservative default costs nothing.
- **Pinning semgrep exactly will cause friction.** A `pip install -r` on a
  machine with a different semgrep now downgrades it. That is the intended
  trade: reproducibility over convenience, with the mismatch path kept
  non-fatal for people who cannot or should not downgrade.
- **The `ecdat` version is a hard-coded string** in `core/__init__.py`, not
  derived from a tag or a build. It will drift from reality the first time
  somebody forgets to bump it.
- **Nothing surfaces provisional status in the dashboard yet.** The properties
  are on the components and the API serves them, but no view says "this
  deadline is unconfirmed" — which is where a reader would most need to see it.
