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

## What this cost, and what confirming it gave back

The mechanism landed with every DST fact demoted, and the cost was immediate
and measurable: the demo's headline component — RSA-2048, hard-coded, BFSI,
internet-facing, Personal data — **dropped from 98/Critical to 78/High**,
because `criticality` went from 20 to 0. **20% of a Critical verdict had been
resting on a fact nobody had looked up.**

The roadmap was then read (2026-09-10) and every fact confirmed, so the same
component is **98/Critical again — and no code changed between those two
states.** Confirming a fact is a data edit and a `make sign-packs`, which is
the property the mechanism exists to have.

| category | originally | demoted | confirmed |
|---|---|---|---|
| quantum | 40 | 40 | 40 |
| mosca | 28 | 28 | 28 |
| exposure | 10 | 10 | 10 |
| **criticality** | **20** | **0** | **20** |
| **total** | 98 Critical | **78 High** | **98 Critical** |

`test_confirming_the_dst_facts_restored_the_twenty_points` pins the round trip.

## The DST facts, as confirmed

**Primary source**, cited on every rule by document, URL and section:

> DST/NQM, *"Report on Quantum-Safe Ecosystem in India: Roadmap to Quantum
> Resiliency"*, May 2026.
> <https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf>

| rule | fact | section | scores |
|---|---|---|---|
| `dst-cii-foundations-inventory` | CII foundations & cryptographic inventory by **2027-12-31** | Sec. 9.0 | 0 (milestone) |
| `dst-cii-priority-migration` | CII high-priority migration by **2028-12-31** | Sec. 9.0 | 20 `criticality` |
| `dst-full-adoption` | Full adoption, all sectors, by **2029-12-31** | Sec. 9.0 | 0 |
| `dst-aes-128-uplift` | AES-128 → AES-256 symmetric uplift | Sec. 9.0 | 0 |
| `dst-assurance-software-l2a` | **L2A = software security assurance** | Sec. 6.0 / Annexure B Table 1 | 0 |

### A correction the confirmation found

The first encoding listed **four** CII sectors: defence, power, telecom, BFSI.
The roadmap gives **seven**: government, strategic, defence, power, telecom,
transport, BFSI. Reading the source is what found it.

This was the *silent* kind of error. A wrong deadline is at least visible in
the output; a missing sector produced no error anywhere — an asset in a
government or transport estate simply fell through to `sector: other`, never
fired the CII rule, and under-scored by 20 points with nothing to indicate it.

`core.scanner.Sector` was widened to match (and `policy.apply`, `cli.py`,
`api/app.py` with it). **A sector a pack names that a `Target` cannot carry is
a dead rule branch** — the closed `Literal` meant three of the seven would have
been unmatchable, and the correction decorative.
`test_every_roadmap_cii_sector_is_expressible_and_scores` parametrises over all
seven and asserts each both constructs a `Target` and earns the 20 points.

### A consequence worth stating

Adding the 2027 milestone moves the reported `ecdat:deadline` for CII assets
from 2028-12-31 to **2027-12-31**, because that field is documented as *the
earliest any rule demands* and the foundations milestone genuinely is earlier.
The 2028 migration date is still carried in the action text of the rule it
belongs to. This is arguably the more useful headline: the first obligation a
CII operator faces is to have an inventory, and a CBOM is what discharges it.

### Still unverified

`knowledge/libraries.yaml`: the GnuTLS, libgcrypt and NSS `pqc_capable_from`
floors remain `verified: false` with `FILL:` markers, because upstream NEWS has
not been checked. They stay unscored, which is the mechanism working as
intended on the facts that genuinely remain open. OpenSSL 3.5.0 is verified
against its release announcement and CHANGES.md.

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

- **The demo number went down and then came back**, which is the strongest
  evidence the mechanism does what it claims. It also means the DST pack's 20
  points now rest on one person having read one PDF once — see the next point.
- **`verified: true` is an assertion by whoever edits the pack.** Nothing checks
  that the `source` string describes a real document, or that the person read
  it. The gate raises the cost of an unchecked fact from "say nothing" to "write
  a specific false citation and sign the pack"; it does not make lying
  impossible. A second reviewer, or a verification date and verifier identity
  per fact, would be the next increment.
- **The confirmation itself is unwitnessed.** One person read the roadmap on
  2026-09-10 and wrote down the sections. Nothing records WHO, and nothing lets
  a second reader countersign. For a pack that now contributes 20 points to
  every CII verdict, a verifier identity and date per fact is the obvious next
  increment — and it needs the production signing story (ADR-0007) to mean
  anything, since the dev key proves only that this repo's tooling signed it.
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
