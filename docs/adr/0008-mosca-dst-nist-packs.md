# ADR-0008: Mosca, DST and NIST packs, and the score inputs they need

* Status: accepted
* Date: 2026-09-09
* Slice: mosca + india_dst + nist_ir8547 packs (completes Pillars 1 & 4)
* Extends: [ADR-0007](0007-policy-engine.md) (the engine, signed cited packs)
* **Resolves** the "Criticality unreachable with quantum-only packs" item
  ADR-0007 deferred.

## Context

ADR-0007 shipped the engine and one pack, and recorded a gap it could not close
alone: with only quantum rules loaded, the maximum score is the quantum cap of
40, so a Shor-broken RSA is Medium and nothing can ever be Critical. The two
ways to "fix" that in isolation — raise the cap, or lower the band threshold —
would both have been dishonest. They make the number bigger without making the
finding worse.

The honest fix is more information. RSA-2048 in a lab, protecting public data,
reachable only from a build server, genuinely is a Medium problem. The same
RSA-2048 in a bank, protecting personal data for 25 years, reachable from the
internet, is genuinely Critical. **Criticality is a property of the situation,
not of the algorithm**, and this slice supplies the situation.

## Decision

### Score inputs are computed at apply time and written before rules run

`policy/apply.py` attaches `ecdat:` properties to every component *before*
`evaluate` sees it, so a pack's `when` clause can select on them exactly as it
selects on `key_size`:

| Property | Meaning |
|---|---|
| `ecdat:data_class`, `ecdat:x_years` | data lifetime, from `knowledge/data_classes.yaml` |
| `ecdat:y_years` | migration time, modelled from configurability |
| `ecdat:z_years` | CRQC horizon, a single global parameter |
| `ecdat:sector`, `ecdat:exposure` | organisational context from the `Target` |

Each estimated term also emits a `_basis` property saying **in words** that it
is an estimate and where it came from. A number a reader cannot distinguish
from a measurement is a number they will treat as one.

`Target` gains `sector` and `exposure`, threaded through the API body, the CLI
(`--sector`, `--exposure`, `--crqc-years`) and the orchestrator.

### Unknown data lifetime is not zero

This is the load-bearing honesty decision of the slice. `mosca_gap` returns
`None` when X is unknown, never 0, and `_x_years` returns nothing for an absent
or unrecognised `data_class` rather than defaulting.

If unknown were 0, every unclassified system would score as having nothing to
protect — and unclassified systems are precisely the estate a migration
programme is trying to find. The mosca pack carries a rule
(`mosca-data-lifetime-unknown`) that fires on exactly that absence, contributes
0, and labels the component so the gap is visible rather than silent. Its
action text says in as many words: *this is NOT a finding that the asset is
safe.*

### `mosca_gap` is the only arithmetic, and it is named not described

`x + y > z` cannot be expressed in the selector grammar, and ADR-0007's
no-eval guarantee means it must not become expressible. So the arithmetic lives
in **one tested function** in `policy/engine.py`, and a pack asks for it by
name:

```yaml
effect:
  type: mosca_urgency
  category: mosca
```

Effect types are a closed vocabulary, validated at load exactly like selector
operators. A pack can *name* a computation; it cannot *describe* one, and there
is no grammar in which to describe a different one. That keeps the whole
no-eval argument intact while still supporting a non-linear score.

`mosca_contribution` scales the gap linearly onto `[0, cap]`, reaching the cap
at `MOSCA_GAP_CEILING = 20` years. Integer arithmetic throughout — a float
would make the score depend on binary rounding, and the determinism guarantee
is about bytes.

### Two-pass evaluation, so a rule can select on a verdict

The DST pack genuinely needs "if this is Shor-broken **and** it is in a critical
sector". `quantum_status` is a verdict output, not a component property, so
`evaluate` runs in two passes: pass one is every rule that does not select on a
derived fact, then `quantum_status` is injected into the facts, then pass two
runs the rules that do.

**Exactly two passes.** A pass-two rule cannot feed another pass-two rule, so
there is no fixpoint to reason about and no ordering subtlety to get wrong.
Contributions from both passes merge identically. `DERIVED_FACTS` names the
closed set of facts that trigger the second pass.

### Four categories, four caps

| Category | Cap | Why this size |
|---|---|---|
| `quantum` | 40 | The defect itself. The largest, because everything else is a modifier on it. |
| `mosca` | 30 | Urgency. Sharpens a verdict; must not outrank the defect. |
| `criticality` | 20 | Sector. An asset that is not broken does not become critical by being in a bank. |
| `exposure` | 10 | Reachability. Adjusts at the margin — able to push a serious finding over a boundary, never able to make a sound one look broken. |

Each pack declares its own cap in its header (ADR-0007), and narrowest-wins
still holds — `test_a_pack_cannot_widen_another_packs_cap` adds a pack claiming
`quantum: 500` and asserts the merged cap stays 40.

Total possible is 100, so the bands mean what they say. Critical (≥80) requires
being bad on **at least three** of the four axes. That is the property worth
protecting: `test_the_same_algorithm_is_critical_or_medium_by_context` fails if
Criticality ever becomes reachable by raising a number instead.

### Worked example

The same RSA-2048, twice:

```
BFSI / Personal / internet / hard-coded    quantum=40 mosca=28 criticality=20 exposure=10
                                          SCORE 98  CRITICAL  deadline 2028-12-31

Lab / Public / internal / configurable     quantum=40 mosca=0  criticality=0  exposure=5
                                          SCORE 45  MEDIUM    deadline 2029-12-31
```

Nothing about the algorithm changed.

### Two deadline sources, so earliest-wins is testable

DST supplies 2028-12-31 (CII) and 2029-12-31 (full adoption); NIST IR 8547
supplies 2030-01-01; the quantum pack supplies 2035-01-01. All four land on one
RSA and the merge returns 2028-12-31. An organisation subject to both regimes is
bound by whichever comes first, and the engine says so without being told which
regime "wins". Before this slice the earliest-deadline rule was a claim with
only one source to exercise it.

### Y is a model, Z is an assumption, and both say so

`Y_YEARS_BASE = 3`, `+2` when the finding is hard-coded — a code change, review
and redeploy versus possibly a config change. Unknown configurability is treated
as configurable, so the estimate does not inflate on ignorance.

`DEFAULT_Z_YEARS = 11`. There is no measurement here and there cannot be. It is
deliberately a single **global parameter** rather than a per-component fact, so
an analyst can move it and watch the whole estate re-prioritise —
`--crqc-years`, `z_years` in the API body, and a dashboard slider later. That is
the honest way to use a number nobody knows: expose the assumption rather than
bury it.

### Data-class X defaults

Public 0, Internal 3, Confidential 10, Personal 25, Sovereign 50.

These are **policy defaults, not statutory retention periods**, and
`knowledge/data_classes.yaml` says so at length in its header. No law states
"personal data must stay confidential for 25 years"; what the DPDP Act supplies
is the framing that personal data's sensitivity is bounded by the data
principal's life. The year counts are ECDAT's, chosen to be defensible and
overridable, and each entry records what it is derived from. Inflating X
manufactures alarm and deflating it manufactures calm, so the provenance of
each number is written down next to it.

### Assurance levels: only what is known

`dst-assurance-software-l2a` maps software assets (library / module / service)
to `assurance:L2A`. Hardware, key-management and CA assurance levels are
**deliberately absent** rather than guessed. An invented assurance level is
worse than a missing one, because it looks answered.

More broadly: the DST deadlines, the CII sector list and the L2A label were
supplied to ECDAT as roadmap requirements and are encoded verbatim. They have
not been checked line by line against the published DST/NQM text by this
engine's authors. The pack header says so, and it is punchlisted. The structure
is certainly right — a phased CII-first migration with a later full-adoption
date is the shape such roadmaps take — but a deadline an organisation acts on
should be confirmed against the source.

## Consequences

* Criticality is reachable, and reachable only by context. The quantum-only
  ceiling from ADR-0007 is resolved.
* **The exposure rules live in `nist_ir8547.yaml` for a practical reason, not a
  principled one.** Exposure is not a NIST concept; it sits there because NIST
  IR 8547's guidance is what asks organisations to prioritise, and reachability
  is what prioritisation needs. The category is separate (`exposure`) precisely
  so moving it to its own pack later costs nothing.
* **The mosca rule fires on any component with a known data lifetime**,
  including quantum-safe ones like AES-256. Mosca urgency for an algorithm that
  is not going to break is arguably noise. Gating it on `quantum_status` would
  need it to be a second-pass rule; that is a one-line change, deferred so the
  slice's merge behaviour is proved with the simpler form first. Punchlisted.
* Applying policy is still idempotent and byte-stable — `apply_policy` now
  strips its own **inputs** as well as its verdicts before rewriting, because
  the context can change between runs too.
* A component with an unknown data class can still reach High (quantum 40 +
  criticality 20 + exposure 10 = 70). That is correct: not knowing the data
  lifetime does not make a Shor-broken internet-facing asset in a bank safe.

## Alternatives considered

* **Raise the quantum cap, or drop the Critical threshold.** The two obvious
  fixes for ADR-0007's gap, and both dishonest: they make the number bigger
  without making the finding worse. Rejected explicitly, and
  `test_the_same_algorithm_is_critical_or_medium_by_context` exists to keep
  them rejected.
* **Default unknown X to 0.** Simpler, no `None` to thread, and it silently
  scores every unclassified system as safe. Rejected — it inverts the tool's
  purpose.
* **Default unknown X to a pessimistic maximum (50).** Errs the safe way, and
  makes the whole unclassified estate Critical at once, which is
  indistinguishable from noise and will be tuned out. Reporting "unassessed" is
  more useful than reporting a guess in either direction.
* **A general expression language for effects.** Would have made `mosca_gap`
  one more pack rule instead of an engine function, and would have reintroduced
  evaluation into the component most attractive to tamper with. The named
  effect type gives the same expressive power for a closed set of computations.
* **Per-component Z.** Physically meaningless — the CRQC arrives once, for
  everyone. A global parameter is both more correct and more useful as a slider.
