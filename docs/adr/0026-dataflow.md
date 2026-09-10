# ADR-0026: Source dataflow — constant propagation and taint

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** source dataflow (Python first)
**Depends on:** ADR-0004 (Scanner A, the rule-metadata contract, and the two
miss-classes this closes), ADR-0002 (identity and the merge rule), ADR-0023
(one config root, the stated-constant convention)

## Context

Scanner A has always matched CALL SITES, and ADR-0004 recorded the two things
that costs. Both come from the same absence — no dataflow — and both are
accuracy bugs rather than coverage gaps: the artefact is usually reported, with
something wrong attached to it.

**Miss-class 1 — `configurable` is guessed from the SHAPE of a captured
value.** `RSA_BITS` is ALL_CAPS, so the heuristic reads it as a resolved
constant and reports `configurable=False`. It is read from `os.environ`.
That flag feeds the crypto-agility score and the Mosca **Y** (migration-time)
estimate, so backwards here prices a restart as a code change, a review and a
redeploy — on every site like it. **No recall number can catch this**, because
the artefact is reported either way.

**Miss-class 2 — an artefact that exists only along a flow is invisible.** A
key assembled by concatenation has no `key = b"..."` literal to match. A weak
RNG assigned to a variable nobody named `secret` is outside the name-scoped
rule by construction — that rule can only see the name.

## STEP 0: what the OSS build actually does

Measured before any rule was written, because this build has surprised the
project before (semgrep OSS emits no `metavars` block at all, and has no
`--offline` flag).

| capability | verdict |
|---|---|
| constant propagation, literal → local | **works** |
| constant propagation, literal → module constant | **works** |
| constant propagation, literal through a branch | **works** |
| constant propagation, **class/attribute reference** | **NOT supported** |
| `mode: taint`, source → sink in one function | **works** |
| taint, no flow present | correctly silent |
| taint, **across a function call** | **NOT supported** (Pro) |

Two findings changed the design.

**Propagation reaches PATTERNS, not CAPTURES.** `algo = "md5"` then
`hashlib.new(algo, ...)` is matched by a pattern written against
`hashlib.new("md5", ...)`, but the metavariable in `hashlib.new($ALG, ...)`
binds the *source text* `algo`, so an accompanying `metavariable-regex` fails.
**Twelve of the Python pack's rules are written in exactly that style**, so the
pack was getting no benefit from propagation at all. The digest and MAC rules
now carry both branches — literals for propagation reach, the regex for
spellings the literals do not enumerate (`MD5`, `Md5`). Recorded in
`knowledge/rules/README.md` as a rule-authoring rule.

**Taint is intra-procedural.** A key assembled in a helper and used by its
caller is not tracked. The rules are written to be honest about that rather
than to imply otherwise, and it is in the answer key as a `known_limit`.

## Decision

### 1. A configurability verdict is an ANNOTATION, not a Finding

`py-configurable-crypto-input` is a taint rule (env/config source → crypto
sink) whose metadata declares `annotates: configurable`. The scanner partitions
semgrep's results, and an annotation never becomes a Finding — it sets
`configurable=True` on findings at the same `(path, line)`.

It could not have been an ordinary rule, for two reasons and the second is the
sharper one:

* The artefact is already reported. What is wrong is a flag on it, so a second
  finding would double-report the key.
* **The normaliser's merge rule makes `configurable=False` beat `True`** — one
  site that cannot be changed without a code edit makes the artefact not freely
  configurable, which is a deliberate and correct choice for merging across
  *sites*. A second finding carrying the correction would therefore be
  *silently overruled by the finding it was meant to correct*. The bug would
  look fixed in the rules and be absent from the output.

The annotation also restores confidence to 1.0 where the shape heuristic had
docked it to 0.6 for an unresolved lower-case name. The penalty existed because
the scanner did not know what the value was; dataflow now knows where it came
from, which is the question `configurable` asks.

**Scoped to cryptographic sinks.** An env-sourced value is only interesting
where it selects an algorithm or a key size. `PAGE_SIZE` is not a
cryptographic fact, and a rule that said so would fire on every settings module
in an estate.

### 2. Two taint rules that ADD findings

`py-assembled-key-material` — concatenation, `join` or `format` reaching a
cipher or MAC. Assembly is the problem, not the parts: a key built from a
constant prefix and a tenant name has whatever entropy the tenant name has, is
derivable by anyone who knows the scheme, and rotating it means changing the
scheme (CWE-321). `redact: true`, like every other key-material rule.

`py-weak-random-dataflow` — `random.*` reaching a key, MAC or token sink.

### 3. BOTH weak-RNG rules ship; neither is a superset

The frame offered keep / replace / both. **Both**, because they cover different
halves:

* the name-scoped rule sees `secret = random.random()` with **no sink in the
  same function** — and taint is intra-procedural, so a value returned to a
  caller is invisible to the taint rule;
* the taint rule sees `value = random.random()` flowing to a cipher, which the
  name-scoped rule cannot see because the name says nothing.

Where both fire they agree on algorithm, primitive, usage and params, so they
carry **one identity** and the normaliser folds them into a single component —
`_drop_position` removes the line, so matching different lines in one file does
not split them. A test asserts the single component rather than trusting it,
and the `flags` on the two rules must stay equal for it to hold: `critical`
sets `params.flagged`, and a params mismatch would split the identity and
double-report.

### 4. The scanner change, and why it is not "a new engine"

`scanners/source` gains `_partition`, `_site` and `_mark_configurable` — about
40 lines. Semgrep still does every piece of analysis; this is the glue that
routes an annotation to a flag instead of to a Finding. An unknown `annotates:`
value is a hard `RulePackContractError`, so a typo in a rule fails the scan
rather than silently dropping the rule's effect.

## Consequences

**Good.**

- Dataflow findings: recall 100% (4/4), precision 100% (0 on the decoys).
  Configurable-flag corrections: 3/3.
- `df_env_keysize.py` and `df_literal_keysize.py` are the same algorithm
  reported by the same rule, and now differ **only** in the flag — which is
  the whole of miss-class 1, asserted as one test.
- The existing Python pack still scores 41/41 recall and 41/41 precision. A
  dataflow rule that fired once on `testdata/python_fixtures` would fail that
  pack's precision assertion; the regression check is part of this suite.
- The decoys — a Monte Carlo simulation, backoff jitter, a banner pick, an
  env-sized page, a concatenated label — produce nothing. What makes a taint
  rule safe to ship is the **sink**, not the source.
- The digest and MAC rules now actually benefit from constant propagation,
  which they did not before this slice regardless of the feature existing.

**Costs and limits.**

- **Python only.** The pattern generalises — Go, JS/TS and Java all have the
  same call-site-only blind spots and semgrep supports taint in all of them —
  but no rule was written for them here.
- **Taint is intra-procedural** (STEP 0). A key assembled in a helper and used
  by its caller is missed. Semgrep Pro's interprocedural analysis is the fix;
  a `known_limit` in the answer key records it.
- **Constant propagation does not follow a class or attribute reference.**
  `algo = algorithms.AES` then `algo(key)` is invisible.
  `testdata/dataflow_fixtures/must_not_fire/constprop_limit.py` pins that
  behaviour with a test that FAILS if a semgrep upgrade starts catching it —
  so the limit cannot go stale in this document.
- **Only the digest and MAC rules were given const-prop reach.** The same
  mechanical treatment is owed to `py-ssl-weak-protocol` and the four
  `py-jwt-*` rules, which regex a value the same way and miss propagated
  constants the same way. PUNCHLIST.
- **The annotation applies by `(path, line)`.** That is exact for the call
  sites here, where the taint sink and the pattern match are the same line, but
  a sink on a different line from the finding it should annotate would be
  missed. A more precise join would key on the semgrep match range.
- **`configurable` is still binary.** "Read from the environment" and "read
  from a signed policy file that requires a change-control ticket" are both
  `True`, and they are not the same migration cost.
