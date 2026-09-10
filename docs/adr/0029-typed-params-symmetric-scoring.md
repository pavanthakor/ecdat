# ADR-0029: Typed params, and symmetric key size scored against data lifetime

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** typed params (Part A) + symmetric scoring (Part B), paired
**Depends on:** ADR-0002 (identity and the CBOM normaliser), ADR-0007 (the
policy engine), ADR-0008 (Mosca and the score inputs), ADR-0017 (the
verified-fact gate)

## Context

Two punch-list items that turned out to be one item.

**`params` is untyped, and params are IDENTIFYING.** They go into the blake2b
digest that becomes the CycloneDX `bom-ref`, so `key_size: 2048` and
`key_size: "2048"` — the same RSA-2048 reported by two scanners that happened
to disagree about a type — hash to two components. The split is not
hypothetical: the source scanner runs `ast.literal_eval` and gets an int; the
container and binary scanners read a size out of text and get a str. Nothing
made them agree and nothing noticed, because both are plausible in isolation.

**The policy engine did not score symmetric key size against data lifetime.**
AES-128 scored a flat 20 whether it protected a session cookie for an hour or a
citizen's health record for fifty years. That is the wrong SHAPE for the fact —
NIST SP 800-131A Rev.2 Table 5 keeps AES-128 **acceptable**, and NIST IR 8547
Sec. 3 halves it to ~64 bits against Grover. Both are true; which governs
depends on how long the data must stay secret.

The second cannot be fixed without the first: `key_size: {max: 128}` is a
numeric comparison and does not match `"128"`.

## Decision — Part A: canonical types, applied before identity

`core/params.py` is the one place that says what a known param IS. Ten keys
today (`key_size`, `mode`, `curve`, `version`, `valid_to`, `valid_from`,
`hybrid`, `pqc_capable`, `flagged`, `version_is_range`), each with its
coercion and **the reason it has that type** — a table of coercions with no
reasons is a table nobody can review, and a test asserts every entry carries
one.

Three rules:

* **A known param is coerced.** `curve` is the one worth calling out: OpenSSL
  says `prime256v1`, SECG and Java say `secp256r1`, NIST and the TLS registry
  say `P-256`. One curve, four bom-refs, until now.
* **An unknown param passes through UNCHANGED.** A param no pack has declared
  has no canonical type to coerce to, and guessing would invent a fact — it
  would also make adding a param to a rule a change to `core/`.
* **A value that will not coerce is left as written**, never dropped and never
  `None`. `key_size: "unknown"` is a real report; losing it would lose the
  fact, and raising would end a scan over somebody else's malformed input.

**It lives in `finding_identity`, not in the CBOM builder.** That function is
the single chokepoint — the fix-it engine fingerprints findings through it too,
and a split there would make a verified fix fail to match itself across the
sandbox boundary.

## Decision — Part B: `policy/packs/symmetric.yaml`

A new pack, category `symmetric`, **cap 25** — below quantum's 40 and mosca's
30, because a key that is merely SHORT is not a key that is BROKEN. An operator
who saw "use a longer key" scored as Critical would stop believing the bands.

The verdict is scaled by `x_years`, the same input Mosca already uses, at the
data-class boundaries a reader already knows:

| x_years | verdict | symmetric score |
|---|---|---|
| ≤ 9 | acceptable for this lifetime | 0 |
| 10–24 | plan a move | 12 |
| ≥ 25 | move to a 256-bit key | 25 |
| **absent** | **weakened, lifetime unknown** | **12** |

The bands are **exclusive** (`min: 10, max: 24`). Overlapping them let two
rules fire on one finding — the cap hid it in the score and `fired_rules`
listed two rules giving different verdicts about the same artefact.

**Unknown is not zero.** Every band above is gated on `x_years`, so a system
nobody has classified would have fallen through all of them and got *no*
symmetric verdict — worse than the flat rule this replaced, because it looks
like a clean result. The unknown case is scored at the middle of the range:
assuming a short life would hide a real exposure, assuming a long one would
manufacture urgency the organisation has not claimed.

**3DES is deliberately not scaled.** Sweet32 (CVE-2016-2183) exploits the
64-bit block and works today; a shorter data lifetime does not make a 64-bit
block bigger. It is labelled `classically-broken`, not `grover-weakened` —
which is also a correction: the old quantum rule called it Grover-weakened.

Every rule carries `verified: true` with its citation and the document it was
checked against. These are published facts, so under ADR-0017 they score rather
than being demoted to notes.

### Two rule families, because two component shapes exist

Measured, not assumed. The engine derives `algorithm` and `key_size` from a
component, and which it gives depends on the input:

```
AES-128 with a key_size param  ->  algorithm=AES,      key_size=128
AES-128 with no param          ->  algorithm=AES-128,  key_size=None
```

Both occur — the second is how a TLS suite, a package string and a binary
symbol all spell it. So each verdict is stated twice, once against `key_size`
and once against the names that carry their size. The pair must be kept in
step; where both match, the category cap makes it harmless.

An earlier draft selected on `primitive: [block-cipher, stream-cipher]`
instead. That silently matched **nothing**: `primitive` is derived from
`cryptoProperties.algorithmProperties`, which many components do not carry. An
algorithm allowlist is the right selector because it is always present.

### The flat rules were MOVED, not duplicated

`quantum-grover-weakened-symmetric` and
`quantum-grover-weakened-aes-128-by-key-size` are gone from the quantum pack.
Leaving them would have scored every AES-128 finding twice — once flat, once by
context — and pushed a key-size item into the same band as a Shor-broken one.
`quantum_status: weakened` moved with them: Grover halving *is* a quantum
status, and dropping it when the rule moved would have lost a signal the
reports read.

`symmetric-legacy-block-cipher` covers only the 3DES family for the same
reason. DES, RC4, RC2 and Blowfish are already scored 40 by
`quantum-classically-broken`; listing them here scored one fact twice and put a
single broken cipher at 65.

## Consequences

**Good.**

- `key_size: 2048` and `key_size: "2048"` produce one bom-ref. So do
  `prime256v1`, `secp256r1` and `P-256`.
- AES-128 protecting 3-year data scores 0 from this pack; the same finding
  protecting 50-year data scores 25 and lands in a higher band. Same algorithm,
  different context — the shape the asymmetric side has always had.
- A string `key_size` scores identically to an int, and a test asserts that
  connection rather than leaving it as a claim here.
- **The golden CBOM did not move.** QuantumBank's params were already
  canonical, so no regeneration was needed and there is no diff to review.
  Canonicalisation only changes a bom-ref where a param was non-canonical.

**Costs and limits.**

- **Stored scans' component IDs may shift** for any artefact whose params were
  non-canonical. Acceptable — stored-scan continuity is not relied on — but a
  re-score of an old scan can produce different bom-refs from the run that
  stored it, and nothing migrates them.
- **The known-key table is manual.** A param that ought to be typed and is not
  in the table passes through untyped, silently. Adding one is a change to
  `core/params.py`, which is where a reviewer will look, but nothing detects
  the omission.
- **The curve alias table is finite.** An unrecognised curve keeps its spelling
  rather than being mangled — deliberate, but it means two spellings of a curve
  nobody listed still split.
- **The two symmetric rule families must be kept in step by hand.** A verdict
  added to one and not the other applies to half the estate.
- **`x_years` comes from the data class, and most targets do not set one.** In
  practice the unknown-lifetime rule will be the one that fires most often
  until systems are classified, which is the honest outcome and not a
  satisfying one.
- **The lifetime thresholds are ECDAT's judgement**, not a standard. 25 years
  as "long-lived" is chosen to line up with the `Personal` data class and with
  published CRQC estimates; no document says 25.
