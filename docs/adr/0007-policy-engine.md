# ADR-0007: The policy engine, and signed cited packs

* Status: accepted
* Date: 2026-09-09
* Slice: policy engine + quantum pack (Pillars 1 & 4 foundation)
* Extends: [ADR-0002](0002-cbom-normaliser.md) (what the normaliser does *not* do)

## Context

Four pillars need a number attached to each component: India-roadmap compliance,
drift, usage-aware recommendation, and Mosca/blast-radius prioritisation. All
four want the same machinery — match a component, contribute a score, a label, a
deadline and an action, then merge the contributions deterministically.

The number has to be **traceable** (which rule, citing what), **stable** (the
same CBOM must score identically tomorrow), and **updatable without rescanning**
(NIST publishes, the estate does not change).

## Decision

### Scoring lives in `policy/`, never in `core/normalise.py`

ADR-0002 drew this line and this slice is where it earns its keep. The
normaliser records what **is**: `nistQuantumSecurityLevel: 0` is a definitional
consequence of the hard problem RSA rests on, not an opinion. The policy engine
decides what that **means**: that RSA is worth 40 points and needs replacing by
2035 is an assessment, and assessments change when guidance changes.

Keeping them apart means re-scoring an estate is re-running `apply_policy` over
stored CBOMs, not re-scanning it. If scoring lived in the normaliser, every
NIST update would invalidate every stored document.

### A pack is data, and a `when` clause is never executed

A rule is a selector, an effect and a citation, all YAML. The selector
vocabulary is closed and dispatched explicitly: `eq`, `in`, `not_in`, `min`,
`max`, `present`, `contains`. Keys are ANDed.

There is no expression language and nothing reaches an interpreter. A `when`
value of `"__import__('os').system('rm -rf /')"` is a string that gets compared
with `!=` against a component name, and that is the whole of what happens to
it — pinned by `test_a_code_looking_selector_is_matched_as_a_string`, which
also asserts the side effect the payload would have had did not occur.

A scoring engine is exactly where an attacker would want an expression
evaluator, and "we only eval trusted packs" is a claim that survives right up
until someone adds a pack-authoring UI.

**An unknown operator raises at load**, not at match time. A silently
never-matching rule is a rule that has been deleted without anyone deciding to,
and a typo would otherwise turn a Critical into an unscored component.

### The selector sees a projection, and `algorithm` is derived

`component_facts()` flattens a component into a documented flat surface:
`name`, `algorithm`, `asset_type`, `primitive`, `usage`, `views`,
`nist_quantum_security_level`, `classical_security_level`, plus every
`ecdat:param:X` as `X`.

`algorithm` is not in the CBOM — the component *name* is `RSA-2048`. It is
recovered as the exact inverse of `core.cbom._component_name`, driven by the
params rather than by the shape of the string. That distinction is load-bearing:
`RSA-2048` must lose its `-2048` while `SHA-1` must keep its `-1`, and no regex
can tell those apart. `test_the_projection_matches_real_normaliser_output`
pins the derivation against real normaliser output so that changing the naming
in `core/cbom.py` fails loudly rather than silently stopping every algorithm
rule from matching.

### Merge semantics

* **score** — contributions ADD within a category, each category is then
  CAPPED, and the capped subtotals sum. Per-category rather than global capping
  is deliberate: ten quantum rules on one component must not be able to bury a
  single critical finding from another dimension once the other packs land.
* **labels** — union, sorted.
* **deadline** — the EARLIEST. A later deadline never relaxes an earlier one.
* **actions** — ordered by `(deadline, rule_id)`, soonest first, deduplicated.
* **fired_rules** — sorted; rule ids are globally unique, enforced at load.
* **quantum_status** — most severe wins (`broken` > `weakened` > `adequate` >
  `pqc`), so adding a reassuring rule can never mask a damning one.

Pack order cannot change a verdict; `test_pack_order_does_not_change_the_verdict`
shuffles packs and rules eight times and compares.

### The category cap table lives in the pack header

`caps: {quantum: 40}` sits in `quantum.yaml`, not in the engine. The rules that
create a category and the ceiling on that category then version and ship
together, and raising a ceiling is a reviewable, **signed** change to the same
file. Where two packs declare the same category the **narrowest** cap wins: a
pack may tighten a ceiling, never widen it. `CATEGORY_CAP_DEFAULT` (40) applies
to any category no pack has declared, so there is always a ceiling.

### Bands: 80 / 60 / 40

`>=80` Critical, `60-79` High, `40-59` Medium, `<40` Low.

**A consequence worth stating plainly:** with only the quantum pack loaded, the
maximum achievable score is the quantum cap, 40 — so a Shor-broken RSA is
**Medium**, not Critical. That is not a bug and it is not the pack being timid;
it is what "cap the quantum category at 40" and "Medium starts at 40" mean
together. Criticality arrives when a component is bad along *several* axes at
once: quantum-broken **and** past an India DST deadline **and** with a Mosca
horizon already breached. Those are the `india_dst`, `nist` and `mosca` packs,
which are the next slice. The slice frame anticipated an RSA showing
Critical/High here; with quantum-only packs that is arithmetically unreachable
without either raising the locked cap or moving the locked bands, so the locked
values were implemented and the expectation is recorded here instead.

### Packs are signed, and unsigned packs do not load

A pack decides what an organisation is told about its own cryptography. Anyone
who can edit one unnoticed can turn a Critical into a Low with a two-character
diff in a file nobody re-reads. Ed25519 detached signatures make that edit
visible: `quantum.yaml` sits beside `quantum.yaml.sig`, the signature covers the
pack's exact bytes, and `load_packs` refuses an unsigned, tampered, or
wrong-key pack.

Detached rather than embedded so the pack stays plain, readable, diffable YAML.
Byte-exact so reformatting also invalidates it — "only whitespace changed" is a
claim a reviewer should have to make explicitly by re-signing.

`dev=True` (or `ECDAT_POLICY_DEV=1`) skips **signature verification only**, and
logs a warning every time. Citations, schema, operator vocabulary and duplicate
rule ids are all still enforced, because those catch mistakes rather than
attacks and a developer editing a pack needs them most.

### Every rule cites its source

`load_packs` refuses a rule whose `citation` is missing or blank, in dev mode
too. Per CLAUDE.md there are no uncited crypto facts; a score nobody can trace
to a FIPS number or an SP section is a number nobody should act on.

### DEV keys now, production key management deferred

The keypair under `policy/keys/dev/` is **committed**, and its private half is
therefore public by definition. A signature made with it proves a pack was built
by this repo's tooling and **nothing about who approved it**. It exists so
`make check` verifies the shipped packs out of the box rather than needing a
key-provisioning step to run the tests.

Production signing — an offline key, a published verification key, a release
process, and probably a key-rotation story — is deferred and punchlisted. The
private key file carries a banner saying so, so nobody mistakes it on a
casual `cat`.

## Consequences

* Stored CBOMs are scored CBOMs. `run_scan` applies policy between normalisation
  and the store, and re-validates against the CycloneDX schema afterwards, so a
  policy that emitted an invalid property fails the scan rather than persisting.
* `apply_policy` is idempotent: it strips its own properties before rewriting
  them, so re-scoring a stored document under an updated pack replaces the
  verdict instead of accumulating a second one beside it.
* A pack that will not load **fails the scan** rather than downgrading it to an
  unscored document. A CBOM that looks scored but is not is worse than one
  obviously missing its scores.
* `GET /scans` now carries `band_counts` and `max_score`, read back out of the
  stored document rather than recomputed — the summary must report what was
  stored, not what today's packs would say. That means parsing every stored CBOM
  per list call, which is fine at present scale and punchlisted.
* **Two rules firing on one component is normal and intended.** RSA matches both
  the algorithm-name rule and the `nistQuantumSecurityLevel: 0` rule; `40 + 40`
  caps back to `40`. The second rule exists to catch an algorithm the name list
  has not been taught yet, and `fired_rules` shows which route reached the
  verdict.

## Alternatives considered

* **CEL, JSONLogic, or a small expression language.** More expressive, and it
  reintroduces evaluation into the component most attractive to tamper with.
  The closed operator set covers every rule the quantum pack needs; when a
  future pack genuinely cannot be expressed, the answer is one more named
  operator, reviewed on its own.
* **Scoring inside the normaliser.** Fewer moving parts, and it welds an
  opinion to the permanent record — every guidance change would invalidate
  every stored CBOM.
* **Python rule plugins instead of YAML.** Maximum expressiveness, no signing
  story that means anything, and it puts crypto knowledge back into code, which
  is what CLAUDE.md's knowledge-pack requirement exists to prevent.
* **Global score cap instead of per-category.** Simpler, and it lets whichever
  pack has the most rules dominate the verdict.
