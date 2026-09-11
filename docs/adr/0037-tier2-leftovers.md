# ADR-0037: Tier-2 leftovers — JS weak-RNG taint (verified), recall gates at 1.0, Java use-site refinement

**Status:** Accepted
**Date:** 2026-09-11
**Slice:** Tier-2 leftovers bundle (accuracy polish; the last build slice)
**Depends on:** ADR-0026 (annotations; the shared-identity pattern), ADR-0027
(a floor hides a regression), ADR-0028 (dataflow in every pack), ADR-0030
(usage classification and use-site refinement), ADR-0014 (the QuantumBank KPI)

Three independent items. Each was measured before it was built, and one turned
out to be built already.

## Part A — the JS weak-RNG taint sibling: already shipped (verified, unchanged)

The brief asked for `js-math-random-dataflow`: a taint rule from
`Math.random()` to a key, MAC or token sink, carrying the same identity as the
name-scoped `js-math-random`, so that a site matching both is one finding.

**STEP 0 found it already in the pack**, shipped in ADR-0030:

- The rule is in `knowledge/rules/javascript/random.yaml`, in `mode: taint`,
  with sinks on `createCipheriv`, `createHmac`, `createSecretKey`, `jwt.sign`
  and `Buffer.from`.
- The file documents the identity-merge argument: algorithm, primitive, usage
  and params agree, so the normaliser folds the two.
- The JS answer key has `js_rng_dataflow.js` and `js_rng_named_and_flowing.js`.
- `tests/test_js_rng_taint.py` asserts exactly the brief's cases:
  - a badly named value reaching a key sink is found, by the taint rule only;
  - the name-scoped rule still catches its no-sink case;
  - where both fire, they produce ONE component;
  - a non-crypto `Math.random()` (jitter, shuffle, banner pick) stays silent.

All six of those tests pass. Nothing was rebuilt: a second copy of a working
rule is the kind of scope expansion CLAUDE.md forbids.

The PUNCHLIST entry that still owes work here owes it for **Go and Java**:
neither has a weak-RNG-by-flow rule. That is unchanged by this slice and stays
listed.

## Part B — recall gates are equalities: nine found, eight swept, one kept as a KPI

The brief named the Go and Java pack gates, both `recall >= 0.9` while scoring
100%. ADR-0027's lesson is that such a floor lets a tenth of the detections
vanish with the build still green.

A structural test was written first, `tests/test_recall_gates.py`. It reads
every test module and fails on any recall assertion that tolerates less than
everything. It found **nine** floors, not two. Every one was measured before
it was changed:

| Gate | Measured | Now |
|---|---|---|
| Go rule pack (`test_rules_go.py`) | 32/32 | `== 1.0` |
| Java rule pack (`test_rules_java.py`) | 54/54, with this slice's fixtures | `== 1.0` |
| Python dataflow (`test_dataflow.py`), named in the same PUNCHLIST entry | 4/4 | `== 1.0` |
| Source scanner (`test_scanner_source.py`) | 51/51 | `== 1.0` |
| Config scanner (`test_scanner_config.py`) | 11/11 | `== 1.0` |
| Container scanner (`test_scanner_container.py`) | 6/6 | `== 1.0` |
| Binary scanner (`test_scanner_binary.py`) | 22/22 | `== 1.0` |
| Deps scanner (`test_scanner_deps.py`) | 5/5 | `== 1.0` |
| QuantumBank KPI (`test_kpi_harness.py`) | 100% | pass-line kept; `== 1.0` guard added |

**The KPI is the one exception, and it is not a guard.** `RECALL_GATE = 0.9`
in `kpi/harness.py` is ADR-0014's published pass-line: recall over the
claimed-detectable set, with decoy precision at 100%. Rewriting a documented
product target to make a test stricter would change what the KPI means. So:

- the test asserts the harness's own verdict, `report.passes`, which keeps the
  pass-line exactly as defined;
- a separate `report.findings.recall == 1.0` is the regression guard.

Both hold today, and the structural test sees no floor left in `tests/`.

The six gates beyond the brief were swept deliberately and are called out
here, not done silently. They carry the same defect the brief describes, each
measured at 100%, and the change is one token each.

## Part C — Java use-site refinement: built, within what OSS semgrep can see

**The bug.** `Signature.getInstance("SHA256withRSA")` names the ALGORITHM, not
the DIRECTION; `initSign` or `initVerify` sets that later. The three Java
signature rules (`java-signature-weak-hash`, `java-signature-rsa`,
`java-signature-ecdsa`) reported `usage: sign` at getInstance, so every Java
verifier was inventoried as a signer. The migration target was unaffected,
since sign and verify both map to ML-DSA. But the policy pack's "Migrate the
VERIFIERS first" advice (NIST IR 8547) could never point at a Java verifier,
because the inventory never said "verify" for one. ADR-0030 fixed the same bug
class for Python and JS JWT verifiers.

### STEP 0: measured on semgrep 1.176.1 OSS

The probe was annotation-shaped rules: `pattern: Signature.getInstance(...)`
inside `$SIG = getInstance(...); ... $SIG.initVerify(...)`, and the same for
`initSign`, `verify` and `sign`.

| Shape | Result |
|---|---|
| typed declaration, then `initVerify` / `verify` on the same variable | verify, at the getInstance line |
| typed declaration, then `initSign` / `sign` | sign |
| declared first, assigned later, then `initVerify` | verify |
| getInstance returned to a caller (no use in the method) | no match |
| `verify()` on a DIFFERENT Signature in the same method | no match: the binding holds |
| one Signature initialised both ways | both match |

This is reliable within a method, which is exactly how Python's use-site
refinement works (ADR-0030). So it was built, not punch-listed.

### Decision

1. **The three signature rules keep `usage: sign`, and declare it
   `usage_refinable: true`**, meaning "this usage is a DEFAULT inferred from
   where the rule matched; the call did not state it". The rules README
   documents the key.
2. **The scanner** (`_refinable`) lets a use-site annotation replace `usage`
   when the finding's usage is `unknown`, as before, or when its rule declared
   the usage refinable.
   - A usage the call itself states (`initVerify`, `Cipher.WRAP_MODE`) is still
     never overridden.
   - A non-boolean flag is a `RulePackContractError`.
3. **`knowledge/rules/java/usage_refinement.yaml`** holds
   `java-signature-used-for-signing` and `java-signature-used-for-verify`, the
   STEP 0 patterns exactly. They are annotations (`annotates: usage`), so
   they emit no finding and correct the one already at the getInstance line.
4. **A Signature with no visible use keeps its default (`sign`)**, as the brief
   requires. Nothing is guessed in either direction.

### Tests

`tests/test_java_usage_refinement.py` has 11 tests:

- a verifier refines to `verify`, and now carries the algorithm
  (`java-signature-verify` at `initVerify` cannot know it);
- a declared-then-assigned SHA-1 verifier refines too, and stays flagged;
- a signer is POSITIVELY identified. `sign` is also the default, so the test
  asserts the annotation's verdict, not just the output;
- no visible use keeps its default;
- a verify on a different Signature does not refine;
- the refinement adds no finding;
- a stated usage is never overridden, and a malformed flag is a contract
  error;
- exactly the three getInstance rules declare the flag, so it cannot spread;
- the verifier reaches the CBOM as `usage: verify`, with the ML-DSA,
  verifiers-first action;
- the refinement is deterministic.

The Java answer key now declares the verifier fixtures with `usage: verify`,
the ground truth the old mislabel was never allowed to be. The per-case test
grades every declared `usage`.

## Consequences and limits (PUNCHLIST)

- **Intra-procedural only.** A Signature built in a factory and initialised by
  its caller, passed as a parameter, or kept in a field keeps its default,
  `sign`. That is the common real-world shape. Semgrep Pro's interprocedural
  analysis is the fix. The same limit holds for Python.
- **A Signature initialised both ways reports one usage**: the first in rule
  order, which is `signing`. This is deterministic, and a limit.
- **`java-signature-verify` still reports `algorithm: unknown`** at
  `initVerify`. The getInstance-side finding in the same method now carries
  `verify` WITH the algorithm, so a verifier is one correctly labelled
  component plus the direction fact.
- **Not covered by this refinement:** the Java JWT rules (`java-jwt-auth0-*`,
  `java-jwt-jjwt`) still report `sign` for their construction calls, and Java
  keygen (`KeyPairGenerator`) refinement is not built. Go and JS
  signature-direction refinement is not built either.
- **Go and Java still have no weak-RNG-by-flow rule** (Part A's real
  remainder).
