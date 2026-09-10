# ADR-0028: Const-prop reach in every pack, and a cross-language contract

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** dataflow/const-prop for Go, JS/TS and Java
**Depends on:** ADR-0026 (the STEP 0 measurement), ADR-0027 (the mechanism and
the Python contract test)

## Context

ADR-0027 closed a quiet recall bug for Python and said, in its own consequences
section, that the same hole was open in three other packs. It was, and in
JavaScript it was not merely a recall gap.

`metavariable-regex` tests the SOURCE TEXT bound to a metavariable. When that
metavariable holds a value PASSED to a call, the text is the variable's NAME
whenever the value was assigned earlier — so the classification silently fails
while the literal-at-call-site form is reported normally.

```js
const alg = "none";
jwt.sign(payload, key, { algorithm: alg });   // produced NO finding at all
```

RFC 8725 §3.1 requires `alg: none` to be rejected: it disables verification
entirely, so anyone can mint a token the service accepts. A service that
selected its signing algorithm from configuration was reported as having no JWT
signing in it.

## STEP 0, measured per language before any rule was touched

| language | string literal via a variable | attribute / enum ref via a variable |
|---|---|---|
| Python | yes (ADR-0027) | **no** |
| Go | — its crypto API has no string-classified algorithms | **no** |
| JS/TS | **yes** | no |
| Java | **yes**, including a whole `"AES/ECB/NoPadding"` transform | **no** |

Two consequences fell straight out of the table, and both changed the plan the
slice arrived with.

**Java's JWT auth-bypass close is NOT achievable.** jjwt and auth0 java-jwt
both spell their algorithms as enum members — `SignatureAlgorithm alg =
SignatureAlgorithm.RS256` — and OSS propagates strings only. Measured, not
assumed: a probe rule matched the String form and missed the enum form in the
same file. It is pinned by a test, not forced.

**Go needs no conversion, and the reason is not the one the brief assumed.**
Go's crypto API classifies with attribute and function references throughout
(`elliptic.P384()`, `tls.VersionTLS10`, `jwt.SigningMethodRS256`). There is no
string to propagate — so there is no classification to fix.

## Decision

### 1. `metavariable-pattern` in JS/TS and Java

Eleven Java rules (7 cipher, 3 signature, 2 SSLContext) and seven JS rules
(4 JWT, `js-createcipheriv`, `js-forge-legacy-cipher`, `js-tls-minversion`) gain
a `metavariable-pattern` branch beside their existing regex branch. The union is
wider than either: a `pattern` is an exact literal so the propagation-aware
branch enumerates values, while the regex branch is a prefix or
case-insensitive match and covers spellings the enumeration does not.

**The ECB verdict survives propagation intact.** Java's cipher rules state the
mode as a rule-level constant (ADR-0023's convention) rather than capturing it,
so `String t = "AES/ECB/PKCS5Padding"` still yields `mode: ECB, flagged: true` —
the highest-value finding in the Java pack, and the one an operator cannot get
by grepping for "ECB".

### 2. Go is left alone, and the limit is a DEGRADED PARAMETER

The Go rules capture their metavariable without a regex constraint, so they
**still fire** on a propagated attribute reference. What is lost is the
parameter:

```
go-ecdsa-keygen  ECDSA  params={'curve': 'curve'}  confidence=0.6  configurable=True
```

The artefact is inventoried; its parameter is reported as the variable's name,
and the scanner marks that honestly on its own — the shape heuristic reads a
lower-case bare name as unresolved, so confidence drops rather than a curve
nobody wrote being asserted.

That is a materially better position than "invisible", and the fixture was moved
from `must_not_fire/` to `must_fire/` once measured, because filing it as a miss
would have been wrong.

### 3. The same degradation applies everywhere, and is asserted

`metavariable-pattern` constrains a binding without rewriting it, so on a
propagated path the **classification is correct and the captured parameter is
the variable's name** — `cipher_suite: "suite"`, `transformation: "transform"`,
`alg: "alg"`. The `algorithm` field carries what the CBOM and the policy engine
read, so this costs a display detail rather than a decision, and the confidence
penalty makes it visible. Tests assert the degraded value rather than glossing
it: an assertion that the value resolved would make the limit invisible.

### 4. The contract test, now cross-language — and it had a hole

ADR-0027's walker now globs all four packs. Extending it exposed a bug in the
guard itself, which is the most useful thing in this slice:

**Its argument-position regex did not include `:`.** JavaScript and TypeScript
spell an argument inside an object literal — `{algorithm: $ALG}` — so the
contract test walked straight past all four `js-jwt-*` rules. *The test written
to make this class of bug unrepeatable could not see the worst instance of it.*

With `:` added, the walker also caught `js-tls-minversion`, which neither the
brief nor this author had listed.

Two exemption kinds, both explicit:

* **by shape** — a metavariable bound as an attribute suffix (`ssl.$PROTO`,
  `jwt.$ALG`) is not an argument position and needs no entry; those rules match
  the constant itself and already report the assignment;
* **by id** — a regex over a variable NAME (`*-weak-random`) or over the SHAPE
  of a literal (`*-hardcoded-key`, `js-forge-rsa-keygen`'s numeric `$BITS`) is
  not classifying an algorithm. A test asserts every exempted id still exists,
  so an exemption for a deleted rule cannot become a hole nobody is watching.

`test_the_contract_test_bites_in_every_language` runs a deliberately-broken rule
in Go, JS and Java syntax through the same predicate. A guard nobody has watched
fail is a guard nobody should trust.

### 5. Every gate is `== 1.0`

ADR-0027's own regression was a rewrite that dropped two detections and passed a
`>= 0.9` check. Go, JS and Java are each scored separately here, each at exactly
1.0 recall and 1.0 precision on their own fixtures.

## Consequences

**Good.**

- **The `alg: none` auth bypass behind a variable is closed in JavaScript and
  TypeScript.** All four JWT families fire on the propagated form.
- Java reports a cipher transformation, a digest and a signature algorithm
  selected through a `String` variable, with the ECB flag intact.
- Go: 24/24 recall, 24/24 precision. JS/TS: 28/28, 28/28. Java: 40/40, 40/40.
- The contract test covers four packs and is proved to bite in three languages.

**Costs and limits.**

- **Java's JWT auth-bypass close is not achievable on this build** (§STEP 0),
  and is pinned by `must_not_fire/EnumRefLimit.java`. If a semgrep upgrade
  starts following enum references that test fails, the fixture graduates, and
  this ADR gets corrected — which is the point of pinning rather than writing
  it down.
- **The captured parameter degrades to a variable name on every propagated
  path**, in every language (§3).
- **Enumeration is manual and finite.** The propagation-aware branches list
  transformations and suites; an unusual one behind a variable is caught only by
  the regex branch, and only at a literal call site.
- **Taint was not extended.** The brief asked for weak-RNG-by-dataflow in
  JavaScript. `mode: taint` works in JS, but the JS pack's `js-math-random` is
  name-scoped and adding a taint sibling means the identity-merge argument
  ADR-0026 made for Python has to be re-made for JS sinks. Not started, not
  faked — PUNCHLIST.
- **Cross-function taint still needs Pro**, unchanged from ADR-0026.
- **Rust and C# packs, when written, inherit the contract test automatically**
  only if their directory is added to `PACKS`. That list is manual.
