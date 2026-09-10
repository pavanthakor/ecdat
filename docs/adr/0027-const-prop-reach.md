# ADR-0027: Finishing constant-propagation reach, and a contract test

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** const-prop reach for the remaining Python rules
**Depends on:** ADR-0026 (dataflow; the STEP 0 measurement this follows up),
ADR-0004 (the rule-metadata contract)

## Context

ADR-0026 measured something and then only half-fixed it.

`metavariable-regex` tests the **source text** bound to a metavariable. When
that metavariable is bound to a value *passed to a call* — `algorithm=$ALG` —
the source text is the variable's NAME whenever the value was assigned earlier,
so the regex fails and the site is never reported. The literal-at-call-site form
is reported normally, which is what makes the gap quiet: the rule looks like it
works.

ADR-0026 fixed the digest and MAC rules by bolting literal `pattern:` branches
beside the regex, and left `py-ssl-weak-protocol` and the four `py-jwt-*` rules
alone. This ADR finishes it and, more importantly, makes the gap impossible to
reintroduce.

## Decision

### 1. `metavariable-pattern`, not literal branches

Measured before rewriting anything:

| construct | sees the propagated value? |
|---|---|
| `metavariable-regex` | **no** — source text only |
| `metavariable-pattern` with `pattern-regex:` inside | **no** — same hole |
| `metavariable-pattern` with a real `pattern:` | **yes** |
| a literal spelled into the top-level `pattern:` | yes (ADR-0026's fix) |

`metavariable-pattern` is the right mechanism, and it is strictly better than
ADR-0026's literal branches for these five rules because **it keeps the
metavariable bound**. The JWT and ssl rules `capture:` their metavariable into
`params`; a bare literal branch would leave `$ALG` unbound and the message would
carry the string `$ALG` into `params.alg`.

The nested-`pattern-regex` result is the one worth recording: it looks like it
should work and does not.

### 2. Both branches ship, per rule

Each rewritten rule carries a `metavariable-pattern` branch **and** the original
`metavariable-regex` branch:

```yaml
- patterns:                       # propagation-aware; enumerates spellings
    - pattern: jwt.encode(..., algorithm=$ALG, ...)
    - metavariable-pattern:
        metavariable: $ALG
        pattern-either: [{pattern: '"RS256"'}, ...]
- patterns:                       # literal-at-call-site; case-insensitive
    - pattern: jwt.encode(..., algorithm=$ALG, ...)
    - metavariable-regex:
        metavariable: $ALG
        regex: ^["'](RS|PS)(256|384|512)["']$
```

The union is wider than either. A `pattern` is an exact literal, so the
propagation-aware branch has to enumerate spellings (`md5`, `MD5`) while the
regex branch is case-insensitive and does not. The two agree on every
identifying field, so a site matching both carries one identity and the
normaliser folds it — the same argument that lets both weak-RNG rules ship
(ADR-0026).

### 3. `py-ssl-weak-protocol` was NOT broken, and is left alone

The brief assumed it had the gap. It does not, and the difference is
instructive: it matches `ssl.$PROTO` — **the constant itself, wherever it
appears** — rather than a value passed to a call. So `proto =
ssl.PROTOCOL_TLSv1_1` is already reported, at the *assignment* line.

Rewriting it to classify the argument of `SSLContext(...)` would have **added**
a gap, because `ssl.PROTOCOL_TLSv1_1` is an attribute reference and OSS
constant propagation does not follow those (ADR-0026). A test pins the current
behaviour so a future tidy-up cannot quietly introduce the bug this slice
exists to remove.

### 4. The contract test — the durable half

`test_no_python_rule_classifies_a_passed_value_with_metavariable_regex_alone`
walks every rule in `knowledge/rules/python/`, and fails any rule that

* binds a metavariable in **argument position** (after `(`, `,`, `=` or `[`), and
* constrains it with `metavariable-regex`, and
* has **no** `metavariable-pattern` constraint on that same metavariable.

Two exemptions, both explicit rather than inferred:

* **Attribute-suffix bindings** are not argument positions, so
  `py-ssl-weak-protocol` passes without an allowlist entry — the shape of the
  pattern is what distinguishes it, which is the right distinction.
* **Name-scoped rules** are listed by id (`py-weak-random-secret`). A regex over
  a variable NAME is asking about the name, and propagation has nothing to do
  with it. Listing them means adding one is a deliberate act.

## Consequences

**Good.**

- All four JWT families now report an algorithm selected through a variable,
  including `py-jwt-none` — the one that matters most, since RFC 8725 s3.1
  requires `none` to be rejected and a signer selecting it through a variable
  was completely invisible.
- The contract test makes the class of bug unrepeatable in the Python pack.
- `EdDSA` (RFC 8037), which no rule in the pack claims, still produces nothing:
  propagation-aware classification did not become a catch-all.

**Costs and limits.**

- **`params.alg` holds the variable NAME on the propagated path**
  (`{'alg': 'SIGNING_ALG'}`), not the resolved value, because
  `metavariable-pattern` constrains a binding without rewriting it. The
  `algorithm` field carries the classification, which is what the CBOM and the
  policy engine read, so this costs a display detail rather than a decision. It
  also means `_is_resolved` reads the site as configurable — which for a
  settings-driven algorithm is arguably right.
- **The contract test covers Python only.** Go, JS/TS and Java use the same
  `metavariable-regex` style in several rules and have the same hole; the test
  is one glob away from covering them, but the rules were not audited or
  rewritten here.
- **Spelling enumeration is manual.** The propagation-aware branch lists
  `md5`/`MD5` and `sha-256`/`SHA-256`; an unusual casing (`Md5`) is caught only
  by the regex branch, and only at a literal call site.
- **A regression guard was too loose and hid a real regression during this
  slice.** Converting the MAC rules dropped the positional
  `hmac.new(..., hashlib.md5, ...)` branch and the Python pack fell to 39/41 —
  while every assertion passed, because the check asserted `recall >= 0.9`. It
  now asserts `== 1.0`. A regression guard with a floor is not a regression
  guard.
