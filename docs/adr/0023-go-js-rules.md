# ADR-0023: Go and JavaScript/TypeScript rule packs

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** paired rule-pack slice — Part A (Go), Part B (JS/TS)
**Depends on:** ADR-0004 (Scanner A and the rule-metadata contract), ADR-0003
(plugin isolation), the redaction guard in `scanners/source`

## Context

Scanner A has been Python-only since ADR-0004, and QuantumBank has carried the
cost in writing: `services/gateway/sign.go` signs partner callbacks with ECDSA
P-256 and embeds a PEM certificate, and the answer key marked both
`known_gap: true` — real crypto, in a real service, that ECDAT could not see.
Two of the seven planted declared-view artefacts were excluded from the KPI
denominator for no reason except the scanner's language coverage.

`knowledge/rules/README.md` has always claimed that adding a detection means
adding YAML, not Python. This slice is the first test of that claim against a
language the contract was not designed on.

## Decision

### 1. Two packs, on the existing engine, scored SEPARATELY

`knowledge/rules/go/` (23 rules) and `knowledge/rules/javascript/` (20 rules),
authored against the same metadata contract the Python pack has satisfied since
ADR-0004. `tests/test_rules_go.py` and `tests/test_rules_js.py` share nothing
but the scoring harness in `tests/rulepack.py`, and each asserts its own
recall ≥ 0.9 and precision == 1.0.

**Separate scoring is the process decision, not a formality.** One combined
number lets a strong pack carry a weak one: Go at 100% and JS at 60% averages
to something that looks shippable, and the average is what would get reported.
Two independent scores cannot do that. The packs ship together only because
both are green; either failing fails the build.

### 2. Semgrep handles both languages — verified before writing either pack

STEP 0 of the slice, before any rule was authored: semgrep 1.176.1 (the pinned
version, ADR-0017) matched a trivial Go rule and a trivial TypeScript rule, and
the message-interpolation capture channel returned `key_size: 2048` from Go
through the real scanner. Neither pack was written on the assumption that it
would work.

### 3. ONE config root, which is the only engine change

`RULE_SUBDIR` moves from `rules/python` to `rules/`. Semgrep is pointed at the
parent directory and each rule's own `languages:` decides which files it reads.

This is a **deviation from the frame**, which asked for no engine changes. It is
one constant, and without it the two new directories would never be loaded —
"new YAML only" was not achievable as stated. No matching, mapping or contract
code changed. The alternative, one `--config` per language, would mean editing
Python every time a language is added, which is the thing the README promises
does not happen.

### 4. Where a language spells a fact differently, the rule states it

Two shapes came up that the Python contract had not needed:

**A constant the source cannot vary.** In Python the cipher mode is an argument
(`modes.CBC(iv)`) and binds to a metavariable. In Go it is part of the function
NAME — `cipher.NewCBCEncrypter` — so there is nothing to bind. The rule writes
`mode=CBC` into the message directly. The scanner extracts captures by
PARAMETER NAME (`_parse_captures`), so it lands in `params.mode` exactly as a
bound metavariable would, and `_is_resolved` reads it as hard-coded — which it
is, because the call site cannot select another mode without a code change. The
`capture` entry names the constant instead of a `$METAVAR` to keep that visible
to whoever reads the rule.

**A family that decides the migration.** JWT and Go-JWT rules are one per
family (`-rsa`, `-ecdsa`, `-hmac`, `-none`), matching the Python pack, because
`metadata.algorithm` is per-rule and the family is the migration: RS256 becomes
ML-DSA, HS256 needs a key-size review, `none` is not a signature at all. One
rule for four families would give one answer to four different questions.

### 5. Redaction now covers three scanner families

Both packs carry `redact: true` key-material rules, and neither interpolates
the metavariable that binds to the secret. Each fixture tree plants sentinels
inside real key material — `GOSECRETSENTINEL`/`GONOTAREALKEY`/`GONOTAREALCERT`
and the `JS*` equivalents — and a negative test asserts none reaches any
Finding, including through a *different* rule that happens to match the same
line (the AES rule matches the hard-coded-key file too, and is declared in the
answer key for exactly that reason).

**The schema-level guard is still owed.** What holds today is two layers in
`scanners/source`: the rule's own `redact` flag, and a scrub of any line
carrying a PEM banner. The second layer's byte-literal net is Python-specific
(`b"..."`), so for Go and JS the PEM banner plus `redact: true` is what does the
work. A guard at the `Finding` boundary — refusing to construct one whose
snippet looks like key material, whatever the scanner — would not depend on
every rule author remembering. PUNCHLIST.

### 6. Decoys per language, and TypeScript proved rather than declared

Each pack has a `must_not_fire/` file planting the four false positives worth
worrying about: prose naming an algorithm, an identifier that reads like a
digest holding a non-secret, a name-scoped RNG rule's non-key use (jitter, a
display shuffle), and a non-crypto import whose name looks cryptographic.
Precision is asserted at exactly 1.0 against an exhaustive answer key, so a
detection that is real but undeclared fails the build.

JS decoys include a `.ts` file, and `ts_*.ts` fixtures carry declared
detections, because `languages: [javascript, typescript]` is a claim. A rule
that silently stopped matching `.ts` would pass every `.js` assertion;
`test_typescript_files_are_actually_scanned` and
`test_the_same_rule_fires_on_both_js_and_ts` are what notice.

### 7. The QuantumBank Go gap is CLOSED, and the exclusion removed

`gateway-ecdsa-p256` and `gateway-embedded-cert` lose `known_gap: true` and
enter the scored denominator. The KPI declared view goes from 14 planted to 16,
overall from 20 to 22, recall stays 100%, decoy precision stays 100%, and the
KNOWN GAPS section is now empty.

Removing the exclusion is the point. A gap that closes but stays excluded means
the denominator never grows and the score improves without anything having been
found — so a test asserts the answer key no longer carries the flag, not merely
that the findings appear.

## Consequences

**Good.**

- Go: recall 100% (22/22), precision 100% (22/22). JS/TS: recall 100% (21/21),
  precision 100% (21/21). Printed separately on every run.
- Three of ECDAT's seven planned languages are covered by the same 600-line
  scanner. The README's claim — a detection is YAML, not Python — now has
  evidence from a language whose syntax the contract was not designed around.
- A mixed Go/JS/TS/Python repo produces one schema-valid CBOM with all four
  represented, all in the `declared` view.
- The QuantumBank demo no longer has to explain a gap in its own fixture.

**Costs and limits.**

- **Java, C/C++, Rust and C# are still unscanned.** Four of seven families. Java
  is the obvious next one (JCA is well-shaped for Semgrep); C/C++ needs
  tree-sitter or a different approach, since OpenSSL calls are macro-heavy.
- **The redaction schema-level guard is still owed** (§5), and the byte-literal
  net remains Python-only.
- **23 Go rules and 20 JS/TS rules is a starting pack, not a complete
  inventory.** Go's
  `crypto/ecdh` X25519 path, `golang.org/x/crypto` (nacl, bcrypt, argon2),
  WebCrypto `subtle.*` in the browser, and the `jose`/`node-jose` families are
  all unmatched. Additive: each is YAML.
- **No constant propagation, in any language.** `crypto.createCipheriv(algo, …)`
  where `algo` is a variable does not match, deliberately — reporting
  `cipher_suite: algo` would be a parameter nobody can act on. Same limit
  ADR-0004 recorded for Python.
- **The name-scoped RNG rules are heuristics.** `Math.random()` assigned to
  `sessionToken` fires; assigned to `t` does not. The decoys pin the false-
  positive side; the false-negative side is unbounded and untested.
- **`params.alg` for Go JWTs holds the Go constant name**
  (`SigningMethodRS256`), not the RFC 7518 token, because Go spells the
  algorithm in an identifier rather than a string and the finding should say
  what the source says. The JS pack reports `RS256` because JS uses a string.
  Two spellings for one concept; the correlator does not join them today.
