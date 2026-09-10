# ADR-0034: A hard-coded-key finding needs corroboration, not a name

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** hard-coded-key precision (Tier-2 accuracy)
**Depends on:** ADR-0023/0024 (the Go, JS/TS and Java packs), ADR-0025 (the
binary scanner's heuristic confidences), ADR-0026 (Python taint, the
assembled-key rule), ADR-0028 (dataflow in every pack), ADR-0033 (the Juice Shop
scan that exposed this)

## Context

With ADR-0033 in place ECDAT could finally scan OWASP Juice Shop (upstream
`1618a61`). The stored scan held seven key-material findings. Five were not key
material at all:

| Site | Declaration | What it is |
|---|---|---|
| `frontend/src/app/Services/basket.service.ts:33` | `private readonly guestBasketKey = 'guestBasket'` | a sessionStorage key |
| `frontend/src/app/Services/conversation-storage.service.ts:9` | `const STORAGE_KEY = 'juiceshop_chat_conversations'` | a localStorage key |
| `frontend/src/app/Services/conversation-storage.service.spec.ts:9` | the same | the same, in the spec |
| `frontend/src/app/welcome-banner/welcome-banner.component.ts:33` | `private readonly welcomeBannerStatusCookieKey = 'welcomebanner_status'` | a cookie name |
| `frontend/src/app/welcome/welcome.component.ts:25` | the same | the same, read back |

A sixth, `js-hardcoded-key` at `lib/insecurity.ts:21`, was the PEM block that
`js-pem-block` had already reported. That made two findings for one key.

The cause was the rule's premise. `js-hardcoded-key` fired on any key-ish NAME
(`key|secret|iv|nonce|salt|passphrase|password|credential`) holding a string
literal of eight characters or more. It fired at confidence 1.0 and was flagged
critical. The name regex matched `iv` as a substring, so it also caught
`private`, `archive` and `active`. And the rule never saw the real key in that
file: `crypto.createHmac('sha256', 'pa4q…')` at `insecurity.ts:42`, which no
variable holds. Go's and Java's rules were the same shape. Python was the
exception. `py-hardcoded-cipher-key` was anchored at `AES.new` from the start,
so a Python mirror of the false-positive class produced no findings even before
this slice.

## STEP 0: what semgrep 1.176.1 OSS can express, per language (measured)

Every probe ran in the scratchpad before any rule was edited.

### (a) Taint: a string literal reaching a key parameter, intra-procedurally

Source `"..."` (later `"$LIT"`); the sink is the key, IV, HMAC-key or
signing-secret argument, via `focus-metavariable`.

| Shape | Python | Go | JS/TS | Java |
|---|---|---|---|---|
| literal inline at the sink | yes | yes | yes | yes |
| local variable | yes | yes | yes | yes |
| module / class-level constant | yes | `const` yes; package **`var` no** | `const`/`let` yes | `static final` and instance fields yes |
| through an encoding wrapper (`.encode()`, `[]byte()`, `Buffer.from`, `getBytes()`) | yes | yes | yes | yes |
| TS/JS class property (`field = '…'` used as `this.field`) | n/a | n/a | yes | n/a |
| JS constructor assignment (`this.k = '…'`) | n/a | n/a | **no** | n/a |
| across a function or a file | **no** | **no** | **no** | **no** |

Go's package-level `var` is the idiomatic Go hard-coded key: `var key =
[]byte("…")`. A **file-scoped source** reaches it: `pattern-inside: var $HOLDER
= []byte("$GLIT") …` with `pattern: $HOLDER` makes every later use of the global
the source. It reached ungrouped and grouped `var ( … )` declarations alike.
Writing a grouped block as a pattern is not valid Go pattern syntax, so none is
needed or used.

The pattern-only alternative, constant propagation into `sink("...")`, missed
too much. It missed `Buffer.from` in JS; locals and package vars in Go;
`static final byte[]` in Java; and bytes locals and module constants in Python
when spelled `b"..."`. So taint is the mechanism.

### (b) `metavariable-regex` for shape and length, and the entropy analyzer

* **Shape and length:** these work in all four languages. PCRE lookaheads
  work, so "32+ characters with a digit and a letter" is one regex. A PEM
  banner is matchable on the bound literal, JS template literals included.
* **Entropy:** `metavariable-analysis: {analyzer: entropy}` works in all four.
  It **rejected** `welcomebanner_status`, `juiceshop_chat_conversations` and
  `guestBasket`; `deadbeef`×4; prose; URLs; camelCase identifiers; and
  uppercase sentinel-style strings. It **accepted** random hex and base64,
  UUIDs, SHA digests and `0123456789abcdef`×2. `entropy_v2` accepted nothing in
  the same battery and is not used.
* **DER shape:** these prefixes were measured on keys and certificates freshly
  generated with `cryptography`. RSA and every X.509 certificate start `MII…`,
  as does PKCS#8 RSA. RSA-1024 SPKI, EC PKCS#8 and P-384 SEC1 start `MIG…`.
  Short-form keys (Ed25519/X25519 `MC4`/`MCo`, P-256 SEC1 `MHc`, P-256 SPKI
  `MFk`) share no header that base64 *text* does not also produce:
  `base64("0123456789")` is `MDEy…` and `base64("0x1f2e")` is `MHgx…`. So
  `MI[IG]` plus 61 characters is the shape rule, and short forms are left to
  the other branches.

### What else STEP 0 measured, and what each finding decided

1. **Default taint propagates through every call, and that is a false-positive
   factory.** A salt literal flowed through `scryptSync` (JS), `pbkdf2.Key`
   (Go), `SecretKeyFactory` (Java), and `PBKDF2HMAC.derive` or a peppered
   `sha256` (Python), then into the key parameter, and was reported as the key.
   `taint_assume_safe_functions: true` removed every one of them and kept every
   true positive. Encoding wrappers come back as propagators and sink shapes.
   A Go `[]byte(…)` conversion is not a call and still carries taint.
2. **`constant_propagation` (on by default) doubles every constant-backed
   key.** The source pattern also matched the constant's *use* at the sink, so
   each such key produced a second, holder-less result. Turned off, each sink
   produces one result, and taint still reaches module constants and class
   fields. The DER rule showed the same doubling at every use of a DER constant
   and turns it off too.
3. **`pattern-not-regex` does not filter taint sources.** A lookahead on the
   literal's bound content does: `^(?![\s\S]*-----(?:BEGIN|END))(?!MI[IG]…)`.
   Java's `+`-joined PEM still leaked through its unbannered middle lines, and
   a concatenation sanitizer closes that.
4. **`--dataflow-traces` puts no trace in the JSON,** with or without
   `--quiet`. The only `extra` keys are `engine_kind`, `fingerprint`, `lines`,
   `message`, `metadata`, `severity` and `validation_state`. So the scanner
   cannot learn *which* literal reached a sink. It *can* learn its holder: a
   taint message interpolates metavariables bound in the **source**, and gave
   `holder=moduleKey`, `holder=fieldKey`.
5. **A bound metavariable is substituted into any longer, UNBOUND name it
   prefixes.** With `hmac.New($H, …)` bound and `$HOLDER` unbound (the inline
   case), the Go message read `holder=sha256.NewOLDER`. If the key argument's
   metavariable had been the prefix, the key bytes would have reached the
   Finding. All 128 existing rules were checked: none was exposed.
6. **A YAML float anywhere in a rule crashes semgrep:** exit 2, no JSON
   (`found: ScalarFloat: 0.5`). The scanner already fails loud on that exit
   code.
7. **Two shapes matching one call cannot share a `pattern-either`.** semgrep
   keeps one binding per range, and the `Buffer.from(...)`/`.encode()`
   see-through shape lost to the plain one.
8. **`token` in the candidate name gate is a false positive.** The first draft,
   run on the whole Juice Shop tree, flagged `BeeTokenAddress = '0x3643…'`
   (`faucet.component.ts:34`), a blockchain address.

## Decision

### 1. The corroboration model, four rules per pack

| Branch | Rule | Mechanism | `confidence` |
|---|---|---|---|
| PEM shape | `<lang>-pem-block` / `py-pem-*` (unchanged) | regex over the file | 1.0 |
| DER shape | `<lang>-hardcoded-key-der` | a string literal starting `MI[IG]` + 61 base64 chars, not inside a PEM block | 1.0 |
| reaches a sink | `<lang>-hardcoded-key` (+ `py-hardcoded-cipher-key`) | taint: literal → key / IV / HMAC key / signing secret | 1.0 |
| entropy only | `<lang>-hardcoded-key-candidate` | key-ish name + 32+ hex/base64 chars + entropy analyzer | **0.5**, `candidate` |
| a bare key-ish string | none | none | does not fire |

One semgrep rule carries one metadata block, and so one confidence. That is why
each confidence gets its own rule. The branches never double-report one
literal:

- the sink rule's sources exclude PEM and DER shapes;
- the candidate regex excludes a DER header;
- a candidate that also reaches a sink is folded (point 3).

The candidate name gate is `key|secret|passphrase|password|passwd|credential`.
`iv`, `nonce` and `salt` are dropped because none is a secret, and `iv` is a
substring of ordinary words. `token` is dropped per STEP 0 point 8.

### 2. A rule may declare doubt: `confidence` and `candidate`

- **`confidence`** is new rule metadata. It is a string in (0, 1] (point 6)
  and acts as a **ceiling**: the scanner's own verdict is kept when lower, so
  a rule can admit doubt but never manufacture certainty.
- **The `candidate` flag** sets `params.candidate = true`, and a `candidate`
  rule must declare a confidence below 1.0. A rule that says "candidate" and
  claims certainty is a `RulePackContractError`.
- **How an analyst sees it.** The candidate is marked three ways: the rule id
  ends in `-candidate`; `ecdat:confidence` is `0.5`; `ecdat:param:candidate`
  is `True`. It is not flagged critical.
- **Why 0.5.** It sits below the binary scanner's weakest technique
  (`constant`, 0.6). A name and a shape are less evidence than a byte table.

### 3. The holder link, and folding a candidate into its confirmation

A high-entropy key that reaches a sink matches the candidate at its declaration
and the sink rule at its use. Keeping both would put one key in the inventory
twice, once asserted and once doubted. There is no trace to join them (point
4), so they are joined by **name**:

- Both rules declare `holder_metavar`, the identifier the literal was declared
  under, delivered as `holder=`.
- The scanner folds a candidate into every confirmed finding with the same
  holder in the same file.
- The candidate's occurrence, the line the key actually sits on, is appended
  to the confirmed finding. Nothing is dropped.
- The holder lives in `raw["holder"]` and never in `params`, since params are
  identifying and a variable name is not a property of the key. A capture that
  is not identifier-shaped is discarded unstored.
- A test fails any rule, in any pack, in which a metavariable is a proper
  prefix of one its message interpolates (point 5).

### 4. Per pack

* **Go, JS/TS, Java:** `*-hardcoded-key` is rewritten from a name-scoped
  pattern into a taint rule. The DER and candidate rules are new. The PEM rules
  are unchanged.
* **Python:** `py-hardcoded-cipher-key` keeps its id and `algorithm: AES`,
  which is what the QuantumBank KPI calls this artefact, and moves from
  constant propagation to taint. `py-hardcoded-key` covers the model's other
  sinks: HMAC, JWT, Fernet, 3DES and ChaCha20. This **adds** Python recall, for
  keys that were never reported; it closes no Python false positives, because
  there were none of this class. `py-hardcoded-iv` is unchanged.
* Every sink rule sets `taint_assume_safe_functions: true` and
  `constant_propagation: false`, and has a `$LEFT + $RIGHT` sanitizer. An
  assembled key's literal is a part, not the key, and in Python that class is
  `py-assembled-key-material`'s. A test pins all three settings, per rule.

### 5. Low-confidence fire, not no-fire, for the entropy-only case

The alternative was silence: report nothing that does not reach a sink. That is
the most precise option, and it throws away the analyst's best lead. OSS taint
is intra-procedural, so a real key defined in one module and used in another
reaches no sink ECDAT can see.

A high-entropy literal under a key-ish name is exactly what an analyst wants
surfaced. The binary scanner already handles this (ADR-0025): report the
heuristic, fix its confidence by the strength of the evidence, and carry the
technique with it so the number can be argued with. The candidate is that,
for source.

## The Juice Shop acceptance test

`testdata/juiceshop_mirror` mirrors the five false positives and
`lib/insecurity.ts` at the **same paths and line numbers**, with filler in
place of Juice Shop's key material. `tests/test_hardcoded_key_precision.py`
checks it four ways:

1. **Fidelity.** The pre-ADR-0034 `js-hardcoded-key`, vendored in the test,
   fires on exactly the five sites plus `insecurity.ts:21`, as it did in the
   real scan.
2. **The false positives are closed.** The shipped pack produces zero
   findings of any rule in the five files.
3. **The true positive is kept, once.** `js-pem-block` fires at
   `insecurity.ts:21` at 1.0. The PEM also reaches `jwt.sign` and `createHmac`,
   and neither produces a second finding.
4. **The missed key is found.** The inline HMAC key at `insecurity.ts:42`
   fires `js-hardcoded-key` at 1.0, and the mirror scores exactly 1.0 recall
   and precision.

On the **real** Juice Shop tree, scanned read-only through the scanner API:

| | Source findings | Key material |
|---|---|---|
| Before (HEAD rule packs) | 11 | 7: the five false positives, the PEM, and its double report |
| After | 6 | 2: the PEM at `:21`, once, and the HMAC key at `:42` |

## Consequences

**Good.**

* The false-positive class is closed in every pack: a mirror of it in Go,
  JS/TS, Java and Python produces zero findings. On Juice Shop, five false
  positives and a duplicate are gone, and a key the old rule could not see is
  found.
* The existing key-to-cipher fixtures fire at the same count, including Go's
  package-level `var` keys and QuantumBank's `vault.py`. Every existing answer
  key, the QuantumBank KPI and the golden CBOM are unchanged. The four fixture
  roots were diffed file by file between the old and new packs, and there was
  no change outside the new fixtures.
* The KDF, pepper and assembled near-misses STEP 0 found stay silent, and each
  has a fixture.
* **Test counts.** The new module has 101 tests. The red run, across it and the
  seven modules it touches, was 115 failed and 270 passed. The 20 new-module
  tests that passed red are the guards: fidelity, the QuantumBank key, the PEM
  rules, determinism, and the prefix-hazard scan. Green: 1253 passed.

**Costs and limits** (PUNCHLIST):

* **Cross-function and cross-file flow needs Semgrep Pro.** A key declared in
  one module and used in another is a candidate at best, and nothing if its
  literal is low-entropy.
* **The fold is linked by name.** Two literals held under one name in one file,
  one reaching a sink and one not, fold together.
* **Accepted blind spots, all recall gaps and none a false positive:**
  - a JS constructor assignment `this.k = '…'` reaches neither branch;
  - short-form DER keys are not recognised by shape;
  - an all-literal concatenation `"a" + "b"` is sanitized along with the
    assembled class;
  - a Go package `var` reassigned at runtime is still read as its literal;
  - the sink catalogue is finite: no CryptoJS, WebCrypto `importKey`,
    `cipher.NewCTR` or AEAD nonces.
* **Assembled keys in Go, JS and Java are no longer reported as hard-coded.**
  Those packs have no assembled-key rule yet (existing PUNCHLIST entry).
* **The console does not distinguish a candidate yet.** The CBOM carries the
  confidence and the `candidate` param. The Inventory has no badge or filter
  for them, and reads no component confidence.
