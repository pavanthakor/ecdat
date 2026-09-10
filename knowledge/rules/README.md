# ECDAT rule packs — the metadata contract

A rule pack is a directory of Semgrep YAML. Semgrep does the matching; the rule
carries the cryptographic knowledge; `scanners/source` is thin glue that turns
one Semgrep match into one `Finding`. Adding a detection should mean adding
YAML, not Python — and that only works if every rule fills in the same fields.

This document is that contract. It is enforced at runtime: a rule that breaks
it raises `RulePackContractError` and fails the scan rather than emitting a
half-populated Finding.

    knowledge/rules/
      README.md          <- this file
      python/            <- one pack per language
        hashes.yaml      <- one file per algorithm family
        asymmetric.yaml
        ...
      go/
      javascript/        <- targets both .js and .ts
      java/

Semgrep is pointed at `knowledge/rules/` itself, not at one language
subdirectory, and every rule's own `languages:` decides which files it reads.
So adding a language is adding a directory of YAML — no Python changes
(ADR-0023).

## Why the message is a machine channel

Semgrep OSS 1.176 does **not** emit a `metavars` block in `--json` output, and
it redacts `extra.lines` to `"requires login"`. It *does* interpolate
metavariables into `extra.message`, and it passes `extra.metadata` through
verbatim without interpolation.

That asymmetry decides the whole design:

| Where | Carries | Interpolated? |
|---|---|---|
| `metadata` | the static facts — algorithm, primitive, usage, citation | no |
| `message`  | the values captured at the match site | **yes** |

So `metadata` declares *which* metavariable holds a parameter, and `message`
delivers *what it bound to*. The two must agree, and the scanner checks that
they do.

The snippet is read from disk by the scanner, not taken from Semgrep, both
because `extra.lines` is unavailable and because reading it ourselves is what
puts redaction under ECDAT's control.

## Required metadata keys

Every rule must set all four. A missing or non-string value is a hard error.

| Key | Meaning |
|---|---|
| `algorithm` | Canonical algorithm name, already in the spelling the CBOM should use: `RSA`, `SHA-1`, `3DES`, `Ed25519`. Not the library's spelling. Use `unknown` when the pattern genuinely cannot tell (an unparsed PEM banner), never a guess. |
| `primitive` | One of the `Primitive` vocabulary in `core/schema.py`: `pke`, `signature`, `kem`, `key-agreement`, `block-cipher`, `stream-cipher`, `hash`, `mac`, `kdf`, `drbg`, `unknown`. Drives quantum scoring — Shor breaks the first four outright, Grover only halves the rest. |
| `usage` | One of the `Usage` vocabulary: `sign`, `verify`, `key-exchange`, `key-transport`, `encrypt`, `decrypt`, `hash`, `kdf`, `unknown`. |
| `quantum_note` | Prose, **with a citation**: FIPS number, NIST SP/IR section, RFC, or CVE. Per CLAUDE.md there are no uncited crypto facts in a knowledge pack. Say what breaks it, classically or quantumly, and what replaces it. |

## Optional metadata keys

| Key | Default | Meaning |
|---|---|---|
| `asset_type` | `algorithm` | One of the `AssetType` vocabulary. Use `protocol` for TLS/SSH versions, `key` for key material, `certificate` for certificates. |
| `keysize_metavar` | — | Sugar for `capture: {key_size: $X}`. Spelled out separately because key size is the parameter nearly every asymmetric rule needs. |
| `capture` | `{}` | Ordered map of `param_name -> $METAVAR`. See below. |
| `flags` | `[]` | Free-form tags. `critical` sets `params.flagged = true`. Conventions in use: `weak`, `control`, `quantum-vulnerable`, `symmetric`, `key-material`, `override`, `critical`. |
| `mode_flags` | `{}` | Map of a captured `mode` value to why it is dangerous (e.g. `ECB`). A match whose mode is a key here also gets `params.flagged = true`. |
| `redact` | `false` | The rule matches key material. Its snippet becomes `<redacted key material>`. |

## How `capture` works

Declare the parameter, then interpolate the same metavariable into the message
in the same order:

```yaml
- id: py-rsa-keygen
  message: "ecdat|key_size=$KEYSIZE"
  metadata:
    algorithm: RSA
    primitive: pke
    usage: unknown
    keysize_metavar: $KEYSIZE
    quantum_note: "Broken by Shor; disallowed after 2035 (NIST IR 8547)."
  pattern-either:
    - pattern: rsa.generate_private_key(..., key_size=$KEYSIZE, ...)
    - pattern: RSA.generate($KEYSIZE, ...)
```

Rules:

* The message **must** start with `ecdat|`. A rule with no captures uses
  `message: "ecdat|"` exactly.
* Multiple captures are `|`-separated in the declared order:
  `"ecdat|mode=$MODE|padding=$PAD"`.
* The parameter name, not the metavariable name, becomes the `params` key.
  `$KEYSIZE` under `keysize_metavar` lands in `params.key_size`.

### Normalisation is by parameter name

The scanner normalises a captured string according to what it is called. This
is why names matter and why you should reuse the existing ones.

| Parameter | Treated as | `ec.SECP256R1()` → | `MODE_CBC` → | `2048` → |
|---|---|---|---|---|
| `mode`, `curve`, `version` | symbol | `SECP256R1` | `CBC` | `2048` |
| everything else | Python literal if it parses, else the raw text | — | — | `2048` (int) |

Symbol normalisation strips a trailing call, takes the last dotted segment, and
drops a `MODE_` or `PROTOCOL_` prefix. Literal normalisation runs
`ast.literal_eval`, so `"RS256"` becomes the string `RS256` and `2048` becomes
the integer `2048` — which matters, because `params` is identifying and
`key_size: 2048` and `key_size: "2048"` hash to different artefacts
(PUNCHLIST: untyped params).

### Constant propagation reaches PATTERNS, not captures

Semgrep propagates literals: `algo = "md5"` followed by `hashlib.new(algo, ...)`
is matched by a pattern written against `hashlib.new("md5", ...)`. It works
through locals, module-level constants and branches.

It does **not** reach a `metavariable-regex`. The metavariable binds the SOURCE
TEXT at the call site — `algo`, not `"md5"` — so a rule written like this sees
nothing when the value is assigned earlier:

```yaml
# Matches only a literal AT the call site.
- patterns:
    - pattern: hashlib.new($ALG, ...)
    - metavariable-regex: {metavariable: $ALG, regex: '^["'](?i:md5)["']$'}

# ALSO matches `algo = "md5"; hashlib.new(algo, ...)`.
- pattern: hashlib.new("md5", ...)
```

`metavariable-pattern` is the mechanism to reach a propagated value **while
keeping the metavariable bound**, which a bare literal branch does not — and a
rule with `capture:` needs the binding:

```yaml
- patterns:
    - pattern: jwt.encode(..., algorithm=$ALG, ...)
    - metavariable-pattern:          # evaluated against the PROPAGATED value
        metavariable: $ALG
        pattern-either:
          - pattern: '"RS256"'
```

Note that a `pattern-regex:` *inside* `metavariable-pattern` has the same hole
as `metavariable-regex` — only a real `pattern:` reaches the propagated value.

So a rule whose algorithm is a short closed vocabulary should carry **both**:
the `metavariable-pattern` branch for propagation reach, and the regex branch
for spellings the enumeration does not cover (`Md5`). Measured in ADR-0026
STEP 0 and ADR-0027.

**This is enforced.** `tests/test_dataflow.py` fails any Python rule that
classifies a value passed to a call using `metavariable-regex` alone. A regex
over a variable NAME is exempt and listed by rule id; a metavariable bound as an
attribute suffix (`ssl.$PROTO`) is not an argument position and needs no
exemption.

What propagation does NOT do in the OSS build: it does not follow a class or
attribute reference. `algo = algorithms.AES` then `algo(key)` is invisible.

### A constant the source cannot vary

Captures are extracted from the message by PARAMETER NAME, not by looking up a
metavariable — so a rule may write a constant it genuinely knows straight into
the message:

```yaml
- id: go-aes-cbc
  message: "ecdat|mode=CBC"
  metadata:
    capture:
      mode: CBC        # the constant, not a $METAVAR -- see below
```

Use this only where the language puts the fact somewhere unbindable. In Python
the cipher mode is an argument (`modes.CBC(iv)`) and binds normally; in Go it is
part of the function NAME (`cipher.NewCBCEncrypter`) and there is nothing to
bind. Writing the constant is then the honest report — the call site cannot
select another mode without a code change, and `_is_resolved` correctly reads it
as hard-coded. Spell the constant in `capture` rather than a fake `$METAVAR`, so
a reader can see which it is.

Do **not** use it to assert something the pattern has not actually established.

### Resolved vs configurable

The scanner decides `configurable` and `confidence` from the *shape* of every
captured value, not from the rule:

| Captured value | Verdict | `configurable` | `confidence` |
|---|---|---|---|
| `2048`, `"RS256"` (a literal) | resolved | `false` | `1.0` |
| `ec.SECP256R1()`, `modes.GCM` (call or dotted) | resolved | `false` | `1.0` |
| `MAX_KEY_SIZE` (ALL_CAPS name) | resolved | `false` | `1.0` |
| `configured_size` (lower/mixed-case name) | unresolved | `true` | `0.6` |
| rule captures nothing | resolved | `false` | `1.0` |

If a rule captures several values and any one is unresolved, the whole finding
is `configurable`. The ALL_CAPS convention is a heuristic: a constant assigned
from `os.environ` is genuinely configurable and will be misread. Fixing that
needs constant propagation — see ADR-0004.

## Choosing `primitive` and `usage`

`primitive` is what the algorithm *is*. `usage` is what this call site *does
with it*. Keep them independent — a recommendation is only correct if it
matches usage, and collapsing them produces confident wrong advice.

* **Key generation gets `usage: unknown`, always.** A freshly generated RSA key
  may go on to sign or to transport, and the correct replacement differs
  (ML-DSA vs ML-KEM). The correlator refines usage from the use site. Guessing
  at the keygen site manufactures a wrong migration plan.
* **MACs use `primitive: mac`, `usage: sign`.** The `Usage` vocabulary has no
  `mac` member; authentication is the closest true statement.
* **Protocols use `asset_type: protocol`, `primitive: unknown`.** A TLS version
  is not a primitive. The suites it negotiates are the crypto, and they are
  captured separately.
* **Detect the safe things too.** SHA-256 and `os.urandom` have rules with
  `flags: [control]`. An inventory that only lists problems cannot show
  coverage, and drift detection needs to know what is correct as well as what
  is not.

## Rules for the rule id

* Unique across the whole pack, and **no dots** — the scanner recovers the bare
  id from Semgrep's `check_id` by taking the last dotted segment.
* Prefix with the language: `py-`, `go-`, `js-`, `java-`. `js-` covers both `.js` and `.ts`; the rules declare
  `languages: [javascript, typescript]` and a test asserts the `.ts` half
  actually matches rather than trusting the declaration.
* The id ends up in every Finding's `Occurrence.detail` as `rule=<id>`, so it
  is what an auditor sees. Name it after what it detects, not after the CVE.

## Never put key material in a message

`message` is copied into the Finding. A rule that matches key material must not
interpolate the metavariable that binds to it:

```yaml
# WRONG -- exfiltrates the key into the Finding
message: "ecdat|key=$K"

# RIGHT -- record the fact and the location, nothing else
message: "ecdat|"
metadata:
  redact: true
```

`redact: true` drops the snippet. It does **not** sanitise the message — that
is the rule author's responsibility, and there is a negative test for it
(`test_no_planted_secret_reaches_any_finding`).

Independently of any rule, the scanner scrubs every snippet: a line carrying a
PEM banner is dropped entirely, and any byte-string literal of 8 bytes or more
is replaced. That second layer exists because a rule about a *cipher* routinely
matches the same line a key literal sits on, and that rule has no idea the key
is there. Write the `redact` flag anyway; do not rely on the net.

## Testing a new rule

Every rule needs three things before it lands, all under `testdata/`:

1. `must_fire/<rule_id>.<ext>` — minimal code that must produce the Finding.
   One fixture root per language: `testdata/python_fixtures`,
   `testdata/go_fixtures`, `testdata/js_fixtures`, each with its OWN
   `answer_key.yaml` and its own score. Language packs are never averaged
   together — one combined number would let a strong pack carry a weak one
   (ADR-0023).
2. An entry in `answer_key.yaml` giving the expected algorithm, primitive,
   usage, asset type, occurrence count, and any `params_any` values the rule
   must capture.
3. Nothing new firing on that language's `must_not_fire/decoys.<ext>`. Each
   decoy file plants the four false positives worth worrying about: prose
   naming an algorithm, an identifier that reads like a digest holding a
   non-secret, a name-scoped RNG rule's non-key use, and a non-crypto import
   whose name looks cryptographic.

The answer key is scored, and **precision is asserted at exactly 1.0**. A rule
that fires on something not declared as ground truth fails the build even if
the detection looks reasonable — which forces every new detection to be
declared before it is allowed to count.
