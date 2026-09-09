# ADR-0004: Source scanning with Semgrep

* Status: accepted
* Date: 2026-09-09
* Slice: Scanner A — Python source crypto detection
* Supersedes: nothing. Extends [ADR-0001](0001-architecture.md) (scanner contract).

> **Numbering.** The slice frame called for `0003-source-scanning-semgrep.md`,
> but `0003` was already taken by the scan-pipe slice
> ([ADR-0003](0003-scan-pipe.md)). This ADR is `0004`; nothing else changed.

## Context

Scanner A is the first real detector: everything before it was schema,
normaliser and pipe, proved end to end with a stub that returned one fixed
finding. It has to find cryptographic use in Python source and emit `Finding`s
that the existing normaliser can turn into a CycloneDX 1.6 CBOM.

Three constraints from CLAUDE.md bind the design. The scan path is **offline**
— no outbound calls, ever. It is **read-only** against the target. And every
cryptographic fact must **cite a source**, which means the crypto knowledge has
to live somewhere a reviewer can read it, not scattered through Python
conditionals.

The environment check that opens this slice:

```
$ semgrep --version
1.176.1
```

## Decision

### Semgrep is the engine; tree-sitter is on standby

Semgrep already has the Python grammar, a pattern language with metavariables,
`pattern-either` / `metavariable-regex` composition, and the performance work
done. Re-implementing that against tree-sitter would be months of effort to
arrive somewhere worse.

Tree-sitter stays on standby for patterns Semgrep genuinely cannot express, not
as a general alternative. Nothing in this slice needed it — all 28 rules
expressed cleanly. One near-miss is recorded below.

### Rules carry the knowledge; the scanner carries nothing

`scanners/source/__init__.py` knows how to run a subprocess, parse JSON, and
map fields. It contains no algorithm names, no key-size thresholds and no
deadlines. All of that is in `knowledge/rules/python/*.yaml`, one file per
family, each rule's `metadata` giving `algorithm`, `primitive`, `usage` and a
cited `quantum_note`. The contract is written down in
[`knowledge/rules/README.md`](../../knowledge/rules/README.md) and enforced at
runtime — a rule missing a required key raises `RulePackContractError` and
fails the scan.

Adding a detection is adding YAML. Adding a *language* is adding a rule pack,
not a scanner.

### Subprocess over `--json`, not the Python package

Semgrep is invoked as a child process. The CLI's JSON output is a stable public
contract across releases; the internal Python API is not. A subprocess also
isolates the scan — a matcher that segfaults on hostile input kills a child,
not the run.

Every invocation is:

```
semgrep scan --metrics off --disable-version-check --no-rewrite-rule-ids \
             --no-git-ignore --quiet --json --config <rules> <target>
```

with `SEMGREP_SEND_METRICS=off` forced into the child environment.

**On `--offline`:** the slice frame asked for `--offline` or, failing that,
`--metrics off`. Semgrep 1.176.1 has **no `--offline` flag** — `semgrep scan
--offline` exits with `unknown option '--offline'`. `--metrics off` is the
supported spelling and is what the scanner uses, belt-and-braces with the
environment variable. `--disable-version-check` matters too: the version check
is a second, separate call to the registry. The rule pack is always a local
directory, never a registry identifier like `p/python`, so semgrep has no
reason to open a socket at all.

`--no-git-ignore` is deliberate: a `.gitignore` must not be able to hide
cryptography from an audit.

### `usage: unknown` at key generation is a deliberate refusal

`rsa.generate_private_key(key_size=2048)` says nothing about whether the key
will sign or transport. The correct post-quantum replacement differs by usage —
ML-KEM (FIPS 203) for key transport, ML-DSA (FIPS 204) for signatures — so
guessing at the keygen site does not produce a vague recommendation, it
produces a confidently wrong one.

Keygen rules therefore emit `usage: unknown` and the correlator refines it from
the use site in a later slice. This is the fourth pillar (usage-aware
recommendation) being protected at its source.

### Detect the safe things too

SHA-256/384/512 and `os.urandom`/`secrets` have rules, flagged `control`. An
inventory that lists only problems cannot demonstrate coverage, and three-view
drift detection needs to know what is *correct* in the declared view as much as
what is broken.

### Confidence and configurability come from the captured value's shape

Semgrep OSS emits no `metavars` block and redacts `extra.lines` to
`"requires login"`. It *does* interpolate metavariables into `extra.message`
while leaving `metadata` verbatim. So `metadata` declares which metavariable
holds a parameter and `message` — authored as `ecdat|key_size=$KEYSIZE` —
delivers what it bound to. The two are cross-checked at parse time.

A captured value that is a literal (`2048`), a call or dotted reference
(`ec.SECP256R1()`), or an ALL_CAPS name is treated as resolved:
`configurable=False`, `confidence=1.0`. A lower- or mixed-case bare name
(`configured_size`) is unresolved: `configurable=True`, `confidence=0.6`.

### Snippets are read from disk and scrubbed twice

Because `extra.lines` is unavailable, the scanner reads the matched line
itself — which is also what puts redaction under ECDAT's control rather than
the engine's. Two layers:

1. A rule that knows it matches key material sets `redact: true` and its
   snippet becomes `<redacted key material>`.
2. Independently, **any** snippet is scrubbed if it carries a PEM banner or a
   byte-string literal of 8 or more bytes (a DES key is 8).

The second layer is not redundant. `AES.new(b"…", AES.MODE_CBC, iv)` is matched
by both the key-material rule *and* the AES cipher rule, and the cipher rule
has no idea a key literal is on its line. Layer 1 alone would have leaked it.

## Consequences

### What this buys

* 28 rules across 8 families, scoring **100% recall and 100% precision** on the
  41 planted findings in `testdata/python_fixtures`, with zero false positives
  on the decoy file. Precision is asserted at exactly `1.0`, which makes the
  answer key authoritative: a new rule that fires on anything not declared as
  ground truth fails the build.
* PUNCHLIST #3 (snippet redaction) moves from "documented, not enforced" to
  enforced for Python key and PEM matches, with a negative test that plants
  sentinel strings inside fixture key material and asserts none reaches any
  Finding.
* The stub scanner is now redundant. It is **not** removed in this slice —
  doing so changes the API and CLI default scanner lists, which is outside this
  frame. Flagged in PUNCHLIST for the next slice.
  *(Done: [ADR-0005](0005-scanner-registry.md) removed it and replaced both
  hard-coded lists with a registry.)*

### What it costs

* **Semgrep's version is part of the determinism story.** Same input plus same
  knowledge packs gives a byte-identical CBOM only within a matching engine
  version; a semgrep upgrade can change matching. `requirements.txt` pins
  `>=1.176,<2` and this ADR records 1.176.1 as the verified version. A stricter
  pin belongs with the reproducible-build work.
* **No dataflow.** Detection is per-call-site pattern matching. An ALL_CAPS
  constant assigned from `os.environ` is read as hard-coded when it is genuinely
  configurable; a key built by string concatenation and passed to a cipher is
  not seen as key material. Constant propagation and taint tracking are a later
  concern and are where tree-sitter (or Semgrep Pro) may re-enter.
* **The weak-RNG rule is scoped by variable name.** `random.random()` assigned
  to something matching `key|token|secret|nonce|salt|passw|seed|otp|session|iv|auth|cred`
  fires; unscoped it does not. An unscoped rule would fire on every simulation
  and sampler in an estate and destroy precision, and without dataflow the
  variable's name is the only signal available. This trades recall for precision
  knowingly: a weak RNG feeding a badly-named variable is missed.
* **`testdata/` is excluded from ruff.** The fixtures are deliberately-bad
  cryptographic code with undefined names and hard-coded keys; linting them
  would mean "fixing" what the scanner exists to detect, and reformatting them
  would move lines the answer key is measured against.

### The one near-miss, and why it did not need tree-sitter

`ssl.PROTOCOL_$VER` is not a valid Semgrep pattern — a metavariable cannot form
part of an identifier, and the rule fails to parse. Rather than write something
fragile, the rule uses `pattern: ssl.$PROTO` narrowed by a
`metavariable-regex` of `^PROTOCOL_(TLSv1|TLSv1_1|SSLv2|SSLv3|SSLv23)$`. This
is more precise than the original intent — it correctly leaves
`ssl.PROTOCOL_TLS_CLIENT` alone — and stays inside Semgrep. Nothing in this
slice was deferred to tree-sitter.

## Alternatives considered

* **Hand-rolled `ast` / tree-sitter walkers.** Full control, and no subprocess.
  Rejected: it puts the crypto knowledge back into Python code, which is
  precisely what the knowledge-pack requirement forbids, and it means writing a
  pattern matcher per language.
* **Semgrep's registry rulesets (`p/python`, `p/secrets`).** Large, maintained,
  free. Rejected outright: fetching them is a network call in the scan path,
  and their metadata carries OWASP/CWE tags rather than the
  algorithm/primitive/usage triple the CBOM needs. Local rules only.
* **Importing `semgrep` as a library.** Rejected: unstable internal API, and no
  process isolation from a matcher crash.
* **Regex over source.** Rejected on precision. The decoy fixture exists to
  make this concrete — a comment mentioning RSA, a `"md5"` dict key, a
  `md5sum = "file.txt"` variable, a `sign_up()` function and an import of
  `des_moines_geocoder` all survive it, and all would fall to grep.
