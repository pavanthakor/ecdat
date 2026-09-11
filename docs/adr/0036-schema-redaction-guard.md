# ADR-0036: Redaction is structural — a schema-level guard no scanner can forget

**Status:** Accepted
**Date:** 2026-09-11
**Slice:** schema-level redaction guard (Tier 4 hygiene)
**Depends on:** ADR-0001 (the schema as the trust boundary), ADR-0004 (the
source scanner's redaction), ADR-0023/0024 (its language-neutral net), ADR-0025
(the binary scanner's), ADR-0034 (the PEM/entropy-in-key-context discipline)

## Context

CLAUDE.md says no secret key material is ever stored. Until this slice that
held by six separate conventions:

- **Source.** `scanners/source` runs every snippet through `_redact`. A
  `redact: true` rule loses its snippet outright. A PEM banner, a byte literal
  of 8 bytes or more, or an opaque 24-character run redacts it too.
- **Container and binary.** They put `<redacted key material>` in place of any
  key snippet.
- **Config, deps and runtime-spool.** They never read key material.

A per-scanner test guarded each convention.

`Occurrence.snippet` was a free-form string, and the normaliser copied it into
`evidence.occurrences[].additionalContext` unexamined. A seventh scanner, or a
new rule in an existing one, that forgot would have put key bytes into the
CBOM, and nothing between it and the store would have noticed. The PUNCHLIST
entry for this was updated six times, once per scanner family, and each update
said the same thing: the schema-level guard is still owed.

## The shape, measured first

- **Every scanner builds `Occurrence(...)` through its constructor**, so
  pydantic validators on the schema run for every finding a scanner emits. The
  schema is a real chokepoint.
- **Two paths skip validators:** `model_construct` and
  `model_copy(update=...)`. The CBOM builder itself uses `model_copy`. The
  normaliser therefore has to be a second chokepoint, not an assumed one.
- **Snippets are not identifying** (`core/identity.py`). Redacting one can
  never move a bom-ref.
- **"This is key material" is already on every Finding that is.**
  - Every rule declared `redact: true` in the packs is `asset_type: key`, or
    `certificate` (which is public).
  - The container and binary key findings are `asset_type: key`.
  - ADR-0034 candidates carry `candidate`.

  No new field is needed.

## Decision

### Where: one module, called from two chokepoints

`core/redaction.py` holds every rule. It is called from:

1. **The schema** (`core/schema.py`):
   - a validator on `Occurrence.locator`, `detail` and `snippet` (rules 1–3);
   - a validator on `Finding.params` (rules 1–2);
   - a validator on `Finding.evidence` (rule 4). `evidence` is declared after
     `scanner_id`, `asset_type` and `params` on purpose, so this validator can
     read them.
2. **The normaliser** (`core/cbom.py::_group_findings`). It re-validates every
   finding with `Finding.model_validate(finding.model_dump())` before
   computing identity. `model_construct` and `model_copy(update=...)` cannot
   reach a CBOM around the guard. The re-validation is idempotent, so the guard
   does not fire twice.

### What: key material, surgically

| # | Rule | Applies to | Replaces |
|---|---|---|---|
| 1 | **Private-key armour**: PEM (PKCS#1, PKCS#8, SEC1, encrypted), OpenSSH, PGP, PuTTY | locator, detail, snippet, string params | the whole text: `<redacted key material>` |
| 2 | **A DER private-key structure** in base64/base64url, hex (contiguous or `:`/space separated), `\x` escapes, byte arrays, or raw bytes. Recognised by decoding (see below). | locator, detail, snippet, string params | that run: `<redacted>` (raw bytes: the whole text) |
| 3 | **A secret-named, high-entropy literal**: an identifier outside the literals names a secret, and a quoted literal or assigned value is 32+ hex/base64 characters with ≥ 3.0 bits per character (ADR-0034's discipline) | snippet | that literal |
| 4 | **Key context**: a finding its own scanner called key material (`asset_type == "key"` unless `material` says public-key or certificate, or the `candidate` flag). Every literal of 8+ characters that is not an algorithm name, long key-shaped bare tokens, byte arrays and escape runs. | snippet | that value |

**Rule 2 is structural.** A run is a private key if it decodes to one of:

- a SEQUENCE whose first element is `INTEGER 0` or `INTEGER 1`, followed by an
  INTEGER, SEQUENCE or OCTET STRING (PKCS#1 RSA, DSA, PKCS#8 v1/v2, SEC1 EC);
- an EncryptedPrivateKeyInfo (PKCS#5 or PKCS#12 PBE OIDs);
- a PKCS#12 PFX;
- an `openssh-key-v1` body.

A certificate, a SubjectPublicKeyInfo and an RSAPublicKey cannot match. Their
first element is a SEQUENCE, or an INTEGER far longer than one byte. So the
rule tells a private key from a public one by what the bytes are, not by how
random they look.

### What it must not touch

The brief's negatives are each protected by a named mechanism, and a test pins
each one:

| Must pass through | Why the guard leaves it alone |
|---|---|
| a config line (`ssl_certificate_key /etc/…/api.key;`) | not a quoted literal or an `=`/`:` assignment, and a path is not key-shaped (`.` is outside the alphabet) |
| an algorithm name (`"PBKDF2WithHmacSHA256"`, `"AES/GCM/NoPadding"`) | made entirely of algorithm, mode, padding and curve vocabulary, even beside a key word and even in key context |
| a certificate, or a public key (PEM, DER hex, or SPKI base64 under a key-sounding name) | not armour for a PRIVATE key; its DER is public; a value that decodes to a complete public structure is exempt from rule 3 |
| a hash digest (`EXPECTED_SHA256 = "e3b0…"`, `key_digest = "e3b0…"`) | no secret name; `digest`/`hash`/`checksum` turn "key" into metadata; a digest never decodes to a private-key structure |
| a bom-ref, a layer digest, a detector detail | no secret context; not DER |
| high entropy with no key context (`request_id = "8f14…"`) | rule 3 needs a secret name; rule 4 needs the scanner's flag |
| ordinary code (`AES.new(key, AES.MODE_GCM, nonce=nonce)`) | no literal to redact |

### Kept: the scanners' own redaction

Defence in depth. The scanners are *stricter* than the guard, and should be:

- the source scanner's opaque-literal net redacts any 24+ alphanumeric literal,
  hash digests included;
- the binary and container scanners redact certificates too.

The guard is the floor under them, not a second opinion. On real scans by the
shipped scanners it never fires. A test scans QuantumBank (five families), the
binary fixtures (the sixth), and the Python and JS key-material fixtures, and
asserts zero redactions.

### Logged: that the backstop acted, never what it removed

Every redaction logs a `key_material_redacted` warning carrying the rule, the
field, the locator and, for rule 4, the scanner id. It never carries the
content, and a test asserts that. Because the shipped scanners never trip the
guard, an entry in that log means a scanner left key material in its evidence.
It is the signal to go fix that scanner.

## Proof

`tests/test_redaction_guard.py`, 71 tests. They were written first, and 37 of
them failed before the guard existed:

- **The seventh scanner.** A `ForgetfulScanner` redacts nothing. It emits a
  PKCS#1 PEM, a base64 PKCS#8 DER literal, a candidate literal and an AWS-style
  secret. It runs through the real `run_scan` (orchestrator, normaliser,
  policy, store). The stored CBOM holds none of those bytes. All four sightings
  are still there as evidence, marked redacted, and the backstop logged exactly
  those four locators.
- **Forgetful families.**
  - The source scanner, with `_redact` switched off, over the ADR-0034 Python
    fixtures: every key-material finding is free of every sentinel, even though
    the raw lines under them carry the sentinels.
  - The container scanner writing the planted key file into its snippets, and
    the binary scanner writing the embedded PEM into its snippets: no body line
    or sentinel survives.
- **Bypasses.** A `model_construct` Finding and a `model_copy(update=...)`
  Finding each carry a PEM key into `normalise()`, and neither reaches the
  CBOM.
- **Every registered scanner id.** The parametrisation comes from the registry,
  so a scanner registered later is covered without editing the test.
- **Encodings.** Rule 1 covers five PEM forms plus PGP and PuTTY. Rule 2 covers
  seven DER encodings and raw bytes. Rules 3 and 4 have their own cases.
- **Negatives.** Twenty lines, plus certificates, public keys, a bom-ref and
  params, pass through byte for byte.
- **Determinism.** Redaction is idempotent. The CBOM is byte-identical
  whatever the input order. A redaction never moves a bom-ref.

## Alternatives considered

- **Leave it with the scanners.** That is the state this ADR ends.
- **Redact only at serialisation (`cbom.py`).** Findings in memory would still
  carry keys: the correlator, the fix-it engine and the logs see Findings,
  not the CBOM. A Finding would also misstate its own content. The schema comes
  first and the normaliser is the second net.
- **Blanket entropy redaction** (the source scanner's opaque net, applied
  everywhere). It eats hash digests, bom-refs and request ids, which are
  exactly the evidence a reviewer needs and which the brief rules out. It stays
  at the source scanner, where that cost was chosen.
- **Reject instead of redact.** One forgetful rule would then abort a whole
  scan. Redacting keeps the finding and its location, which is the evidence
  ECDAT exists to produce, without the secret, and the redaction is logged.
- **A new `key_material` field on Finding.** Not needed:
  `asset_type == "key"` and `candidate` already carry the claim. A new field
  would also change every model dump.

## Consequences and limits (PUNCHLIST)

- **The residual: an unnamed literal on a line matched by a rule that is not
  about the key.** The example is `jwt.encode(claims, "s3cr3t…")` reported by
  the JWT rule. Nothing in that text says the literal is a key, and catching it
  would mean redacting every opaque literal. The source scanner's opaque net
  still covers it. A new scanner that emits such a line for a non-key finding
  would not be caught.
- **A line from the middle of a PEM body** (no armour, and not the start of a
  DER structure) is not recognisable. The scanners snippet the line a match
  starts on, which is the armoured one.
- **Encodings not recognised:** a JWK's private `d` member, and PKCS#12
  contents beyond the PFX header.
- **Rule 3's word lists are heuristics**, ADR-0034's, stated in
  `core/redaction.py`.
- **`raw` is not guarded.** It is never written to the CBOM.
- **Cost:** one extra validation per finding at the normaliser, which is
  negligible against a scan.
