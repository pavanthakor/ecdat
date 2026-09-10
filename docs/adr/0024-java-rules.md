# ADR-0024: The Java rule pack, and a language-neutral redaction net

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** Java rule pack (solo)
**Depends on:** ADR-0004 (Scanner A and the rule-metadata contract), ADR-0023
(Go and JS/TS packs; the one-config-root layout and the stated-constant
convention)

## Context

ADR-0023 left Java as the obvious next language: the JCA surface is
well-shaped for Semgrep patterns and needs no engine work, and Java is where
most of the enterprise crypto an NTRO-scale estate actually runs.

It also left a hole it named precisely: *"the byte-literal net is
Python-specific (`b"..."`), so for Go and JS the PEM banner plus `redact: true`
is what does the work."* That was tolerable while no fixture exercised the case
it protects. This slice stopped tolerating it.

## Decision

### 1. JCA-first, and the whole pack is shaped by `getInstance(String)`

32 rules in `knowledge/rules/java/`. Almost everything in Java crypto goes
through a factory taking one string — `Cipher.getInstance("AES/GCM/NoPadding")`,
`Signature.getInstance("SHA256withRSA")`, `MessageDigest.getInstance("MD5")` —
so the algorithm, the mode and the padding all arrive as a single literal, and
the parameters usually arrive in a *second* statement:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
```

So the keygen rules bind the generator with `pattern-inside` and match the
initialiser. That two-statement shape is the pattern most of this pack needs
and is the main thing Java added that Python, Go and JS did not.

Bouncy Castle gets two rules, not a pack. Most of BC is reached through the
same JCA factories the rules above already cover; `RSAKeyGenParameterSpec` and
the named-curve table are the two spellings that appear in application code
often enough to be worth their own patterns.

### 2. The cipher mode is PARSED out of the transformation string

`AES/GCM/NoPadding`, `AES/CBC/PKCS5Padding` and `AES/ECB/PKCS5Padding` are one
grammar, so each rule selects its mode with `metavariable-regex` and then states
the parsed value (`mode=GCM`) using the convention ADR-0023 introduced — while
**also** capturing the whole transformation, so the parse never discards what
the source said. A finding carries both `mode: GCM` and
`transformation: AES/GCM/NoPadding`.

**`Cipher.getInstance("AES")` is reported as ECB.** A transformation naming only
the algorithm takes the provider's default mode and padding, and for SunJCE that
is ECB/PKCS5Padding. This is the highest-value rule in the pack: an operator
grepping the codebase for "ECB" finds nothing, and the cipher is ECB everywhere.
The word appears in no source file and the finding says it anyway.

### 3. A weak digest inside a signature is its OWN rule

`SHA1withRSA` is not "an RSA finding whose transformation string happens to
start with SHA1". A chosen-prefix collision (SHAttered, 2017) yields two
documents sharing one valid signature *whatever the modulus* — so the RSA key
size is irrelevant, the break is classical and available today, and the fix is
the digest rather than the migration. `java-signature-weak-hash` carries
`flagged` and its own note; `java-signature-rsa` does not. A reader should not
have to parse a transformation string to see the difference.

### 4. The AES key size is reported, not flagged

`java-keygenerator-aes` captures `key_size` and stops there. The frame asked for
AES-128 to be flagged; **the policy engine already scores key size against the
data's lifetime**, and CNSA 2.0's requirement is conditional — AES-128 is
acceptable under NIST SP 800-131A Rev.2 for shorter-lived data and unacceptable
for anything that must stay confidential past 2035. A rule that flagged it
unconditionally would be asserting the conditional half of that as a fact and
duplicating the scorer, which is the thing ADR-0004's division of labour exists
to prevent: the rule reports what the source says, the pack says what it means,
the policy engine says how much it matters here.

### 5. The redaction net is now language-neutral — a REAL hole, closed

The frame required the guard to hold for Java "including the cross-rule case
(another rule matching the same line must not leak it)". A fixture was written
to exercise exactly that:

```java
return MessageDigest.getInstance("MD5").digest("JAVASECRETSENTINEL…".getBytes());
```

`java-digest-md5` matches that line. It has no `redact` flag and no idea a
secret is on it. **The test failed, and it should have** — the second layer only
ever recognised Python's `b"..."` spelling, so the guard for Go, JS and Java was
each rule author remembering, with nothing behind them.

`scanners/source/_redact` gains a third case: a quoted literal whose **whole**
content is one unbroken alphanumeric run of 24+ characters, optionally
base64-padded.

Both the bound and the alphabet were chosen by what the net must NOT eat:

| | |
|---|---|
| 8 chars | ate `PKCS5Padding` |
| 16 chars | ate `PBKDF2WithHmacSHA256`, a real `SecretKeyFactory` argument |
| **24 chars** | clears both; an AES-128 key is 32 hex or 24 base64 characters |
| `/` in the alphabet | ate `AES/CBC/PKCS5Padding` — the JCA grammar is built on `/` |
| **`/` excluded** | every transformation survives |

Anchoring to the *entire* literal is what does most of the work: any `/`, `-`,
`_`, `.` or space anywhere in it disqualifies the match, which keeps JCA
transformations, Node suite strings (`aes-256-gcm`) and prose out. A
slash-bearing base64 key is not caught by this layer and is still covered by its
own rule's `redact: true` — this layer is the backstop for the rule that does
not know a key is there, not a replacement for the flag.

**This is an engine change, and the frame said none.** It is ~10 lines in one
function, it closes a hole ADR-0023 documented, and the frame's own redaction
requirement could not be satisfied without it. `test_the_opaque_literal_net_
keeps_algorithm_strings_intact` pins the trade-off from the other side, listing
the strings that must survive.

**The schema-level guard is still owed.** This is a better second layer, not the
trust-boundary check. `Occurrence.snippet` remains a free-form string any
scanner can fill with anything, and the normaliser still copies it into
`evidence.occurrences[].additionalContext` unexamined. Five of six scanner
families are now covered by discipline plus a net; the guard in
`core/schema.py` is what would make it structural, and it is still in PUNCHLIST.

## Consequences

**Good.**

- Java: recall 100% (36/36), precision 100% (36/36), printed on every run.
- Four languages — Python, Go, JS/TS, Java — on one 600-line scanner and one
  metadata contract. Adding Java added zero matching or mapping code.
- The cross-rule redaction case is now genuinely exercised rather than
  incidentally satisfied, and the fix protects Go and JS retroactively.
- `Cipher.getInstance("AES")` — silent provider-default ECB — is detected.

**Costs and limits.**

- **C/C++ is still deferred, and deliberately.** OpenSSL call sites are
  macro-heavy (`EVP_*` behind conditional compilation), so a Semgrep pack over
  them would be fragile in the way this project has said it will not ship.
  That is a tree-sitter question. Rust and C# are simply not started.
- **A slash-bearing base64 key is not caught by the net** (§5), only by its
  rule's flag.
- **32 rules is a starting pack, not the JCA surface.** Unmatched: `SecretKeyFactory` / PBKDF2
  iteration counts, `KeyStore` types (JKS vs PKCS12), `SSLParameters`
  cipher-suite lists, JCA provider selection, and the JCE unlimited-strength
  policy. Each is additive YAML.
- **The name-scoped weak-RNG heuristic is inherited**, and Java makes its worst
  case slightly worse: the `iv` substring matches inside ordinary words
  (`archive`, `derive`, `private`). It only fires in combination with an 8+
  character literal, so the practical rate is low, but it is a heuristic and is
  listed with the others in PUNCHLIST.
- **`java-jwt-jjwt` reports `algorithm: unknown`.** `signWith` takes a
  `SignatureAlgorithm` enum member that may be RS256, ES256 or HS256, and
  `metadata.algorithm` is per-rule. The rule captures which one into
  `params.alg` rather than guessing a family — the same honesty the pack applies
  everywhere else, at the cost of a less specific component name.
