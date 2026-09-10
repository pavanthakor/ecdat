# ADR-0025: Scanner D — binaries, and saying what could not be read

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** binary scanner (ELF + PE), standalone
**Depends on:** ADR-0001 (the Finding contract), ADR-0003 (plugin isolation),
ADR-0006 (container scanning; the `shipped` view and the redaction discipline),
ADR-0017 (the verified-fact gate)

## Context

`scanners/binary/` has been an empty directory since Phase 0, and the README
has said so. It is the fifth of seven planned scanner families and the one that
answers a question none of the others can: **what cryptography is in the
artefact that actually ships, when there is no source, no manifest and no
config file to read?**

That is also the question with the least reliable evidence available. Every
other scanner reads a declaration — a call site, a manifest line, a config
directive — and can be certain of what it read. A binary offers a symbol table
that may have been stripped, an import table that may be empty because the code
is statically linked, byte patterns that may be a coincidence, and strings that
may be version banners or may be log messages.

## Decision

### 1. Heuristic, confidence-scored, and honest about coverage

Three rules, in the order they matter:

**Nothing is ever confidence 1.0.** Each technique carries a fixed confidence
set by what the evidence actually proves, and every finding carries the
technique beside it so the number can be argued with rather than merely
trusted. `test_no_binary_finding_is_ever_certain` asserts it across the whole
scan.

| technique | conf | what it actually proves |
|---|---|---|
| `pem` | 0.95 | a key or certificate is embedded verbatim |
| `symbol` | 0.90 | the linker resolved this named API |
| `oid` | 0.85 | the binary can **name** this algorithm |
| `version-string` | 0.80 | a library banner is present in the image |
| `constant` | 0.60 | a table associated with this algorithm exists |

`pem` outranks `symbol` because it is the one technique here that genuinely
*parses* rather than infers — the bytes decode to a certificate or they do not.
It is still below 1.0: present in the image is not in use at runtime.

The confidences are **fixed, not computed**. A longer S-box match is the same
evidence as a short one, and a technique allowed to raise its own score would
move every downstream risk band in the same direction without anyone deciding
to.

**Coverage is reported, not implied.** `BinaryScanner.coverage()` answers "what
could I read here?" *separately* from "what did I find?", because a scanner
that returns fewer findings on an unreadable artefact has reported a clean
artefact — and a clean report on something nobody could read is worse than no
report, because someone acts on it. A stripped binary says so in prose:

> the static symbol table has been removed (strip): local and statically linked
> cryptographic routines are invisible, and the symbol technique can only see
> what is still imported dynamically. **The finding count here is a FLOOR, not a
> total.**

An unparseable file says something stronger: *"NOTHING was read from it. This
is not a clean result."*

**Techniques are allowed to disagree.** A symbol table entry and an S-box are
different evidence for the same AES. Both are emitted, scored differently, and
left for the correlator — merging them into one averaged claim would destroy
the only thing that makes a low-confidence technique safe to ship.

### 2. Constants are a real technique and a deliberately thin one

Four entries in `knowledge/constants.yaml`, all scored 0.6.

A constant table is the *only* evidence that survives a statically linked,
stripped binary — which is exactly the case where the strong techniques
contribute nothing, so it earns its place. It is also the one that can be
wrong: 32 bytes of a substitution table can appear in a codec, a font or a
compression dictionary, and finding them proves the code is **present**, never
that it runs.

So the pack is four entries rather than forty. This technique's failure mode is
a confident inventory of ciphers a binary does not implement, and an operator
who sees that once stops believing the whole report. The RSA-F4 entry matches
the five-byte DER INTEGER TLV (`02 03 01 00 01`) rather than the bare `01 00
01`, which occurs in almost any binary of reasonable size.

### 3. `directory`, not a new `binary` target kind

`TargetKind` is a closed vocabulary threaded through the schema, the API, the
CLI and the store. Widening it for one scanner would be a schema change to
express something `directory` already says, so the scanner walks a directory
for files starting with an ELF, PE or Mach-O magic number, and also accepts a
`ref` that is a single binary.

**`image` is deliberately NOT claimed.** The container scanner owns image
targets and reads package databases out of layer blobs; handing its extracted
layer contents to this scanner is the obvious next step and is **not done**.
Claiming `image` now would advertise a capability that does not exist.

### 4. Committed fixtures, and one opt-in test against a real binary

`testdata/binary_fixtures/` holds real compiled ELFs, a hand-assembled PE, and
a truncated file. `make_fixtures.sh` records exactly how each was produced.

Committed rather than built at test time, because a test that compiled its own
fixtures would depend on a toolchain, an OpenSSL version and a linker, and
would be measuring those rather than the scanner. Committed bytes make the
answer key exact and the suite hermetic.

The PE is hand-assembled with a real import directory for `bcrypt.dll`. There
is no Windows cross-toolchain on the build host, and Windows CNG is where PE
cryptography lives — a fixture that only carried strings would make "PE is
supported" mean "we can read strings out of a PE", which is not the claim.

`test_a_real_system_libcrypto_is_scanned` is gated behind
`ECDAT_RUN_BINARY_TESTS=1`, the same way the docker tests are gated. Whether
the scanner survives a real 4MB shared library with thousands of symbols is a
different question from whether it is correct, and it depends on what happens
to be installed.

### 5. Precision is scored against the decoy, not the union of the key

A difference from the source rule packs, and a deliberate one. A binary is a
haystack: `elf_openssl_symbols` legitimately contains libc imports, section
names and compiler strings, and demanding that the answer key enumerate every
byte a heuristic could touch would make it a transcript rather than a measuring
stick.

What must hold is that the **non-crypto binary produces exactly nothing** — a
hello-world ELF whose only imports are libc. That is the claim an operator
relies on, and it is asserted at exactly zero.

### 6. Redaction, across the sixth and final family

An embedded private key is recorded by presence, its PEM label, and a
blake2b fingerprint of its own bytes — an identifier that is stable across
scans and carries no part of the key. The snippet is `<redacted key material>`.

Certificates are redacted too, even though a certificate is public: a snippet
is not a place for a blob, and the fields worth having (subject, issuer,
validity, key algorithm and size) are parsed into `params` where they can be
scored. A test asserts no `-----BEGIN` reaches any finding at all.

All six scanner families now enforce this by discipline. **The schema-level
guard in `core/schema.py` is still the real fix** and is still owed:
`Occurrence.snippet` remains a free-form string any scanner can fill with
anything, and the normaliser still copies it into
`evidence.occurrences[].additionalContext` unexamined.

## Consequences

**Good.**

- Recall 100% (22/22 planted), precision 100% (0 findings on the non-crypto
  decoy), printed on every run with a per-technique breakdown.
- All five techniques fire on committed fixtures, and the confidence ordering
  is asserted rather than documented: constants score below everything else,
  OIDs below symbols.
- The coverage report distinguishes "found nothing" from "could not look",
  which is the distinction this scanner exists to make.
- A truncated file is logged and skipped and every other binary in the
  directory is still read.
- LIEF is pinned `>=1.0,<2` for the reason ADR-0017 pinned semgrep: an
  unpinned parser is an engine whose behaviour can change under a scan. The
  accessor for the static symbol table was in fact renamed between LIEF majors
  (`static_symbols` → `symtab_symbols`), and the first implementation reported
  *every* binary as stripped because of it — caught by the test that asserts an
  unstripped binary reports no stripping limitation.

**Costs and limits.**

- **Container → binary wiring is not done** (§3). The scanner cannot see inside
  an image today, which is where most shipped binaries actually live.
- **Stripped and statically linked binaries genuinely reduce recall.** The
  scanner says so per-binary, but saying so does not recover the findings, and
  nothing yet aggregates those limitations into the scan-level report or the
  coverage PDF.
- **PE support is shallower than ELF.** The import directory is read and the
  byte techniques are format-independent, but PE export tables, resource
  sections and .NET metadata are not touched, and the only PE fixture is one
  this project assembled. Mach-O is recognised by magic number and otherwise
  untested.
- **A symbol proves a link, not a call.** `RSA_sign` in the import table means
  the linker resolved it; whether any reachable path calls it needs call-graph
  analysis this scanner does not do.
- **Ambiguous APIs report `unknown` rather than guessing.**
  `EC_KEY_new_by_curve_name` carries both ECDSA and ECDH keys;
  `BCryptSignHash` takes its algorithm from a provider handle. Those findings
  name a primitive or an algorithm of `unknown`, which is honest and is also
  less useful than a name — closing it needs argument tracking.
- **No firmware, no packers, no obfuscation.** A UPX-packed or otherwise
  obfuscated binary presents compressed bytes, and every technique here reads
  the file as laid out on disk.
