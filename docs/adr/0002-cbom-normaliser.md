# ADR-0002: Content-addressed findings and a deterministic CycloneDX 1.6 CBOM

- Status: accepted
- Date: 2026-09-08
- Slice: Phase 0 — CBOM normaliser (resolves PUNCHLIST #1)
- Follows: [ADR-0001](0001-architecture.md)

## Context

ADR-0001 fixed the shape of the pipeline: scanners emit `Finding`, a normaliser
turns findings into a CycloneDX 1.6 CBOM, and that CBOM is the single internal
model. Two obligations from that ADR were left unimplemented:

1. **Determinism** — "the same input with the same knowledge packs produces a
   byte-identical CBOM". `Finding` had no identity, so nothing could be
   deduplicated or diffed, and the CycloneDX library randomises a serial number
   and stamps a wall-clock timestamp on every document.
2. **One artefact, one component** — six scanner families will report the same
   RSA key or the same TLS configuration. Without a shared name for an
   artefact, the CBOM grows a component per detector, blast-radius counts
   inflate, and drift detection turns into noise.

## Decision

### 1. A finding is named by its content, not by who found it

`core.identity.finding_identity(finding, target)` is a BLAKE2b-128 digest
(32 hex characters) over a canonical, sorted-key JSON encoding of exactly:

    asset_type, primitive, algorithm, params, usage, artefact locus

and of nothing else. `scanner_id`, `view`, `confidence`, `configurable`, `raw`
and snippets are excluded: they describe the *sighting*, not the artefact. The
digest is used verbatim as the CycloneDX `bom-ref`, so a component's address in
the CBOM is a function of what it is.

**The locus** is `target.system or target.ref`, plus every place the finding
was seen, normalised:

| view | rule | why |
| --- | --- | --- |
| declared, shipped | drop a trailing `:<n>` | a line number or byte offset says where *in* the file, not which file |
| observed | drop a trailing `:pid<n>` | a process is not the artefact |
| observed | keep a trailing `:<n>` | a port identifies the service |

Paths are made relative to `target.ref` for repo and directory targets, so the
same service scanned from two checkouts is one artefact.

Deciding on the *view* rather than guessing from the string shape is what keeps
`services/auth/jwt.py:42` (a line) and `api.internal:443` (a port) apart. A
shape heuristic would have to choose one meaning for `:443`.

Leaving `view` out of the identity is deliberate: it is what lets the same
artefact seen in source, in the image and at runtime collapse into one
component carrying three occurrences. Keeping the *path* in is what stops
unrelated artefacts collapsing with it.

### 2. Merge rules

Findings sharing an identity agree on every identifying field by construction,
so only the sighting-level fields need a rule:

- **evidence** — union of occurrences, deduplicated, sorted by (view, locator).
- **confidence** — the maximum; the most confident report wins.
- **configurable** — hard-coded (`False`) beats configurable (`True`) beats
  unknown (`None`). One site that cannot be changed without a code edit makes
  the artefact not freely configurable, which is what the migration-effort
  estimate needs to hear.

Merging is idempotent: re-hashing a merged finding yields the identity it was
grouped under, so a second scan of unchanged input is a no-op diff.

### 3. Mapping into CycloneDX, and where it does not fit

CycloneDX 1.6 is narrower than ECDAT's vocabulary in two places. Neither is
papered over:

- `CryptoAssetType` has four values, not seven. `key` becomes
  `related-crypto-material`; `library`, `module` and `service` are not
  cryptographic assets at all — they are the things that *contain* crypto — so
  they become ordinary `library`/`application` components with no
  `cryptoProperties`. Every component carries an `ecdat:asset_type` property so
  the original term survives.
- `cryptoFunctions` has no name for key exchange or key transport, so both map
  to `other` and the exact term survives in `ecdat:usage`.

### 4. Everything ECDAT-specific lives in `properties`

Nothing ECDAT-specific is written outside the standard `properties` list:
`ecdat:asset_type`, `ecdat:usage`, `ecdat:configurable`, `ecdat:confidence`,
one `ecdat:view` per distinct view, one `ecdat:occurrence` per sighting
(`view|locator|scanner[,scanner]|detail`), and one `ecdat:param:<key>` per
parameter. The parameter properties exist so that a param CycloneDX has no
field for — a cipher-suite list, a certificate serial — still reaches the CBOM
rather than being silently dropped. To any other CycloneDX reader the document
is a plain 1.6 BOM.

### 5. The normaliser writes facts, never judgements

No Mosca value, no risk rating, no DST roadmap deadline, no severity. Those are
assessments *of* a fact and belong to the policy slice, which reads the CBOM.

The one apparent exception is `nistQuantumSecurityLevel` /
`classicalSecurityLevel`, and it is not an exception: only definitional anchors
are written. NIST's PQC security strength categories 1–5 are *defined* by
AES-128, SHA-256, AES-192, SHA-384 and AES-256 (NIST PQC Call for Proposals
§4.A.5, the page the CycloneDX 1.6 schema cites), and category 0 is defined by
the schema as "none of the categories are met" — which is what RSA, DSA, DH,
ECDH, ECDSA and EdDSA are, because Shor's algorithm solves the hard problem
each rests on. Anything requiring an inference ("RSA-3072 is roughly
AES-128-equivalent", "SHA-512 must therefore be category 5") is left unset.

### 6. Determinism, concretely

Four things had to be pinned:

1. **Component order** — findings are merged and emitted in identity order.
2. **Serial number** — derived from the content (UUIDv5 over a digest of the
   scope and the sorted identities) instead of a fresh random UUID, so
   re-scanning unchanged input produces the same document.
3. **Timestamp** — left unset. A timestamp is a fact about the scan run, not
   about the artefacts; a caller who wants one passes it in.
4. **Evidence occurrence order** — the one that was not obvious. A CycloneDX
   `Occurrence` with an unset `bom-ref` hashes on `id(self)` and its
   comparisons are non-transitive (two unset refs are neither equal nor
   ordered), so the library's `SortedSet` ordered evidence by memory address
   and the same input produced two different documents at random. Every
   occurrence is therefore given an explicit `bom-ref` of `<identity>#<n>`.
   That also gives the drift correlator a stable address for a single sighting.

Verified byte-identical across repeated runs, shuffled input order, and
different `PYTHONHASHSEED` values, and pinned by a committed golden CBOM.

### 7. Nothing leaves unvalidated

`core.normalise.normalise()` serialises and then validates against the official
CycloneDX 1.6 JSON schema bundled with `cyclonedx-python-lib`, offline, and
raises `CbomValidationError` rather than returning a document that does not
validate. If the validator itself cannot run (the optional `jsonschema`
dependency is missing) it raises `SchemaValidationUnavailableError` instead of
quietly skipping the check. `make validate` is the CI gate.

## Consequences

Good:

- The CBOM is content-addressed: a `bom-ref` means the same artefact across
  scans, machines and Python versions, which is what makes drift a diff.
- Re-scanning unchanged input yields a byte-identical document, so a diff in CI
  is always a real change.
- Merging is testable as an invariant (identity is stable under merge) rather
  than as a pile of examples.

Costs, accepted:

- **Cross-view merging only happens when the normalised locus genuinely
  matches.** The same RSA seen in source, in a shipped binary and at runtime
  usually has three different paths, so it produces three components, not one.
  That is the right default here — collapsing them would destroy the very
  signal three-view drift detection exists to find — but it means artefact-level
  correlation across views is the correlator's job, not the normaliser's. See
  PUNCHLIST #4.
- `raw` from non-base findings is dropped when findings merge; the scanner and
  detail survive on each occurrence. See PUNCHLIST #5.
- The small table of structural NIST/classical levels lives in code rather than
  in a cited knowledge pack. See PUNCHLIST #6.
- Component order in the output is the library's `SortedSet` order (type, then
  name, then version, then bom-ref), not bom-ref order: `Bom.components` is a
  `SortedSet` with its own comparator and there is no hook to override it. The
  order is total and deterministic, which is what the invariant actually
  requires.

## Alternatives rejected

- **A UUID or a counter per finding.** Not reproducible, so no diff and no
  merge. Rejected — this is the gap PUNCHLIST #1 recorded.
- **Including `view` in the identity.** Simple, and it makes the three views
  trivially separable, but it guarantees that two scanners looking at the same
  file in the same view still merge while nothing ever merges across views. It
  also hard-codes into the identity a distinction the correlator should be free
  to reason about. Rejected.
- **Hashing the whole `Finding`.** Confidence, `raw` and line numbers would all
  change the identity, so nothing would ever merge and the CBOM would churn on
  every scan. Rejected.
- **Serial number pinned to a constant.** Deterministic, but then two genuinely
  different CBOMs claim the same serial, which RFC 4122 and every downstream
  consumer would read as the same document. Rejected in favour of deriving it
  from the content.
- **A custom JSON serialiser to force bom-ref ordering.** Would mean
  re-implementing the library's output layer to satisfy a requirement that
  determinism already meets. Rejected.
