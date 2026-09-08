# ECDAT punch-list (deferrals and known gaps)

- ~~**No stable identity on `Finding`.**~~ **Resolved** in the Phase 0 CBOM
  normaliser slice by `core/identity.py`: `finding_identity()` is a BLAKE2b
  content hash over the identifying fields plus the artefact locus, and it is
  used verbatim as the CycloneDX `bom-ref`. Determinism is pinned by
  `tests/golden/quantumbank.cbom.json` and gated by `make validate`.
  See [ADR-0002](docs/adr/0002-cbom-normaliser.md).
- **`params` is an untyped `dict`.** `key_size`, `curve`, `mode`, `padding`,
  `version`, `valid_to` and friends are unvalidated at the schema layer; a
  scanner can write `keysize` or `"2048"` and nothing complains. Because params
  are identifying, `key_size: 2048` and `key_size: "2048"` currently hash to
  two different artefacts. Per-algorithm parameter schemas belong with the
  knowledge packs.
  *Raised: Phase 0, core schema slice.*
- **"No secret key material in `snippet`" is documented, not enforced.**
  `Occurrence.snippet` is a free-form string, and the normaliser copies it into
  `evidence.occurrences[].additionalContext`. Given this is a stated invariant
  in ADR-0001, it wants a redaction/length guard plus negative tests once
  scanners exist to violate it.
  *Raised: Phase 0, core schema slice.*
- **Cross-view merging only happens when the normalised locus matches.** The
  same RSA seen in source, in a shipped binary and at runtime usually has three
  different paths, so it yields three components rather than one merged
  artefact. This is the deliberate default — merging them would destroy the
  signal three-view drift detection exists to find — but artefact-level
  correlation across views still has to be built in the correlator slice.
  *Raised: Phase 0, CBOM normaliser slice. See ADR-0002 Consequences.*
- **`raw` is dropped for all but the base finding when findings merge.** The
  scanner id and detail of every contributing sighting survive on the
  occurrences, but verbatim detector output does not. Needs the Finding store
  (a later slice) to keep per-sighting `raw` alongside the merged component.
  *Raised: Phase 0, CBOM normaliser slice.*
- **The structural NIST/classical security-level table lives in code.**
  `core/cbom.py` carries the definitional anchors (AES-128/192/256,
  SHA-256/384, and the Shor-broken family at category 0) with their citations
  inline. Per CLAUDE.md this is knowledge-pack material and should move to
  `knowledge/` with the rest, once that format exists.
  *Raised: Phase 0, CBOM normaliser slice.*
