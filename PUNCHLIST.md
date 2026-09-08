# ECDAT punch-list (deferrals and known gaps)

- **No stable identity on `Finding`.** Frozen pydantic models with `dict`
  fields (`params`, `raw`) are unhashable, so findings cannot be deduplicated
  or diffed by object identity. The normaliser will need a canonical content
  hash (sorted-key JSON over the identifying fields) before the CBOM
  determinism guarantee in ADR-0001 can be tested end to end.
  *Raised: Phase 0, core schema slice.*
- **`params` is an untyped `dict`.** `key_size`, `curve`, `mode`, `padding`,
  `version`, `valid_to` and friends are unvalidated at the schema layer; a
  scanner can write `keysize` or `"2048"` and nothing complains. Per-algorithm
  parameter schemas belong with the knowledge packs.
  *Raised: Phase 0, core schema slice.*
- **"No secret key material in `snippet`" is documented, not enforced.**
  `Occurrence.snippet` is a free-form string. Given this is a stated invariant
  in ADR-0001, it wants a redaction/length guard plus negative tests once
  scanners exist to violate it.
  *Raised: Phase 0, core schema slice.*
