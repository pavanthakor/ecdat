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
- **"No secret key material in `snippet`" is enforced for Python source only.**
  **Partially resolved** in the Scanner A slice. `scanners/source` scrubs every
  snippet twice: a rule that matches key material declares `redact: true` and
  loses its snippet entirely, and independently *any* snippet carrying a PEM
  banner or a byte-string literal of >=8 bytes is redacted. The second layer is
  load-bearing -- `AES.new(b"...", AES.MODE_CBC, iv)` is matched by the cipher
  rule as well as the key rule, and the cipher rule does not know a key is on
  its line. Negative tests plant sentinel strings inside fixture key material
  and assert none reaches any Finding
  (`test_no_planted_secret_reaches_any_finding`,
  `test_key_material_findings_carry_a_redacted_snippet`).
  **Still owed:** the guard lives in the source scanner, not at the trust
  boundary. `Occurrence.snippet` is still a free-form string that any other
  scanner can fill with anything, and the normaliser still copies it into
  `evidence.occurrences[].additionalContext` unexamined. The remaining work is
  a redaction/length guard in `core/schema.py` itself, so the invariant holds
  for the binary, process and network scanners before they are written rather
  than after.
  **Update (Scanner C):** now also enforced for the container scanner, in the
  `shipped` view -- private keys carry a public-key fingerprint and a redacted
  snippet, keystores are never opened, and a negative test reads the planted
  key back out of the fixture and asserts none of its body escaped. Two of
  six scanner families are covered; the schema-level guard is still owed.
  *Raised: Phase 0, core schema slice. Partially resolved: Scanner A slice,
  see [ADR-0004](docs/adr/0004-source-scanning-semgrep.md).*
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
- ~~**`scanners/stub` is a placeholder and must be deleted.**~~ **Resolved** in
  the scanner-registry slice. The package and `tests/test_stub_scanner.py` are
  gone, and the hard-coded scanner lists that made deleting it awkward are gone
  with them: `core/registry.py` is now the single source of truth, and both
  `api/app.py` and `cli.py` ask it rather than naming plugins themselves.
  Adding a scanner is one import and one `register(...)` line in
  `core/registry.py` -- no change to the API or CLI. The orchestration tests
  that used the stub as "a scanner that yields one predictable finding" now use
  a test-local `FixedScanner`, and the end-to-end pipe test was repointed to
  the real source scanner over `testdata/minimal_repo` rather than dropped.
  `tests/test_registry.py` asserts, by parsing the AST of every module, that
  nothing imports `scanners.stub` again.
  *Raised: Phase 0, scan pipe slice. Resolved: scanner-registry slice.*
- **`POST /scans` is synchronous.** The request blocks until the whole scan
  finishes, which is acceptable for a stub and not for a real repo, image or
  host scan. Needs a job model: accept, return a scan id immediately, and let
  the dashboard poll status.
  *Raised: Phase 0, scan pipe slice. See ADR-0003 Consequences.*
- **The API has no authentication and `GET /scans` is unpaginated.** It serves
  an estate's complete cryptographic inventory over plain localhost CORS. Needs
  authn/authz and pagination before it is exposed anywhere but a developer
  machine.
  *Raised: Phase 0, scan pipe slice.*
- **Source detection has no dataflow, so two classes of finding are missed.**
  Scanner A matches per call site. An ALL_CAPS constant assigned from
  `os.environ` is reported as hard-coded when it is genuinely configurable, and
  a key assembled by concatenation before reaching a cipher is not recognised
  as key material. The weak-RNG rule is likewise scoped by variable name
  (`key|token|secret|nonce|...`) because an unscoped `random.random()` rule
  would fire on every simulation in an estate; a weak RNG feeding a
  badly-named variable is missed. Needs constant propagation and taint
  tracking -- Semgrep Pro or a tree-sitter pass.
  *Raised: Scanner A slice. See
  [ADR-0004](docs/adr/0004-source-scanning-semgrep.md) Consequences.*
- **Determinism is only guaranteed within one semgrep version.** "Same input +
  same knowledge packs -> byte-identical CBOM" now also depends on the matching
  engine, which is an external binary. `requirements.txt` pins
  `semgrep>=1.176,<2` and ADR-0004 records 1.176.1 as the verified version, but
  nothing fails the build if the installed engine differs from the one the
  fixtures were scored against. Wants a recorded engine version in the scan
  record, and a stricter pin, as part of reproducible builds.
  *Raised: Scanner A slice.*
- **`params.flagged` is a boolean where a reason belongs.** The scanner sets
  `flagged: true` for rules tagged `critical` and for modes named in a rule's
  `mode_flags`, but the *why* -- which is written in the rule and is the useful
  part -- is dropped. The policy engine will want the reason, not the bit.
  *Raised: Scanner A slice.*
- **The scan record does not say which scanners ran.** `core/registry.py` knows
  what is available and the structured log says what ran, but `store.Scan` keeps
  only the CBOM and the target. So "was this estate ever scanned for binaries,
  or does it just have no binary findings?" cannot be answered from the
  database -- and those two states look identical in the dashboard. Needs the
  scanner set (and ideally each scanner's version) persisted on the scan row.
  *Raised: scanner-registry slice. See
  [ADR-0005](docs/adr/0005-scanner-registry.md) Consequences.*
- **Container scanning ignores layer whiteouts.** A file deleted in a later
  layer still produces a finding from the layer that introduced it. For
  supply-chain purposes that is arguably right -- the bytes shipped -- but it
  is not the same claim as "present in the running filesystem", and the two are
  currently indistinguishable in the CBOM. Needs `.wh.` whiteout handling and a
  `present_in_final_layer` parameter so a reviewer can tell which claim is
  being made.
  *Raised: Scanner C slice. See [ADR-0006](docs/adr/0006-container-scanning.md).*
- **Each container layer blob is held in memory while it is walked.** Layers
  are streamed for iteration, but `_open_image` reads each blob into bytes
  first. Fine for base images and the fixtures; a multi-gigabyte application
  image will want a spooled temporary file under `ctx.scratch_dir`.
  *Raised: Scanner C slice.*
- **GnuTLS and libgcrypt PQC capability is unverified.** `knowledge/libraries.yaml`
  records `pqc_capable_from: null` for both, with a note, because their
  post-quantum support was moving and the first supporting version was not
  confirmed against upstream NEWS. `pqc_capable` is therefore absent rather
  than false for those libraries -- deliberately, since a guessed version would
  be an uncited crypto fact. Verify against upstream NEWS and fill both in
  before any scoring depends on them.
  *Raised: Scanner C slice.*
- **`libssl3` and `libcrypto3` are inventoried as two components.** They are
  one source package shipped as two binaries, and the scanner reports both
  because the image ships both. `params.source_package` carries the link, but
  nothing rolls them up, so an OpenSSL count is currently a package count.
  Belongs to the correlator slice.
  *Raised: Scanner C slice.*
