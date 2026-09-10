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
- **Policy packs are signed with a committed DEV key.** `policy/keys/dev/` holds
  an Ed25519 keypair whose private half is in the repository, so a valid
  signature proves a pack was built by this repo's tooling and nothing about
  who approved it. It exists so `make check` verifies the shipped packs without
  a key-provisioning step. Production needs an offline signing key, a published
  verification key, a release process that uses them, and a rotation story --
  none of which exist. Until then the signature gate defends against accidental
  edits and in-repo tampering, not against an attacker who can commit.
  *Raised: policy engine slice. See [ADR-0007](docs/adr/0007-policy-engine.md).*
- ~~**With only the quantum pack, nothing can reach Critical or High.**~~
  **Resolved** in the mosca/DST/NIST pack slice, and resolved the way it should
  have been -- by adding context rather than by raising a cap. Four categories
  now total 100 (quantum 40, mosca 30, criticality 20, exposure 10), so Critical
  requires a component to be bad on at least three axes at once. The same
  RSA-2048 scores 98/Critical in a BFSI system holding personal data on the
  internet and 45/Medium in an internal lab holding public data.
  `test_the_same_algorithm_is_critical_or_medium_by_context` is the guard: if a
  future edit makes Criticality reachable by tuning a number instead of by
  context, that test is what should stop it.
  *Raised: policy engine slice. Resolved: mosca/DST/NIST slice, see
  [ADR-0008](docs/adr/0008-mosca-dst-nist-packs.md).*
- **`GET /scans` parses every stored CBOM to build its summary.** `band_counts`
  and `max_score` are read back out of each stored document on every list call.
  Correct (the summary must report what was stored, not what today's packs
  would say) but O(scans x document size) per request. Wants the verdict
  summary denormalised onto the scan row when the store gains a migration
  story -- which is also where `scanners_ran` should land.
  *Raised: policy engine slice.*
- **Re-scoring a stored CBOM under updated packs has no entry point.**
  `apply_policy` is idempotent and designed for exactly this, but nothing
  exposes it: there is no `ecdat rescore` command and no API route, so today a
  guidance change means re-scanning. The whole reason scoring is separate from
  normalisation is to make that unnecessary.
  *Raised: policy engine slice.*
- **`quantum_status` severity ordering is hard-coded in the engine.**
  `broken > weakened > adequate > pqc` lives in `policy/engine.py` rather than
  in a pack, so a pack cannot introduce a new status without an engine change.
  Acceptable while `quantum` is the only pack defining the field; revisit if a
  second pack wants its own status vocabulary.
  *Raised: policy engine slice.*
- **The India DST deadlines and assurance mapping are unverified.** The
  2028-12-31 CII deadline, the 2029-12-31 full-adoption deadline, the CII sector
  list and the `assurance:L2A` software mapping in
  `policy/packs/india_dst.yaml` were supplied to ECDAT as roadmap requirements
  and encoded verbatim; they have not been checked line by line against the
  published DST/NQM roadmap text. The structure is right, but a deadline an
  organisation acts on must be confirmed against the source. Hardware,
  key-management and CA assurance levels are deliberately absent rather than
  guessed. The pack header carries the same warning.
  *Raised: mosca/DST/NIST slice. See ADR-0008.*
- **The Y (migration time) model is crude.** `Y = 3 years, +2 if hard-coded` is
  a two-value heuristic derived from one bit of information. Real migration time
  depends on blast radius, test coverage, deployment cadence, vendor
  dependencies and whether the algorithm is negotiated or pinned -- none of
  which ECDAT looks at yet. Every emitted `y_years` carries a basis string
  saying it is an estimate, which is the minimum honest treatment, not a
  substitute for a better model. Revisit once the correlator can measure blast
  radius.
  *Raised: mosca/DST/NIST slice.*
- **The exposure model is three buckets and a default.** internet/internal/
  build/unknown, scored 10/5/2/0, set per TARGET rather than per component --
  so every component in a scan shares one exposure value even though a build
  script and a TLS terminator in the same repo plainly differ. Per-component
  exposure needs the correlator (which asset is actually reachable), and the
  rules deliberately live in their own `exposure` category so they can move to
  their own pack without touching anything else.
  *Raised: mosca/DST/NIST slice. See ADR-0008 Consequences.*
- **Mosca urgency fires on quantum-safe algorithms too.** The
  `mosca-harvest-now-decrypt-later` rule fires on any component with a known
  data lifetime, so AES-256 in a Sovereign-classified system accrues mosca
  points despite not being going to break. Gating it on `quantum_status` makes
  it a second-pass rule, which the engine now supports -- a one-line change,
  deferred so the four-pack merge was proved with the simpler form first.
  *Raised: mosca/DST/NIST slice.*
- **`sector`, `exposure` and `z_years` are not persisted on the scan row.**
  They reach the CBOM as `ecdat:` properties on every component, so the stored
  document is self-describing, but `store.Scan` still records only kind, ref,
  system and data_class. Re-running policy over a stored CBOM under a different
  CRQC horizon therefore needs the caller to remember the original context.
  Belongs with the same store migration as `scanners_ran` and the verdict
  summary.
  *Raised: mosca/DST/NIST slice.*
- ~~**The eBPF probe is UNPROVEN until a human runs it.**~~ **Resolved.**
  `--self-test` PASSED on kernel 7.0.0-31-generic / bcc 0.35.0 / OpenSSL 3.5:
  `SSL_do_handshake` fired 6 times on one real handshake, 8 events captured
  (6 handshake + 2 control `SSL_new`), client and server threads distinguished
  by `tid`, entry/return retval pattern correct, zero decode errors. Pillar 2's
  central technical risk -- does a uprobe attach and deliver on this kernel --
  is retired.
  *Raised: eBPF agent slice 1. Resolved: 2026-09-09, see
  [ADR-0009](docs/adr/0009-ebpf-agent-slice1.md).*
- ~~**Negotiated version and cipher are not read.**~~ **Resolved by
  accessor uretprobes**, with a stated coverage limit. Reading the SSL struct
  was measured and rejected: the cipher needs `ssl+0x900 -> session+0x2f8 ->
  cipher+0x8` through three internal structs with no DWARF to verify against,
  and `SSL_get_negotiated_group` is not exported at all. Instead uretprobes on
  `SSL_get_version`, `SSL_CIPHER_get_name` and `SSL_group_to_name` read the
  returned `const char*` -- no struct offsets anywhere, so nothing can drift
  with an OpenSSL point release.
  **Remaining limit:** these fire only when the observed process asks libssl
  for its own parameters. A silent application yields `enrichment=partial`
  with a reason rather than a guess. Closing that gap means the type-tag-gated
  `0x48` version read, and must carry refuse-on-mismatch.
  *Raised: eBPF agent slice 1. Resolved: enrichment slice, see
  [ADR-0011](docs/adr/0011-enrichment.md).*
- ~~**The agent's observed findings do not reach the store.**~~ **Resolved** by
  the spool seam. The agent writes atomic JSON lines into a directory
  (`--spool`); `scanners/runtime_spool` reads them back as observed Findings
  through the ordinary registry and Finding contract (`--kind spool`). No
  network, no credential in a root process: the filesystem is the trust
  boundary. Ingested files move to `consumed/` so re-scanning cannot
  double-count, and files that yield nothing valid move to `rejected/` so a bad
  producer stays visible. **This unblocks the correlator** — all three views can
  now land in one store, and the cross-view non-merge is proved with real
  declared, shipped and observed findings.
  *Raised: eBPF agent slice 1. Resolved: spool seam slice, see
  [ADR-0010](docs/adr/0010-spool-seam.md).*
- **Runtime coverage is narrower than "TLS on this host".** A `libssl` uprobe
  cannot see statically linked TLS, Go's `crypto/tls`, GnuTLS, NSS or mbedTLS,
  and needs one attach per distinct libssl build in use. The agent reports that
  it cannot attach rather than reporting nothing found, which is the honest
  failure -- but an `observed` view with silent gaps will be read as complete
  unless the CBOM records what was and was not probed.
  *Raised: eBPF agent slice 1.*
- **The agent needs bcc and pydantic in the same interpreter for `--findings`.**
  bcc is a distro package in the system Python; this repo's dependencies are in
  a venv. The attach proof itself needs only bcc -- `agent.to_finding` is
  imported lazily and only under `--findings` -- but anything that builds a
  `Finding` needs both, which today means `sudo python3 -m pip install pydantic`
  into the system interpreter or a `--system-site-packages` venv. This is an
  artefact of the bcc-first decision in ADR-0009; the production libbpf CO-RE
  agent is a self-contained binary with no Python and removes the clash
  entirely, along with the runtime kernel-header dependency.
  *Raised: eBPF agent slice 1, after the first manual attach proof.*
- ~~**The uprobe attaches but captures nothing.**~~ **Resolved: it was the
  three-terminal timing race, not the probe.** The manual walkthrough asks the
  operator to attach *between* starting a server and running a client, and
  every failed run was that ordering rather than anything in the BPF program.
  All four investigated theories -- wrong library, wrong client, versioned
  symbol resolution, IFUNC indirection -- were false. `--self-test` was built
  to make the next diagnosis decisive and fixed the fault by construction, by
  removing the human from the timing.
  **Standing lesson:** when a proof needs a human to perform three steps in the
  right order, "it does not work" and "we ran the test wrong" are
  indistinguishable. Make the test self-contained first.
  *Raised: eBPF agent slice 1. Resolved: 2026-09-09, see ADR-0009.*
- **`--once` against an external process is race-prone.** It is kept for
  observing a real workload, but it is not a proof path: use `--self-test`.
  A later slice that watches a long-running service will want a supervised
  attach-then-signal handshake rather than the operator's timing.
  *Raised: eBPF agent slice 1.*
- **Production transport for observed findings is still a file spool.** ADR-0010
  chose a directory over authenticated HTTP deliberately: the API has no authn,
  and a root sensor holding an API credential would undo the privilege split
  the scan path exists to keep. That reasoning holds for a single host and does
  not for a fleet -- a distributed deployment needs a real transport, which
  needs the API's authn story first. Until then the agent and the scanner must
  share a filesystem.
  *Raised: spool seam slice. See ADR-0010.*
- **The spool grows without bound.** `consumed/` and `rejected/` are never
  pruned, deliberately -- the raw record is the evidence behind an observed
  finding, and deleting it on ingest would throw that away. But a
  continuously-running agent will fill a disk. Needs a retention policy (age or
  size based) and probably compression of `consumed/`.
  *Raised: spool seam slice.*
- **Per-process attribution lives in evidence, not in components.**
  `_drop_position` strips `:pid<N>` for the observed view, so handshakes in two
  processes merge into one "TLS on host X" component with both occurrences
  retained. Right for an inventory -- a PID is ephemeral and not a distinct
  cryptographic artefact -- but a question like "which service negotiated
  TLS 1.0?" has to be answered from the occurrence list rather than the
  component list. Revisit when the correlator needs per-service rollup.
  *Raised: spool seam slice. See ADR-0002 and ADR-0010.*
- **Enrichment coverage depends on the observed application.** The accessor
  uretprobes (ADR-0011) only fire when a process calls `SSL_get_version`,
  `SSL_CIPHER_get_name` or `SSL_group_to_name`. `openssl s_client/s_server` and
  Python's `ssl` module do; a service that never logs its TLS parameters does
  not, and shows `enrichment=partial` with a reason. That is honest, but an
  estate of silent services would have a thin observed view. A gated struct
  read is the fallback if it becomes a real gap.
  *Raised: enrichment slice.*
- **`SSL_CIPHER_get_name` is called per connection by anything that logs.**
  Three extra uretprobes on moderately hot functions is a real cost on a busy
  host; `--no-enrich` turns them off, but there is no measurement of the
  overhead yet. Wants a benchmark before the agent runs anywhere continuously.
  *Raised: enrichment slice.*
- ~~**There is no config scanner, so the primary drift axis has no producer.**~~
  **Resolved.** `scanners/config` parses nginx (`server{}` blocks, so findings
  carry a real `host:port` endpoint), `sshd_config` and `openssl.cnf`.
  100% recall and 100% precision on 11 planted findings across three formats,
  zero false positives on the decoys. R2/R3/R4 now run against a parsed
  declared side -- the drift evidence cites `nginx.conf` at its real line --
  rather than hand-built components.
  *Raised: correlator slice. Resolved: config scanner slice, see
  [ADR-0013](docs/adr/0013-config-scanner.md).*
- **Group drift depends on the observed group being read.** R2's hard finding
  needs `observed_group`, which ADR-0011's accessor uretprobes only capture when
  the process calls `SSL_group_to_name`. Python's `ssl` module does not call it
  as part of `.cipher()`, so the common case may be the weaker
  `declared-pqc-observed-unconfirmed` signal rather than a confirmed downgrade.
  That is honest, and it means the headline drift is likelier to appear as
  "unverified at runtime" than "downgraded" until enrichment coverage improves.
  *Raised: correlator slice. See ADR-0011 and ADR-0012.*
- **An unattributed observation joins every endpoint in its system.** The
  observed view names no endpoint -- a uprobe sees a process, not an nginx
  server block -- so it correlates against every configured endpoint for its
  role. With one endpoint that is right; with several DIFFERENT configurations
  in one system an observation cannot be assigned to one of them and the
  correlator may compare it against the wrong config. Needs socket-level
  attribution in the probe (local address/port at handshake time).
  *Raised: correlator slice.*
- **Only four drift rules, and no shipped-vs-observed rule.** A library the
  image ships but the runtime never loads, or vice versa, is a real drift
  (dead crypto, or crypto arriving from somewhere unaudited) and is not
  detected. Deferred deliberately: the four rules that landed are the ones the
  demo turns on.
  *Raised: correlator slice.*
- **Apache is not parsed, and was deliberately not half-done.** `SSLProtocol`,
  `SSLCipherSuite` and `SSLOpenSSLConfCmd Groups` are individually trivial, but
  Apache's endpoint lives in `<VirtualHost *:443>` plus `ServerName` -- a second
  block grammar, which is the same work as nginx again rather than the cheap
  addition the slice allowed for. A half-parsed Apache config would attribute
  directives to the wrong vhost, which is the one failure mode ADR-0013 is
  arranged to prevent.
  *Raised: config scanner slice. See [ADR-0013](docs/adr/0013-config-scanner.md).*
- **HAProxy, Postfix, strongSwan, Envoy and Ingress annotations are not
  parsed.** Each is another grammar. The three formats that landed are the ones
  the demo turns on; the parser-per-format shape means each addition is
  self-contained.
  *Raised: config scanner slice.*
- **A declared certificate is a reference, not a parse.** `ssl_certificate`
  records the path with `resolved: false`; the file is usually not in the
  scanned tree (it lives in the image), so its key size, signature algorithm
  and validity come from the container scanner instead. Nothing yet joins the
  two, so "this endpoint's certificate is RSA-2048 and expires in 2027" is not
  answerable from a config scan alone.
  *Raised: config scanner slice.*
- **KNOWN GAP: Go and JavaScript source are not scanned.** QuantumBank's
  gateway signs partner callbacks with ECDSA P-256 and embeds a PEM
  certificate, in Go. Scanner A is Python-only (ADR-0004), so ECDAT sees
  neither. Both are planted in the fixture, marked `known_gap: true`, excluded
  from the recall denominator and PRINTED on every `make kpi` run -- the point
  being that the gap is visible rather than hidden by omitting the artefact.
  Go and JS rule packs are the next language slice; the rule-metadata contract
  in `knowledge/rules/README.md` was written to be language-agnostic for
  exactly this.
  *Raised: KPI slice. See [ADR-0014](docs/adr/0014-quantumbank-kpi.md).*
- ~~**P3 fix-it is not built.**~~ **Resolved** by the fix-it slice.
  `correlate/fixit/` proposes a unified diff, applies it to a `tempfile`
  sandbox copy, re-runs the producing scanner over the copy, and releases the
  diff only if the original finding is gone AND no new Critical appeared.
  Never auto-applies; read-only on the real target, proved three ways (a tree
  hash, a `Path.open` write-mode guard, and a mutation test that disables the
  copy and asserts the tree *does* change). Four templates ship:
  `nginx-weak-protocol`, `nginx-add-hybrid-group`, `openssl-cnf-groups`,
  `md5-to-sha256`. **Pillar 3 is complete.**
  *Raised: README, P3 status. Resolved: fix-it slice, see
  [ADR-0015](docs/adr/0015-fixit.md).*
- **The shipped fix templates are a starter set: four templates, two formats,
  one language.** They cover the QuantumBank demo path (nginx, `openssl.cnf`,
  Python MD5) and nothing else. sshd `KexAlgorithms`/`Ciphers` is the obvious
  next one — the config scanner already parses it, so it re-verifies for free.
  Apache, HAProxy, Envoy and Ingress annotations each need their parser first
  (same blocker as the config-scanner punch-list entries above), and Go/JS
  source fixes need their rule packs. The template contract in
  `correlate/fixit/template.py` was written to make each addition
  self-contained: one class, one entry in `DEFAULT_TEMPLATES`.
  *Raised: fix-it slice.*
- **`dep-bump` and `dockerfile-base-bump` are BLOCKED on their producer
  scanner.** Both were in the fix-it slice as framed and were deliberately not
  shipped: nothing in ECDAT reads a Dockerfile or a dependency manifest
  (`scanners/deps` is an empty directory), and the container scanner reads
  `dpkg`/`apk` databases from inside layer blobs of an image tar, which a
  unified text diff cannot patch. Both diffs could be generated and neither
  could be verified by re-scan, which is the one thing ADR-0015 refuses to
  ship. **Add the fix template when the scanner lands** — a Dockerfile parser
  (`FROM`, pinned `apt-get install pkg=version`) resolved against
  `knowledge/libraries.yaml`, or a real `scanners/deps`. The capability floor
  the templates would use is already in the pack
  (`OpenSSL pqc_capable_from: 3.5.0`).
  `test_every_shipped_template_names_a_registered_scanner` is what stops an
  unverifiable template creeping back in.
  *Raised: fix-it slice. See [ADR-0015](docs/adr/0015-fixit.md).*
- **Fixes are verified one at a time, and the loop is expensive.** One sandbox
  copy plus two scans per finding — negligible for config, ~3s per finding for
  source, because semgrep runs twice. Two verified diffs touching the same file
  are each proved ALONE; nothing proves they apply together or that the
  combination is still clean. For the four shipped templates they touch
  distinct lines, but that is a property of these templates rather than a
  guarantee. Wants batching (one sandbox, several independent fixes, one
  re-scan) and a combined-application check before it runs over an estate.
  *Raised: fix-it slice.*
- **"No new Critical" is the only blast-radius gate on a fix.** A fix that
  introduces a new HIGH is accepted and merely reported in `new_findings`.
  Critical is the defensible line for an automatic refusal, but the threshold
  is a policy decision hard-coded in `correlate/fixit/engine.py`
  (`BLOCKING_BAND`) rather than something a pack can set.
  *Raised: fix-it slice.*
- **`ecdat fix` does not update the stored scan, so the dashboard cannot show
  fixes.** It prints diffs, saves `.patch` files and can write a fix-annotated
  CBOM to a file, but it does not write back to the store — silently rewriting
  stored history is worse than not showing fixes. Needs an API route and a
  decision about whether a fix pass produces a new scan row or amends one.
  Belongs with the same store migration that owes `scanners_ran`, the verdict
  summary, and `sector`/`exposure`.
  *Raised: fix-it slice.*
- **`ecdat fix` re-takes `--sector` and `--exposure` because the scan row does
  not keep them.** They are not cosmetic here: they decide whether a finding a
  fix INTRODUCES counts as Critical, and therefore whether that fix is
  rejected. The defaults (`other`/`unknown`) are the permissive direction, so
  a fix run without them is judged more leniently than the scan that found the
  problem. Closed by the same store migration as the entry above.
  *Raised: fix-it slice.*
- **KPI recall is a statement about a fixture we wrote.** 100% on QuantumBank
  means the pipeline detects what it claims to detect on a realistic-but-small
  estate. It does NOT mean ECDAT finds all cryptography, and it should never be
  quoted without the known-gap and unattributable lines that print beside it.
  A second, independently-authored fixture -- ideally from a real codebase
  nobody on the project planted artefacts in -- would be a much stronger claim.
  *Raised: KPI slice.*
- **Unattributable drift is printed but not solved.** Three of six drifts on
  QuantumBank are a consequence of the observed view carrying no endpoint: the
  handshake wildcard-joins every declared endpoint and drifts against ones it
  did not occur on. They are excluded from precision and printed as
  UNATTRIBUTABLE rather than scored either way, because neither "correct" nor
  "invented" is true. The fix is socket-level attribution (local address/port
  at handshake time) in the probe.
  *Raised: KPI slice. See ADR-0012 and ADR-0014.*
- **`scripts/setup.sh` is unverified on a truly fresh machine.** It is
  idempotent, non-destructive, shellcheck-clean, and its dry run
  (`scripts/setup.sh --check`) is verified on the development machine -- but
  every step there reports "already installed", which is exactly the path a
  fresh machine will not take. Only a teammate running it on a clean Ubuntu
  install proves the apt package list, the Docker repository setup, the
  nodesource step and the first-ever venv creation. Until then, treat the
  onboarding path as designed rather than proven, and report the step and the
  remedy it printed if it fails.
  *Raised: onboarding slice. See [docs/ONBOARDING.md](../docs/ONBOARDING.md).*
- **`cryptography` and `pyyaml` were missing from `requirements.txt`.**
  **Resolved**, and worth recording because a clean machine would have hit both:
  `cryptography` (certificate parsing in the container scanner, Ed25519 pack
  signatures in `policy/sign.py`) was satisfied only TRANSITIVELY via
  semgrep -> pyOpenSSL, and `pyyaml` -- imported by four modules in the scan
  path -- was listed only in `requirements-dev.txt`, so a production install
  would have failed on the first scan. A direct import needs a direct
  requirement; neither was caught earlier because the development venv had both
  by accident.
  *Raised and resolved: onboarding slice.*
