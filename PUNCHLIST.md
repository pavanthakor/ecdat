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
- **Schema changes are additive-only, by rule, not by accident.** `init_db()`
  introspects `PRAGMA table_info` and issues `ALTER TABLE ... ADD COLUMN` for
  anything missing (ADR-0016). Deliberate while ECDAT is one SQLite file per
  developer, with no deployed installations and no downgrade requirement.
  **The moment a change needs to DROP, RENAME or RETYPE a column -- or needs to
  run against a database somebody else owns -- this approach has reached its
  limit and Alembic is the answer, not a bigger `ADDED_COLUMNS`.** The models
  are written so Alembic can be adopted without rework: no SQLite-only types,
  application-generated ids, every added column nullable or defaulted.
  *Raised: store migration. See [ADR-0016](docs/adr/0016-store-migration.md).*
- **`parent_scan_id` is not a database foreign key.** SQLite enforces foreign
  keys only with a per-connection pragma, so declaring one would advertise a
  guarantee that is not switched on. The link is maintained by `core/store.py`,
  the only module that writes it, and nothing prevents an orphan if a parent is
  ever deleted (nothing deletes today). A real FK belongs with the PostgreSQL
  move.
  *Raised: store migration.*
- **Derived-row chains are permitted but unexplored.** Nothing stops a rescore
  of a rescore or a fix against a fix row: the columns allow it, no code walks a
  lineage deeper than one level, and no test covers it. Decide whether chains
  are meaningful (a fix re-verified under a new horizon?) or should be refused,
  before the dashboard starts rendering trees.
  *Raised: store migration.*
- **`POST /scans/{id}/fix` is synchronous and slower than a scan.** Verifying a
  fix copies the target and re-scans it twice per finding, so the request blocks
  for the whole pass. The same job model `POST /scans` has owed since ADR-0003,
  now with a worse worst case.
  *Raised: store migration.*
- **The migration backfills every un-summarised CBOM at first open.** One-off
  and bounded by the number of pre-migration rows, but it makes the first open
  of a large legacy database slower than every open after it. Fine at current
  scale; wants batching if a database ever holds thousands of scans.
  *Raised: store migration.*
- **`verified: true` is an assertion by whoever edits the pack, and the DST
  confirmation is UNWITNESSED.** Nothing checks that a rule's `source` names a
  real document, or that anybody read it; nothing records WHO confirmed it or
  WHEN, and nothing lets a second reader countersign. One person read the
  roadmap on 2026-09-10 and wrote down the sections, and the DST pack now
  contributes 20 points to every CII verdict on that basis. ADR-0017 raises the
  cost of an unchecked fact from "say nothing" to "write a specific false
  citation and sign the pack" — it does not make lying impossible. A verifier
  identity and verification date per fact, plus a second reviewer, is the
  obvious next increment; it needs the production signing story (the dev-key
  entry above) to mean anything.
  *Raised: verified-fact slice. Sharpened: DST confirmation.*
- **Provisional status is not surfaced in the dashboard.** `ecdat:provisional`,
  `ecdat:provisional_rule` and `ecdat:deadline_provisional` are on the
  components and the API serves them, but no view says "this deadline is
  unconfirmed" — which is exactly where a reader would need to see it. A
  deadline shown without its caveat is the failure ADR-0017 exists to prevent,
  reintroduced one layer up.
  *Raised: verified-fact slice.*
- **The `ecdat` version recorded on a scan is a hard-coded string.**
  `core.ECDAT_VERSION` is not derived from a git tag or a build, so it will
  drift from reality the first time somebody forgets to bump it. Wants deriving
  from packaging metadata once the repo is a distribution (it deliberately is
  not yet — see `pyproject.toml`).
  *Raised: verified-fact slice.*
- **Pinning semgrep exactly will cause install friction.** `pip install -r
  requirements.txt` on a machine with a different semgrep now downgrades it.
  That is the intended trade — reproducibility over convenience, with the
  mismatch path kept non-fatal — but it is a real cost for anyone who shares an
  environment with another semgrep user.
  *Raised: verified-fact slice.*
- **A derived row records no engine, so its footer says "engine not
  recorded".** A rescore runs no scanner, so `save_rescore` writes no
  `engine_versions` -- literally true of the row, and slightly misleading about
  the artefacts it shows, which DID come from an engine. The console defaults
  to the `kind: "scan"` row so the normal path is unaffected; selecting a
  rescore row from the picker shows the honest-but-thin line. Either inherit
  the parent's engine on a derived row, or have the footer follow
  `parent_scan_id`.
  *Raised: dashboard polish.*
- **The console bundle dropped to 242KB (78KB gzipped)** when the score
  distribution became a labelled div bar chart and Recharts was removed. Slice
  2's roadmap timeline, agility gauge and drift graph may want a charting
  library back; at ten buckets, divs were more precise and needed no
  dependency.
  *Raised: dashboard polish.*
- **Dashboard slice 2 is owed.** Slice 1 shipped the core console (ADR-0018):
  app shell + scan selector, the risk summary strip off the denormalised row,
  the sortable/filterable inventory table, the Mosca slider driving the real
  rescore endpoint, and the drill-down drawer with evidence, fired rules, drift
  and the verified/provisional distinction. A polish pass then took it to
  production density: severity as a left-edge accent, right-aligned tabular
  figures, hairline separators, quiet metadata chips, an (i) affordance instead
  of inline explainers, a live band readout beside the slider, skeleton rows,
  three distinct empty states, and an auditable footer. **Still owed:** the India roadmap
  timeline, the crypto-agility gauge, a fixes view that can trigger a fix pass
  and show its verified diffs as a review queue, and a drift graph. The fix
  data is already parsed and the drawer renders a verified diff when a
  `kind: "fix"` row is selected -- there is just no dedicated view and no way
  to start a fix pass from the console.
  *Raised: dashboard slice 1.*
- **The console has no authentication, and it widens the API gap.** It is a
  static SPA served by the same FastAPI process, so it inherits the API's
  existing authn hole exactly -- and it now puts an estate's full inventory AND
  its verified fix diffs one URL away on an unauthenticated port. No new hole,
  a bigger blast radius. Tracked with the API entry below, which remains the
  largest open item on this list.
  *Raised: dashboard slice 1.*
- ~~**No stored scan carries drift, so the console's drift features show
  nothing on real data.**~~ **Resolved** by the system scan. `ecdat scan-system
  <manifest.yaml>` (and `POST /systems/scan`) runs every applicable scanner
  over every target in a system manifest, normalises the findings into ONE
  CBOM, and runs the correlator over it with all three views present. On
  QuantumBank that is 26 components (17 declared, 4 shipped, 5 observed) and
  **6 drifts**, including the two the demo turns on at
  `payments.quantumbank.invalid:443`: `shipped-cannot-do-declared`
  (X25519MLKEM768 vs OpenSSL 3.0.2) and `declared-pqc-observed-classical`
  (X25519MLKEM768 vs x25519). `GET /scans` reports `drift_counts` summing to 6,
  so the console's DRIFT metric and "Drift only" filter are non-empty. A
  control test asserts a single-target scan still finds NO drift.
  *Raised: dashboard slice 1. Resolved: system-scan slice, see
  [ADR-0019](docs/adr/0019-system-scan.md).*
- **The Mosca slider re-colours in one direction only, on this fixture.**
  Pulling Z in from 11 to 5 moves 15 of 17 components across a band boundary;
  pushing it out to 20 lowers every score by the same 13 points and crosses no
  threshold, because every QuantumBank component shares one data class and
  their Mosca terms move together. Relative ORDER is stable for the same
  reason. Both are asserted in `web/src/api/parse.test.ts` so the limit is
  recorded rather than discovered on stage; a fixture with mixed data classes
  would exercise re-ordering.
  *Raised: dashboard slice 1.*
- **`web/dist/` is git-ignored, so a fresh clone must run `make web` once.**
  The API returns a 503 naming the exact command rather than a bare 404, but it
  is still a step that can be forgotten before a demo. Decide whether to commit
  the build output (fast, ugly) or add it to `scripts/setup.sh` (clean, one
  more thing that must succeed on a fresh machine).
  *Raised: dashboard slice 1.*
- **The console bundle is 619KB (183KB gzipped) in one chunk**, most of it
  Recharts. Fine over localhost, and it is loaded once; wants a manual chunk
  split before it is served over anything slower than a LAN.
  *Raised: dashboard slice 1.*
- **The `frontend-design` skill was not available when the console was built.**
  `/mnt/skills/public/frontend-design/SKILL.md` does not exist on this machine,
  so the visual decisions in ADR-0018 follow the slice brief's constraints and
  the stated SOC-console reference rather than that guidance. Worth a review by
  someone who has it before the console is treated as final.
  *Raised: dashboard slice 1.*
- **`scan-system` is SYNCHRONOUS, and it wants the job model more than
  `POST /scans` does.** It runs every applicable scanner over every target and
  blocks until they are all done -- ~1.5s on QuantumBank, and a real estate
  will not be that. The async job model owed since ADR-0003 now has two
  callers asking for it.
  *Raised: system-scan slice. See [ADR-0019](docs/adr/0019-system-scan.md).*
- **`kpi/harness.py` still merges three scans by hand.** It predates
  `core.system.scan_system` and does the same job worse -- per-target
  normalisation, so de-duplication is not global and two targets producing the
  same artefact would repeat a bom-ref. Rewriting it on top of `scan_system`
  would also make the KPI measure the code path the product actually runs. Not
  done in the system-scan slice so the KPI's numbers stayed comparable across
  the change.
  *Raised: system-scan slice.*
- **Manifest paths are working-directory relative**, so a system manifest is
  only runnable from the repository root. Manifest-relative resolution is the
  better default (move the checkout, the manifest still works) and would change
  every committed ref plus the locator/bom-ref identity that keeps
  `ecdat scan <repo>` and `ecdat scan-system` agreeing. Deferred as one change,
  not two.
  *Raised: system-scan slice.*
- **The system root is "the first path target in manifest order."** Unambiguous
  for one repo, arbitrary for two. It decides what locators are made relative
  to, and therefore component identity, so a manifest naming several checkouts
  would want an explicit `root:` key rather than a positional rule.
  *Raised: system-scan slice.*
- **The observed view in a system scan is a FIXTURE, not a measurement.** The
  committed spool is a recording of one real handshake, kept so a system scan
  is deterministic, offline and needs no root. A system scan observes nothing
  live and must never be presented as though it does; `make prove-pillar2` is
  where the live eBPF claim lives.
  *Raised: system-scan slice.*
- **The API has no authentication and `GET /scans` is unpaginated.** It serves
  an estate's complete cryptographic inventory over plain localhost CORS. Needs
  authn/authz and pagination before it is exposed anywhere but a developer
  machine. **Widened by the store migration:** `GET /scans` now also returns
  every derived row, and `GET /scans/{id}/fixes` serves verified patches for
  the estate's weakest crypto -- a more attractive thing to read without
  credentials than an inventory alone. STILL OWED, and now the largest open
  item on this list.
  *Raised: Phase 0, scan pipe slice. Widened: store migration.*
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
- ~~**Determinism is only guaranteed within one semgrep version.**~~
  **Resolved** by the verified-fact slice. `requirements.txt` pins
  `semgrep==1.176.1` exactly rather than a range, and a test asserts it equals
  `scanners.source.PINNED_SEMGREP_VERSION`. Every scan records the engine that
  produced it on its row (`store.Scan.engine_versions`: the ecdat version plus
  each engine's pinned/installed/matches), and a divergence sets
  `engine_warning` and a structured log line. A mismatch WARNS rather than
  fails, deliberately: a teammate one patch release ahead should not be
  blocked, and what matters is that a surprising result can be traced to the
  engine rather than argued about.
  *Raised: Scanner A slice. Resolved: verified-fact slice, see
  [ADR-0017](docs/adr/0017-verified-facts.md).*
- **`params.flagged` is a boolean where a reason belongs.** The scanner sets
  `flagged: true` for rules tagged `critical` and for modes named in a rule's
  `mode_flags`, but the *why* -- which is written in the rule and is the useful
  part -- is dropped. The policy engine will want the reason, not the bit.
  *Raised: Scanner A slice.*
- ~~**The scan record does not say which scanners ran.**~~ **Resolved** by the
  store migration. `store.Scan.scanners_ran` holds `[{"id", "version"?}]`,
  taken from the scanner SELECTION rather than from which plugins produced
  findings -- a scanner that ran and found nothing has still looked. NULL means
  UNKNOWN (a row predating the column) and `[]` means "known, and nothing ran";
  the two are never collapsed, and a test asserts they stay distinguishable
  through the store and the API.
  *Raised: scanner-registry slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
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
- **GnuTLS and libgcrypt PQC capability is unverified — MECHANISM BUILT,
  values STILL await confirmation.** The one remaining data fill. Entries carry
  `pqc_capable_verified` / `pqc_capable_source`, and `_is_pqc_capable()`
  returns `None` for an unverified floor, so a version filled in WITHOUT a
  confirmed source produces no `pqc_capable` parameter rather than a drift
  verdict nobody checked (ADR-0017). GnuTLS, libgcrypt and NSS are
  `verified: false` with `FILL:` markers naming the upstream NEWS that would
  settle each; OpenSSL 3.5.0 is verified against its release announcement and
  CHANGES.md, which is the one the drift demo depends on.
  **REMAINING WORK:** check GnuTLS NEWS (3.8.x), libgcrypt NEWS (1.11) and the
  Mozilla NSS release notes, then set the version and the flag together.
  *Raised: Scanner C slice. Mechanism: verified-fact slice, see
  [ADR-0017](docs/adr/0017-verified-facts.md).*
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
- ~~**`GET /scans` parses every stored CBOM to build its summary.**~~
  **Resolved** by the store migration. `band_counts`, `max_score`,
  `drift_counts` and `coverage_gaps` are denormalised onto the row by
  `core/summary.py` at save time -- computed in the store, beside the bytes
  they describe, so the columns cannot disagree with them. The migration
  backfills them for older rows, since a summary IS derivable from the stored
  document. The test that defends this corrupts a stored CBOM and asserts the
  summary is unchanged, so a regression to parsing cannot pass.
  *Raised: policy engine slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
- ~~**Re-scoring a stored CBOM under updated packs has no entry point.**~~
  **Resolved** by the store migration. `ecdat rescore <scan-id> [--z-years N]`
  and `POST /scans/{id}/rescore` re-apply the scoring pipeline to the STORED
  document and write a new linked row; no scanner runs, and a test patches
  every registered scanner to prove it. Scoring is now one shared function
  (`orchestrator.score_and_correlate`) so a re-scored document is produced
  exactly the way the original was -- including stripping the correlator's
  carried pre-drift score first, without which a rescore amplified the OLD
  number.
  *Raised: policy engine slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
- **`quantum_status` severity ordering is hard-coded in the engine.**
  `broken > weakened > adequate > pqc` lives in `policy/engine.py` rather than
  in a pack, so a pack cannot introduce a new status without an engine change.
  Acceptable while `quantum` is the only pack defining the field; revisit if a
  second pack wants its own status vocabulary.
  *Raised: policy engine slice.*
- ~~**The India DST deadlines and assurance mapping are unverified.**~~
  **Resolved.** The roadmap was read (2026-09-10) and every DST fact confirmed
  against the primary source — DST/NQM *"Report on Quantum-Safe Ecosystem in
  India: Roadmap to Quantum Resiliency"*, May 2026,
  <https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf>
  — with the document, URL and section on every rule: Sec. 9.0 for the 2027
  foundations/inventory, 2028 CII migration and 2029 full-adoption dates, the
  seven CII sectors and the AES uplift; Sec. 6.0 / Annexure B Table 1 for
  L2A = software security assurance. They score again, and **no code changed**
  to make that happen (ADR-0017).
  **The confirmation found a real error:** the CII sector list had FOUR entries
  and the roadmap gives SEVEN — government, strategic and transport were
  missing. That was the silent kind of mistake: those targets fell through to
  `sector: other`, never fired the CII rule, and under-scored by 20 points with
  nothing to indicate it. `core.scanner.Sector` was widened to match, since a
  sector a pack names that a `Target` cannot carry is a dead rule branch.
  Hardware, key-management and CA assurance levels remain deliberately absent
  rather than guessed.
  *Raised: mosca/DST/NIST slice. Mechanism: verified-fact slice. Confirmed:
  2026-09-10, see [ADR-0017](docs/adr/0017-verified-facts.md).*
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
- ~~**`sector`, `exposure` and `z_years` are not persisted on the scan row.**~~
  **Resolved** by the store migration. All three are columns now, so a derived
  pass reproduces the original judgement instead of re-inventing it. They are
  nullable on purpose: a migrated row leaves them NULL rather than being
  backfilled with a guess, because unlike the verdict summary they are not
  derivable from anything stored.
  *Raised: mosca/DST/NIST slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
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
  image ships but the runtime never loads, or vice versa, is a real drift (dead
  crypto, or crypto arriving from somewhere unaudited) and is not detected.
  Deferred deliberately: the four rules that landed are the ones the demo turns
  on. **Now more visible than it was** -- `ecdat scan-system` puts all three
  views in one document, so the missing rule is the only reason that comparison
  is not made.
  *Raised: correlator slice. Sharpened: system-scan slice.*
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
- ~~**`ecdat fix` does not update the stored scan, so the dashboard cannot show
  fixes.**~~ **Resolved** by the store migration, and resolved the way the
  question was posed: a fix pass writes a NEW row (`kind="fix"`,
  `parent_scan_id` set), never an in-place amend. `store._derived()` issues no
  UPDATE at all, so the parent's immutability is structural rather than a
  convention, and a mutation test performs the amend itself to prove the
  byte-comparison notices. `POST /scans/{id}/fix` and `GET /scans/{id}/fixes`
  give the dashboard its view.
  *Raised: fix-it slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
- ~~**`ecdat fix` re-takes `--sector` and `--exposure` because the scan row
  does not keep them.**~~ **Resolved** by the store migration. Context
  resolution is one shared function -- explicit flag > what the parent row
  recorded > the permissive default -- and the CLI flags now default to `None`
  rather than to `other`/`unknown`, because "unsupplied" and "supplied as the
  default" have to be distinguishable for inheritance to work at all.
  `cli._inherited_context` is a named seam, and a mutation test disables the
  inheritance and asserts the lenient default comes straight back.
  *Raised: fix-it slice. Resolved: store migration, see
  [ADR-0016](docs/adr/0016-store-migration.md).*
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
