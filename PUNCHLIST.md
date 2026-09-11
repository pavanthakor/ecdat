# ECDAT punch-list (deferrals and known gaps)

- ~~**No stable identity on `Finding`.**~~ **Resolved** in the Phase 0 CBOM
  normaliser slice by `core/identity.py`: `finding_identity()` is a BLAKE2b
  content hash over the identifying fields plus the artefact locus, and it is
  used verbatim as the CycloneDX `bom-ref`. Determinism is pinned by
  `tests/golden/quantumbank.cbom.json` and gated by `make validate`.
  See [ADR-0002](docs/adr/0002-cbom-normaliser.md).
- ~~**`params` is an untyped `dict`.**~~ **Resolved for the hash split** by
  [ADR-0029](docs/adr/0029-typed-params-symmetric-scoring.md). `core/params.py`
  is the one place that says what a known param IS -- ten keys, each with its
  coercion and the REASON it has that type -- and the coercion runs inside
  `finding_identity`, so `key_size: 2048` and `key_size: "2048"` produce one
  bom-ref. `prime256v1`, `secp256r1` and `P-256` likewise become one curve.
  An UNKNOWN param passes through unchanged, and a value that will not coerce
  is left as written rather than dropped -- `key_size: "unknown"` is a real
  report.
  **Still owed:** the table is MANUAL. A param that ought to be typed and is
  not listed passes through untyped, silently, and nothing detects the
  omission. Per-algorithm parameter SCHEMAS -- which params an algorithm may
  carry at all, and validation at the schema layer rather than coercion at the
  normaliser -- are still the larger unbuilt thing, and still belong with the
  knowledge packs. The curve alias table is finite too: an unrecognised curve
  keeps its spelling, so two spellings of a curve nobody listed still split.
  *Raised: Phase 0, core schema slice. Hash split resolved: typed-params
  slice.*
- **Stored scans' component IDs may shift after ADR-0029.** Canonicalising a
  param changes the bom-ref of any artefact whose params were non-canonical, so
  re-scoring an old stored scan can produce different ids from the run that
  stored it. Accepted rather than migrated -- stored-scan continuity is not
  relied on anywhere -- but nothing rewrites the old ids, and a report that
  cross-referenced two scans by bom-ref across that boundary would not join.
  *Raised: typed-params slice.*
- ~~**"No secret key material in `snippet`" is enforced for Python source only;
  redaction is per-scanner discipline, and a new scanner could leak.**~~
  **Resolved STRUCTURALLY** by
  [ADR-0036](docs/adr/0036-schema-redaction-guard.md). `core/redaction.py` is
  called from the schema's validators and again from the normaliser, which
  re-validates every finding, so a scanner that forgets -- or a `model_construct`
  that skips the schema -- cannot put key material in the CBOM.
  - **Rules 1–2, on every evidence field and string param:** private-key armour
    goes whole; a DER private-key structure goes in any encoding.
  - **Rule 3, on snippets:** a secret-named high-entropy literal goes.
  - **Rule 4, on key-material findings:** every non-algorithm literal goes.
  - **It is surgical.** Config lines, algorithm names, certificates, public
    keys, hash digests and bom-refs pass through unchanged, and tests pin each.
  - **It is proven against a seventh scanner that redacts nothing**, run
    through the real `run_scan`.
  - **The per-scanner redaction below stays** as defence in depth, and the
    shipped scanners never trip the guard.

  The history follows. *Was:* **Partially resolved** in the Scanner A slice. `scanners/source` scrubs every
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
  key back out of the fixture and asserts none of its body escaped.
  **Update (Go/JS rule packs, ADR-0023):** now also enforced for **source-Go**
  and **source-JS/TS**. Both packs carry `redact: true` key-material rules that
  never interpolate the metavariable binding the secret, each fixture tree
  plants its own sentinels (`GOSECRETSENTINEL`/`GONOTAREALKEY`/`GONOTAREALCERT`
  and the `JS*` equivalents) inside real key material, and a negative test per
  language asserts none reaches any Finding -- including via a DIFFERENT rule
  that matches the same line, which is why the AES rule is declared against the
  hard-coded-key fixture in both answer keys.
  **Update (Java pack, ADR-0024): the second layer is now LANGUAGE-NEUTRAL.**
  It previously recognised only Python's `b"..."` spelling, so on Go, JS and
  Java the guard was each rule author remembering `redact: true` with nothing
  behind them. A Java fixture was written to exercise the case that protects --
  a sentinel hashed by `MessageDigest.getInstance("MD5")` on ONE line, where
  the digest rule has no `redact` flag and no idea a secret is there -- and the
  test failed, correctly. `_redact` gained a third case: a quoted literal whose
  whole content is one unbroken alphanumeric run of 24+ characters. The bound
  and the alphabet were chosen by what the net must NOT eat (8 ate
  `PKCS5Padding`; 16 ate `PBKDF2WithHmacSHA256`; `/` in the alphabet ate
  `AES/CBC/PKCS5Padding`), and
  `test_the_opaque_literal_net_keeps_algorithm_strings_intact` pins that from
  the other side. Five scanner families now have a net as well as discipline.
  **Update (Scanner D, ADR-0025): all SIX scanner families now enforce it.**
  The binary scanner records an embedded private key by presence, its PEM label
  and a blake2b fingerprint of its own bytes -- an identifier stable across
  scans that carries no part of the key -- and redacts certificates too, even
  though a certificate is public, because a snippet is not a place for a blob
  and the fields worth having (subject, issuer, validity, key algorithm and
  size) are parsed into `params` where they can be scored. Tests assert both
  that a planted sentinel reaches no Finding and that no `-----BEGIN` reaches
  one at all.
  **Still owed, unchanged, and now the ONLY thing left:** a slash-bearing
  base64 key is caught only by its own rule's flag, and **the schema-level
  guard in `core/schema.py` is what would make any of this structural** rather
  than six separate scanner-local conventions. `Occurrence.snippet` is still a
  free-form string any scanner can fill with anything, and the normaliser still
  copies it into `evidence.occurrences[].additionalContext` unexamined. Every
  family enforcing it by discipline is exactly the state where the next scanner
  written forgets.
  *Raised: Phase 0, core schema slice. Partially resolved: Scanner A slice,
  see [ADR-0004](docs/adr/0004-source-scanning-semgrep.md). Resolved
  structurally: schema redaction guard slice.*
- **The schema redaction guard's stated residual (ADR-0036).**
  - **Unnamed literals on non-key lines.** The structural guard cannot see an
    UNNAMED key literal on a line matched by a rule that is not about the key.
    The example is `jwt.encode(claims, "s3cr3t...")` reported by the JWT rule:
    nothing in the text says the literal is a key, and catching it would mean
    redacting every opaque literal, hash digests included. Today the source
    scanner's own opaque-literal net covers it. A NEW scanner emitting such a
    line for a non-key finding would not be caught.
  - **Unarmoured PEM body lines.** A line from the middle of a PEM body (no
    armour, and not the start of a DER structure) is not recognisable.
  - **Unrecognised encodings.** A JWK's private `d` member, and PKCS#12
    contents beyond the PFX header.
  - **Heuristic word lists.** Rule 3's secret words and the words that make
    "key" public (`public`, `cert`, `fingerprint`, `digest`, ...) are
    heuristics, ADR-0034's.
  - **`raw` is not guarded.** It is never written to the CBOM.

  *Raised: schema redaction guard slice.*
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
- ~~**`POST /scans` is synchronous.**~~ **Resolved** by
  [ADR-0035](docs/adr/0035-api-hardening.md): it answers 202 with a job id at
  once, a worker thread runs the scan, and `GET /jobs/{id}` reports pending,
  running, done (with the scan id) or failed (with the reason). The console
  polls it; `?wait=true` keeps a synchronous path. *Was:* the request blocked
  until the whole scan finished.
  *Raised: Phase 0, scan pipe slice. See ADR-0003 Consequences. Resolved: API
  hardening slice.*
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
- ~~**`POST /scans/{id}/fix` is synchronous and slower than a scan.**~~
  **Resolved** by [ADR-0035](docs/adr/0035-api-hardening.md): a fix pass is a
  job (202 + job id; the console's Fixes screen polls it). A stored row whose
  target kind ECDAT cannot classify is still refused at once (400), not queued
  to fail. *Was:* the request blocked for the whole pass.
  *Raised: store migration. Resolved: API hardening slice.*
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
  **Update (ADR-0031):** none of them did. The Gantt, the agility gauge and the
  histogram are divs and one SVG arc. The full twelve-screen console is 332KB
  (102KB gzipped) with no charting library.
  *Raised: dashboard polish.*
- ~~**Dashboard slice 2 is owed.**~~ **Resolved** by the Q-orbit console
  ([ADR-0031](docs/adr/0031-qorbit-dashboard.md)): the Migration Roadmap
  deadline Gantt, the Crypto Agility gauge (configurable share real, key-store
  and protocol shown as not computed), a Verified Fixes queue that can start a
  fix pass and shows verified diffs only, and a Declared → Shipped → Observed
  panel per drift finding. The drift "graph" shipped as that per-finding
  panel, not as a node graph. Kept below for the record.
  Slice 1 shipped the core console (ADR-0018):
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
- ~~**The console has no authentication, and it widens the API gap.**~~
  **Resolved** by [ADR-0035](docs/adr/0035-api-hardening.md): the console
  sends an API key on every request, raises a sign-in gate on any 401 with the
  server's reason, and its user menu names the key and its role. A viewer is
  not offered scans, fix passes or patches. *Was:* It is a
  static SPA served by the same FastAPI process, so it inherits the API's
  existing authn hole exactly -- and it now puts an estate's full inventory AND
  its verified fix diffs one URL away on an unauthenticated port. No new hole,
  a bigger blast radius. Tracked with the API entry below, which remains the
  largest open item on this list.
  **Update (ADR-0031):** the Q-orbit console's top-bar user menu is COSMETIC
  until the Tier-3 auth work lands -- it opens, every entry is disabled, and it
  says why in plain text rather than implying a session that does not exist.
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
- ~~**`scan-system` is SYNCHRONOUS, and it wants the job model more than
  `POST /scans` does.**~~ **Resolved for the API** by
  [ADR-0035](docs/adr/0035-api-hardening.md): `POST /systems/scan` is a job,
  and a target the job cannot read fails it with the target named. The CLI's
  `scan-system` stays synchronous on purpose: a terminal waits either way.
  *Was:* It runs every applicable scanner over every target and
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
- ~~**`reports/` is an empty directory.**~~ **Resolved** by the reports slice
  (ADR-0020). Three PDFs render from a STORED scan with no re-scan: `executive`
  (headline numbers, top 5 by risk, the DST framing with its confirmed source),
  `technical` (drift first, then every artefact by band with evidence, fired
  rules, per-category scores and verified fix diffs) and `coverage` (which
  scanners ran, which views were and were NOT collected, and the standing list
  of what ECDAT cannot detect at all). `ecdat report <scan-id> --kind ...` and
  `GET /scans/{id}/report/{kind}`. Provisional facts render as provisional in
  the TEXT, and output is byte-identical across renders.
  *Raised: project start. Resolved: reports slice, see
  [ADR-0020](docs/adr/0020-reports.md).*
- **A module-scoped fixture must isolate its own database.** pytest
  instantiates fixtures broadest-scope-first, so a `scope="module"` fixture
  runs BEFORE the function-scoped autouse fixture in `tests/conftest.py` that
  points `ECDAT_DB` at a tmp file. `tests/test_reports.py` hoists its expensive
  system scan to module scope for speed and therefore has to set `ECDAT_DB`
  itself (`_own_database`). Anyone adding another broad-scoped fixture that
  touches the store needs the same wrapper --
  `test_the_store_writes_where_ecdat_db_points` is the canary that catches it.
  *Raised: reports slice.*
- **Report styling is functional, not designed.** Helvetica, rules and a
  two-column grid -- an artefact you can hand to an auditor, not a brochure. A
  designed template (typography, a cover, the ECDAT mark) is later work and does
  not change any of the content decisions in ADR-0020.
  *Raised: reports slice.*
- **The technical report grows with the estate.** QuantumBank's 26 components
  make ~88KB across a dozen pages; a thousand-component estate would produce
  something nobody reads. Wants filtering (by band, by system, by drift) before
  it is run against anything real.
  *Raised: reports slice.*
- **No report frames a CHANGE.** A fix row and a rescore row are ordinary scans
  and render fine, but nothing says "here is what moved between these two
  scans". A comparison report is the obvious next one, and it is what an
  operator actually wants after a rescore or a fix pass.
  *Raised: reports slice.*
- **The database mismatch is DIAGNOSABLE, not resolved.** `ecdat scan` /
  `scan-system` print the absolute `db=` they wrote to, the API logs the
  absolute path it opened, and `ecdat scans` lists what is actually in the
  current one. Two shells with different `ECDAT_DB` values still produce an
  empty console -- deliberately, because two processes using two databases is a
  legitimate thing to want and reconciling them would be guessing. The rule
  (one `ECDAT_DB` for scanning and serving) is an OPERATIONAL one, documented in
  web/README.md, docs/ONBOARDING.md and the README.
  *Raised: reports slice. See [ADR-0020](docs/adr/0020-reports.md).*
- **reportlab ships no type stubs**, so `reports/layout.py` is an untyped edge
  with a mypy override. Contained to that one module by design; revisit if a
  maintained `types-reportlab` for 4.x appears.
  *Raised: reports slice.*
- ~~**`scanners/deps` is an empty directory.**~~ **Resolved** by Scanner B
  (ADR-0021). Python (`poetry.lock`, `Pipfile.lock`, `requirements.txt`,
  `pyproject.toml`), Node (`package-lock.json`, `yarn.lock`, `package.json`)
  and Go (`go.mod`, `go.sum`), lockfile-preferred, with a manifest-only range
  recorded AS a range and no capability verdict placed on it. 100% recall and
  100% decoy precision on `testdata/deps_fixtures`.
  *Raised: Phase 0. Resolved: deps-scanner slice.*
- **Java and Rust dependencies are not scanned.** `pom.xml`, `build.gradle`,
  `Cargo.toml` and `Cargo.lock` are each another grammar; the parser-per-format
  shape in `scanners/deps` makes each addition self-contained. A fast follow to
  ADR-0021, deliberately not half-done in the same slice.
  *Raised: deps-scanner slice.*
- **A dependency finding is not evidence the library is USED.** A manifest entry
  says the code CAN reach a library, not that it does. Pairing a `library`
  finding with the source call sites that import it is real correlation work and
  is not done: the two sit side by side in the CBOM and nothing joins them. It
  is also what would let a migration plan say "this RSA call site comes from
  THIS dependency", which is the question an engineer actually asks.
  *Raised: deps-scanner slice.*
- **Transitive dependencies are read where the lockfile lists them and not
  otherwise.** `package-lock.json` and `go.sum` name the whole graph;
  `requirements.txt` names only what was asked for. The same project therefore
  reports a different dependency count depending on which file it has, and
  nothing in the output distinguishes "direct dependencies" from "the whole
  resolved graph". A `direct` flag on the finding would.
  *Raised: deps-scanner slice.*
- **Dependency version comparison is numeric-prefix only.** `42.0.5rc1`
  compares as `(42, 0, 5)` -- the conservative reading for a capability
  question, and neither PEP 440 nor semver. A pre-release that genuinely
  precedes its release compares as equal to it. Shared with the container
  scanner via `scanners/libraries.py`, so a fix lands in one place.
  *Raised: deps-scanner slice.*
- **ADR-0035's own limits.**
  - **No TLS of its own.** API keys are bearer tokens: serve on localhost or
    behind a TLS-terminating proxy.
  - **Keys have no expiry or rotation schedule.**
  - **No rate limit or lockout** on failed attempts.
  - **A thin audit trail:** a job's `requested_by`, plus log lines.
  - **Jobs run in the server process and do not survive a restart.** The next
    start marks them failed; it does not resume them.
  - **One API process per database.** The startup sweep would fail another
    process's running jobs.
  - **A viewer may rescore,** so a viewer can add rescore rows.
  - **The console keeps its key in localStorage,** and the server sends no CSP
    header yet.
  - **`/docs` and `/openapi.json` are open.**
  - **Offset pages shift by one** if a row lands mid-browse.
  - **The top bar and Compare offer only the newest 50 rows.** Older ones are
    reached through Scan History.
  *Raised: API hardening slice. See [ADR-0035](docs/adr/0035-api-hardening.md).*
- ~~**The API has no authentication and `GET /scans` is unpaginated.**~~
  **Resolved** by [ADR-0035](docs/adr/0035-api-hardening.md):
  - **Auth:** every data route needs an API key. It is a bearer token; the
    server keeps SHA-256 digests in a key file outside the repository and
    checks them locally.
  - **Roles:** `viewer` reads. `admin` also triggers scans and fix passes, and
    reads `GET /scans/{id}/fixes`.
  - **Pages:** `GET /scans` and `GET /jobs` answer
    `{items, total, limit, offset}`, default 50, max 500.

  *Was:* It serves
  an estate's complete cryptographic inventory over plain localhost CORS. Needs
  authn/authz and pagination before it is exposed anywhere but a developer
  machine. **Widened by the store migration:** `GET /scans` now also returns
  every derived row, and `GET /scans/{id}/fixes` serves verified patches for
  the estate's weakest crypto -- a more attractive thing to read without
  credentials than an inventory alone. STILL OWED, and now the largest open
  item on this list.
  *Raised: Phase 0, scan pipe slice. Widened: store migration.*
- ~~**Source detection has no dataflow, so two classes of finding are
  missed.**~~ **Resolved for PYTHON** by
  [ADR-0026](docs/adr/0026-dataflow.md), and it needed neither Semgrep Pro nor
  a tree-sitter pass -- the OSS build has constant propagation and `mode:
  taint`, which STEP 0 measured before any rule was written.
  An env-sourced key size now reports `configurable=True` while a literal one
  still reports `False` (same algorithm, same rule, the flag is the only
  difference); a concatenation-assembled key reaching a cipher is a key-material
  finding; and a weak RNG is caught by FLOW as well as by name.
  The configurability verdict is applied as an ANNOTATION rather than a second
  finding, because the normaliser's merge rule makes `configurable=False` beat
  `True` -- a correction emitted as its own finding would have been silently
  overruled by the finding it was meant to correct.
  *Raised: Scanner A slice. Resolved (Python): dataflow slice.*
- ~~**Dataflow is PYTHON-ONLY.**~~ **Partly resolved** by
  [ADR-0028](docs/adr/0028-dataflow-all-languages.md): CONST-PROP reach is now
  general. Eleven Java rules and seven JS/TS rules carry a propagation-aware
  `metavariable-pattern` branch, and **the `alg: none` authentication bypass
  behind a variable is closed for JavaScript and TypeScript** (RFC 8725 s3.1) --
  it produced no finding at all before. Go needed no conversion: its crypto API
  classifies with attribute references throughout, so there is no string to
  propagate.
  *Raised: dataflow slice. Const-prop half resolved: all-languages slice.*
- **TAINT rules are still mostly PYTHON-ONLY.** ~~The JS one is the most
  wanted.~~ **The JS weak-RNG-by-flow rule shipped** in
  [ADR-0030](docs/adr/0030-usage-classification.md) with the identity-merge
  argument re-made for JS sinks and the single-component outcome asserted, so
  the name-scoped and flow-based rules can both ship without double-reporting.
  Still owed: the configurability annotation and the assembled-key rule have no
  counterpart in Go, JS or Java, and Go and Java have no weak-RNG-by-flow rule
  at all.
  **Re-verified by [ADR-0037](docs/adr/0037-tier2-leftovers.md):** the JS
  sibling's four cases are asserted and green:
  - flow through a non-key-named variable is found;
  - where both rules fire, they make one component;
  - the name-scoped rule still catches its no-sink case;
  - the non-crypto decoys stay silent.

  Nothing was rebuilt. Go and Java weak-RNG-by-flow remain owed.
  *Raised: all-languages slice. JS weak-RNG resolved: usage-classification
  slice.*
- ~~**usage classification is thin: nothing consumes it, and keygen sites stay
  unknown forever.**~~ **Resolved** by
  [ADR-0030](docs/adr/0030-usage-classification.md), and the audit found worse
  than "thin": **no policy rule conditioned on `usage` at all**, so the RSA
  advice was one string listing every option, and the Python and JS JWT rules
  matched `jwt.decode`/`jwt.verify` while reporting `usage: sign` -- every token
  VERIFIER in an estate was recommended a signing migration. The quantum pack
  now branches (sign/verify -> ML-DSA, transport/exchange -> ML-KEM, otherwise
  the agnostic advice, which SAYS it could not determine the usage); `verify`,
  `key-transport` and `key-exchange` rules exist across four packs where the API
  names them; and a Python keygen refines from its use site.
  *Raised: Scanner A slice. Resolved: usage-classification slice.*
- **USE-SITE REFINEMENT covers Python and Java `Signature` only, and is
  INTRA-PROCEDURAL.**
  - **Coverage.** ADR-0037 added Java `Signature` direction refinement:
    initSign/initVerify on the same variable in the same method. Still not
    written: Go and JS, Java keygen (`KeyPairGenerator`), and the Java JWT
    construction rules.
  - **More limiting than the language gap.** A key generated in a factory and
    used by its caller, which is the common shape in real code, stays
    `unknown` (or keeps its declared default) in every language. Semgrep Pro's
    interprocedural analysis is the fix.
  - **One usage per key.** A key used for TWO things reports only one usage
    (first in sorted rule order -- deterministic, and a limit).

  *Raised: usage-classification slice. Java signatures: ADR-0037.*
- **Two usage rules report an algorithm they cannot know.** **Update
  (ADR-0037):** where getInstance and initVerify share a method, the
  getInstance-side finding is now refined to `verify` and carries the
  algorithm, so the verifier is labelled correctly. `java-signature-verify`
  itself still reports `unknown` at `initVerify`. *Was:*
  `java-signature-verify` reports `algorithm: unknown` because the algorithm was
  chosen at `Signature.getInstance` and `initVerify` only sets the direction --
  joining the two calls is use-site refinement for Java, which is not built. And
  `java-cipher-wrap-mode` reports `RSA` unconditionally: `Cipher.WRAP_MODE`
  names the usage but not the algorithm, and RSA is the overwhelmingly common
  case rather than the only one, so an AES key-wrap would be mislabelled.
  *Raised: usage-classification slice.*
- ~~**Java verifiers are reported as SIGNERS.**~~ **Resolved within a method**
  by [ADR-0037](docs/adr/0037-tier2-leftovers.md).
  - **Mechanism.** The three getInstance signature rules keep `usage: sign` as
    a DEFAULT (`usage_refinable: true`). `java-signature-used-for-verify` /
    `-signing` refine it from `initVerify`/`verify` or `initSign`/`sign` on the
    same variable in the same method. STEP 0 measured this on semgrep 1.176.1
    OSS: typed declarations and later assignments, with a `verify()` on a
    different Signature correctly ignored.
  - **Ground truth.** The Java answer key now declares verifiers as
    `usage: verify`.
  - **Remaining.** A Signature passed in, returned or held in a field keeps
    `sign` (intra-procedural, as in Python). A Signature initialised both ways
    reports `sign`.

  *Was:* `java-signature-rsa` fires at
  `Signature.getInstance("SHA256withRSA")` with `usage: sign` -- but
  `getInstance` cannot know sign from verify; the direction is set later, by
  `initSign` or `initVerify`. So a verifier reports a `sign` finding at
  `getInstance` beside ADR-0030's `java-signature-verify` (`usage: verify`,
  `algorithm: unknown`) at `initVerify`. The same bug class as the JWT verifier
  mislabel ADR-0030 fixed for Python and JS, still open in Java.
  **Consequence:** the migration TARGET is unaffected (sign and verify both map
  to ML-DSA), but the "migrate verifiers first" advice never reaches a Java
  verifier. **Fix:** Java use-site refinement -- `usage: unknown` at
  `getInstance`, refined from `initSign`/`initVerify` in the same method through
  the ADR-0030 annotation mechanism (refinement is Python-only today, above).
  The same join would give `java-signature-verify` its algorithm. Recorded, not
  fixed: `JavaSignatureVerify.java` (the ADR-0030 follow-up fixture) takes its
  `Signature` as a parameter precisely so that no answer key declares the
  mislabel as ground truth.
  *Raised: ADR-0030 report. Recorded: verify-rule coverage follow-up.*
- **`go-ecdsa-verify` labels `ed25519.Verify` as ECDSA.** Its third pattern
  matches Ed25519 verification and reports `algorithm: ECDSA`, while
  `go-ed25519-keygen` labels the same keys `Ed25519`. The migration target is
  unchanged (both are Shor-broken -> ML-DSA), but the inventory names the wrong
  algorithm, so a key's keygen and verify sides would not read as one algorithm.
  **Fix:** split out `go-ed25519-verify` (`algorithm: Ed25519`) with its own
  fixture. No fixture calls `ed25519.Verify` today; the follow-up fixture covers
  `ecdsa.Verify` / `ecdsa.VerifyASN1` only, so no key declares the mislabel.
  *Raised: verify-rule coverage follow-up.*
- ~~**The Go and Java answer-key recall gates are still `>= 0.9` floors.**~~
  **Resolved** by [ADR-0037](docs/adr/0037-tier2-leftovers.md).
  - **Structural guard.** `tests/test_recall_gates.py` fails on ANY recall
    floor in `tests/`.
  - **Sweep.** It found nine, and eight are now `== 1.0`: Go, Java, Python
    dataflow, and the source, config, container, binary and deps scanner
    gates, each measured at 100% first.
  - **The QuantumBank KPI keeps its ADR-0014 pass-line**, a published product
    target, through `report.passes`, with a separate `== 1.0` regression
    guard beside it.

  *Was:*
  `tests/test_rules_go.py` and `tests/test_rules_java.py` assert
  `recall >= 0.9` -- ADR-0027's lesson is that a floor can hide a regression.
  Mitigated, not fixed: every declared case is also asserted on its own by the
  parametrised per-fixture test, and `tests/test_dataflow_multilang.py` scores
  the SAME two answer keys at `== 1.0`. The Python dataflow gate at
  `tests/test_dataflow.py:434` is a floor too. Sweep all three to `== 1.0` in
  one pass. *Raised: ADR-0030 slice. Recorded: verify-rule coverage follow-up.*
- **Shipped rules that no answer key and no test names.** An audit of all 128
  rule ids against every `answer_key.yaml` and every file under `tests/` found
  21; the follow-up covered two (`go-ecdsa-verify`, `java-signature-verify`).
  Three more are ANNOTATION rules whose effect behaviour tests assert without
  naming them (`py-configurable-crypto-input`, `py-keygen-used-for-signing`,
  `py-keygen-used-for-key-transport`). The remaining 16 have nothing that names
  them:
  - Go: `go-des`, `go-jwt-ecdsa`, `go-jwt-hmac`, `go-jwt-none`
  - Java: `java-sslcontext-provider-default`, `java-jwt-auth0-ecdsa`
  - JS: `js-hmac-sha1`, `js-forge-legacy-cipher`, `js-jwt-ecdsa-verify`,
    `js-jwt-hmac-verify`, `js-jwt-none-verify`
  - Python: `py-jwt-ecdsa-verify`, `py-jwt-hmac-verify`, `py-jwt-none-verify`,
    `py-rsa-verify`, `py-keygen-used-for-key-exchange`

  Eight of the sixteen are ADR-0030's own -- the same test-first gap as the two
  fixed rules, wider than first reported. **Fix:** fixtures and answer-key
  entries for each, then a CONTRACT test that fails whenever a rule id appears
  in no answer key and is not on an explicit, reasoned exemption list -- so the
  next untested rule is caught at commit, not in a post-commit audit.
  *Raised: verify-rule coverage follow-up.*
- ~~**The source scanner aborts on one unparseable file (blind on real
  repos).**~~ **Resolved** by
  [ADR-0033](docs/adr/0033-source-scanner-resilience.md). Found scanning OWASP
  Juice Shop: one malformed challenge snippet
  (`data/static/codefixes/registerAdminChallenge_*.ts`) made ECDAT raise
  `SemgrepOutputError` and keep ZERO source findings; the whole codebase yielded
  one dependency finding. Semgrep itself had skipped the file and exited 0 --
  ECDAT treated every entry in its `errors` array as fatal. Now a per-file parse
  error (`warn`, an allowlisted parse type, a named file) is tolerated and the
  file is recorded as a coverage gap (`ecdat:coverage:unparsed` /
  `partially_parsed` in the CBOM metadata, plus a log event); anything else
  still fails loud. *Raised and resolved: source-scanner resilience slice.*
- ~~**The hard-coded-key rules over-fire on plain strings (real-code false
  positives).**~~ **Resolved** by
  [ADR-0034](docs/adr/0034-hardcoded-key-precision.md). Found scanning OWASP
  Juice Shop once ADR-0033 let it scan: `js-hardcoded-key` was NAME-scoped, so
  five Angular storage, cookie and config strings (`guestBasketKey`,
  `STORAGE_KEY` twice, `welcomeBannerStatusCookieKey` twice) were reported as
  hard-coded key material at confidence 1.0, and the PEM at
  `lib/insecurity.ts:21` was reported twice. Go and Java had the same shape. A
  key finding now needs corroboration: a PEM/DER shape or a literal that
  reaches a key parameter (1.0), or a key-ish name holding a high-entropy 32+
  character literal (0.5, marked `candidate`). A bare key-ish string does not
  fire. On the real Juice Shop tree, 7 key-material findings became 2: the PEM,
  once, and an inline HMAC key the old rule never saw.
  *Raised: Juice Shop scan. Resolved: hard-coded-key precision slice.*
- **Cross-function and cross-file key flow still needs Semgrep Pro.** OSS
  taint is intra-procedural (ADR-0026 STEP 0, re-measured in ADR-0034). A key
  declared in `config.js` and used in `crypto.js`, or returned by a helper and
  used by its caller, never reaches the sink rule. It is a low-confidence
  CANDIDATE if its literal is key-ish and high-entropy, and nothing otherwise.
  *Raised: hard-coded-key precision slice.*
- **The candidate fold is linked by NAME.** Semgrep OSS puts no dataflow trace
  in `--json`, so a candidate is folded into a confirmed finding because both
  name the same holder in the same file. Two different literals held under one
  name in one file (shadowing), one reaching a sink and one not, fold together,
  and the second is lost as a separate candidate. A dataflow trace (Pro, or a
  future OSS JSON field) would make the link exact.
  *Raised: hard-coded-key precision slice.*
- **Hard-coded-key blind spots the corroboration model accepts.** Each was
  measured and left for a stated reason (ADR-0034), and each is a recall gap,
  never a false positive:
  - a JS key assigned in a constructor (`this.k = '...'`) reaches neither
    branch;
  - a short-form DER key (Ed25519, X25519, P-256 SEC1/SPKI) is not recognised
    by shape;
  - an all-literal concatenation (`"a" + "b"`) is sanitized along with the
    assembled class;
  - a Go package `var` reassigned at runtime is still read as its literal;
  - the sink catalogue is finite: no CryptoJS, no WebCrypto `importKey`, no Go
    `cipher.NewCTR` or AEAD nonces.

  *Raised: hard-coded-key precision slice.*
- ~~**The console does not show that a finding is a candidate.**~~ **Resolved
  for the Inventory and its drawer** by the
  [ADR-0031 addendum](docs/adr/0031-qorbit-dashboard.md). A finding below
  confidence 1.0, or flagged a candidate, now gets three marks: a dashed
  `candidate` tag, a lighter name, and its confidence written in the row. The
  drawer shows the stored confidence, the verdict and the reason in words.
  "Candidates" / "Confirmed" toggles separate the two kinds. None of this uses
  colour: the band pill and the severity bar are unchanged, and a test asserts
  that. *Raised: hard-coded-key precision slice. Resolved: candidate/confidence
  display slice.*
- **Candidates are marked only in the Inventory.** The Overview's lists, the
  Roadmap, Drift, Agility and Compare still show an artefact without its
  candidate treatment. The browser-side CSV export and the PDFs carry no
  confidence and no candidate flag, so an exported candidate reads as a
  confirmed finding. *Raised: candidate/confidence display slice.*
- ~~**"candidate" covers every finding below 1.0.**~~ **Resolved** the same
  day (ADR-0031 addendum, "Revised the same day"). The table's `candidate` tag
  and the Candidates filter now fire only on the flag (`ecdat:param:candidate`).
  A finding below 1.0 for another reason is **inferred**: no table tag, and its
  confidence and reason are still in the drawer. That covers a 0.6 parameter
  from a variable and every binary-scanner finding. The JS-fixture scan now
  tags 1 of 37 components, not 6, and the binary-fixture scan tags 0 of 22, not
  all 22. *Raised and resolved: candidate/confidence display slice.*
- ~~**"Confirmed" meant exactly 1.0, so an inferred finding was in neither
  toggle.**~~ **Resolved** by [ADR-0035](docs/adr/0035-api-hardening.md) §6.
  "Confirmed" is now every row NOT flagged a candidate, so the two toggles
  partition the table:
  - JS-fixture scan: 1 candidate and 36 confirmed out of 37 (it was 31
    confirmed);
  - binary scan: 0 candidates and 22 confirmed out of 22 (it was 0 confirmed).

  The drawer still shows each finding's confidence and its reason. *Raised:
  candidate-tag follow-up. Resolved: API hardening slice (Part 0).*
- **The console and the coverage PDF do not read `ecdat:coverage:*` yet.** A
  scan whose every file failed to parse is honest in the stored document ("
  nothing could be parsed ... not a clean result") and still LOOKS empty in the
  Inventory and Scans screens and in the PDF. Needs: the parser in
  `web/src/api/parse.ts` to read CBOM metadata, the Coverage screen and the
  Inventory's "no artefacts" empty state to say N files could not be parsed, and
  a section in `reports/coverage.py`. *Raised: source-scanner resilience slice.*
- **Semgrep `Timeout` errors are tolerated SILENTLY.** Pre-existing, and kept
  as-is in ADR-0033 to stay in frame: a rule that timed out on a file produced
  nothing, and nothing records it. It is the same honesty gap as an unparsed
  file and belongs in the same record, as a `timed-out` gap kind per (rule,
  file). *Raised: source-scanner resilience slice.*
- **Semgrep's parsers can recover from a syntax error WITHOUT reporting it.**
  Measured in ADR-0033: `def f(:` over a valid body line produced findings and
  no error, while a harder break produced a `Syntax error` and nothing. ECDAT
  can only report the gaps semgrep reports; a silently-recovered file looks
  fully parsed. Worth checking whether a semgrep option surfaces recovered
  parses. *Raised: source-scanner resilience slice.*
- **Other scanners' unreadable inputs do not reach the document.** The binary
  scanner logs `binary_unparseable` and continues (ADR-0025), but the CBOM says
  nothing about it; `ScanContext.coverage` is now the place to record it.
  *Raised: source-scanner resilience slice.*
- **`test_store`'s "no ./ecdat.db" guard fails whenever an operator's database
  sits in the repo root.** `test_the_store_writes_where_ecdat_db_points` asserts
  `not Path("ecdat.db").exists()`, which is red for a legitimate database a
  console session created, not only for one the test wrote. It should compare
  the file's presence and mtime before and after the test.
  *Raised: verify-rule coverage follow-up (observed); recorded: resilience slice.*
- **A loud semgrep failure says too little.** A broken rule pack raises
  `SemgrepFailedError("semgrep exited 7 on <target>: ")` -- loud, as it must be,
  but with nothing after the colon: `_run_semgrep` quotes stderr, and under
  `--quiet --json` semgrep puts the reason (`InvalidRuleSchemaError`, "invalid
  configuration file found") in the JSON on stdout. Quote the first error
  messages from that JSON when it parses. *Raised: source-scanner resilience
  slice.*
- **A policy pack rule can be silently detached from its `verified` flag.**
  `quantum.yaml`'s layout let a rule's `verified:`/`source:` block sit after a
  COMMENT introducing the NEXT rule. Inserting a rule between them moved the
  flag onto the wrong rule, made `quantum-shor-broken-asymmetric` provisional
  and dropped its score to ZERO -- caught by the suite, not by review, during
  the usage slice. The block is attached directly now, but nothing structurally
  prevents a repeat: a pack lint asserting every rule owns its own
  `verified`/`source` (and that no rule's block follows a comment belonging to
  another) is what would.
  *Raised: usage-classification slice.*
- **A propagated path reports the VARIABLE NAME as the captured parameter, in
  every language.** `metavariable-pattern` constrains a binding without
  rewriting it, so `String t = "AES/ECB/PKCS5Padding"` yields
  `transformation: "transform"`. The CLASSIFICATION is right -- and for Java's
  cipher rules the mode survives intact, because the mode is a rule-stated
  constant rather than a capture -- so this costs a display detail rather than a
  decision, and the confidence penalty makes it visible. Resolving the value
  needs Semgrep Pro.
  *Raised: all-languages slice.*
- **Java's JWT auth-bypass close is NOT achievable on this build.** jjwt and
  auth0 java-jwt both spell their algorithms as ENUM members
  (`SignatureAlgorithm.RS256`), and OSS const-prop follows strings only --
  measured, not assumed. So the JavaScript fix has no Java counterpart, and a
  Java service selecting its JWT algorithm through a variable is still
  invisible. Pinned by `testdata/java_fixtures/must_not_fire/EnumRefLimit.java`
  with a test that FAILS if a semgrep upgrade starts catching it.
  *Raised: all-languages slice.*
- **Taint is INTRA-PROCEDURAL in the OSS build, so a flow through a function
  call is missed.** Measured, not assumed (ADR-0026 STEP 0): a key assembled in
  a helper and used by its caller is invisible to every taint rule here. That
  is Semgrep Pro's interprocedural analysis. Recorded as a `known_limit` in
  `testdata/dataflow_fixtures/answer_key.yaml` rather than left as a silent
  recall gap.
  *Raised: dataflow slice.*
- **Constant propagation does not follow a class or attribute reference, and
  only the digest/MAC rules were given propagation REACH.** Two separate
  limits.
  First: `algo = algorithms.AES` then `algo(key)` is invisible -- OSS
  propagates literals, not class references.
  `testdata/dataflow_fixtures/must_not_fire/constprop_limit.py` pins that with
  a test that FAILS if a semgrep upgrade starts catching it, so the limit
  cannot go stale.
  Second: propagation applies to the PATTERN, not to the capture, so a rule
  written as `hashlib.new($ALG, ...)` plus a `metavariable-regex` sees the
  source text `algo` and never the propagated value.
  ~~Twelve Python rules are written that way... the four `py-jwt-*` rules still
  do not.~~ **Resolved for Python** by
  [ADR-0027](docs/adr/0027-const-prop-reach.md): every value-classifying rule
  now carries a `metavariable-pattern` branch, which IS evaluated against the
  propagated value and (unlike a bare literal branch) keeps the metavariable
  bound so `capture:` still works. `py-ssl-weak-protocol` turned out never to
  have had the gap -- it matches `ssl.$PROTO`, the constant itself, so a
  protocol behind a variable is already reported at the assignment -- and a
  test pins that so a tidy-up cannot introduce one.
  A CONTRACT TEST now fails any Python rule that classifies a value passed to a
  call using `metavariable-regex` alone, so the class of bug cannot come back.
  *Raised: dataflow slice. Resolved (Python): const-prop-reach slice.*
- ~~**The const-prop contract test covers PYTHON only.**~~ **Resolved** by
  [ADR-0028](docs/adr/0028-dataflow-all-languages.md). It globs all four packs
  and is proved to BITE in three languages by a deliberately-broken rule per
  language. Extending it exposed a hole in the guard itself: its
  argument-position regex omitted `:`, so it walked straight past every
  `{algorithm: $ALG}` object-literal argument -- meaning the test written to
  make this class of bug unrepeatable could not see its worst instance, the JS
  `alg: none` auth bypass. With `:` added it also caught `js-tls-minversion`,
  which nobody had listed.
  **Still owed:** the pack list is manual, so a Rust or C# pack inherits the
  contract only when its directory is added to `PACKS`.
  *Raised: const-prop-reach slice. Resolved: all-languages slice.*
- **`params` carries the VARIABLE NAME on a propagated path, not the resolved
  value.** `metavariable-pattern` constrains a binding without rewriting it, so
  a JWT algorithm selected through `SIGNING_ALG = "ES256"` reports
  `params.alg = "SIGNING_ALG"`. The `algorithm` field carries the
  classification, which is what the CBOM and the policy engine read, so this
  costs a display detail rather than a decision -- but a report that showed the
  captured value would be showing a name. Also means `_is_resolved` reads the
  site as configurable, which for a settings-driven algorithm is arguably
  correct and is not currently distinguished from the ADR-0026 annotation's
  evidence-backed verdict.
  *Raised: const-prop-reach slice.*
- **The configurability annotation joins on `(path, line)`, and `configurable`
  is still binary.** The join is exact for the call sites here -- the taint
  sink and the pattern match are the same line -- but a sink on a different
  line from the finding it should annotate would be missed; keying on the
  semgrep match range would be precise. Separately, "read from the environment"
  and "read from a signed policy file behind a change-control ticket" are both
  `configurable=True`, and they are not the same migration cost -- which is the
  number this flag feeds.
  *Raised: dataflow slice.*
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
- **PQC capability is unverified for most of the library pack -- MECHANISM
  BUILT, values await confirmation.** `_is_pqc_capable()` returns `None` for an
  unverified floor, so an unconfirmed value produces no capability verdict
  rather than a guess (ADR-0017). Currently unverified: GnuTLS, libgcrypt and
  NSS (distro), and **every one of the fifteen dependency entries added in
  ADR-0021** -- cryptography, pyOpenSSL, PyCryptodome, PyNaCl, PyJWT, paramiko,
  node-forge, jsonwebtoken and golang.org/x/crypto carry `FILL:` markers naming
  what would settle each. Some are marked NOT APPLICABLE with a reason instead:
  bcrypt/passlib are password hashes, crypto-js has no public-key algorithm,
  and elliptic/tweetnacl are entirely Shor-broken with no later version to
  upgrade to. OpenSSL 3.5.0 remains the one verified floor, and it is the one
  the drift demo depends on.
  **REMAINING WORK:** upstream release notes per library. `provides`,
  `weak_defaults` and `source` ARE confirmed from each project's own docs.
  *Raised: Scanner C slice. Widened: deps-scanner slice, see
  [ADR-0021](docs/adr/0021-deps-scanner.md).*
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
  chose a directory over authenticated HTTP deliberately: the API had no authn
  (it has API keys since ADR-0035, and the next reason still holds),
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
- ~~**KNOWN GAP: Go and JavaScript source are not scanned.**~~ **Resolved** by
  [ADR-0023](docs/adr/0023-go-js-rules.md). `knowledge/rules/go/` (23 rules) and
  `knowledge/rules/javascript/` (20 rules, `.js` and `.ts`) run on the same
  Semgrep engine and the same metadata contract, which is the claim
  `knowledge/rules/README.md` has always made and this is the first test of it
  against a language the contract was not designed on. QuantumBank's
  `gateway-ecdsa-p256` and `gateway-embedded-cert` are DETECTED and their
  `known_gap` flags are REMOVED, so the KPI declared denominator grows 14 -> 16
  and overall 20 -> 22 with recall still 100% -- the gap closed rather than the
  measurement moving. The KNOWN GAPS section of `make kpi` is now empty.
  *Raised: KPI slice. Resolved: Go/JS rule-pack slice.*
- ~~**Java source is not scanned.**~~ **Resolved** by
  [ADR-0024](docs/adr/0024-java-rules.md). `knowledge/rules/java/` ships 32
  rules -- JCA-first (`KeyPairGenerator`, `Cipher`, `Signature`,
  `MessageDigest`, `Mac`, `KeyGenerator`, `SSLContext`), two Bouncy Castle
  spellings, both JWT libraries, the name-scoped RNG rule and key material --
  at recall 100% and precision 100%. Four languages now run on one scanner and
  one metadata contract, and Java added no matching or mapping code.
  *Raised: Go/JS rule-pack slice. Resolved: Java rule-pack slice.*
- **C/C++, Rust and C# source are still not scanned.** Three of seven planned
  language families. **C/C++ is deliberately NOT a Semgrep job**: OpenSSL call
  sites are macro-heavy (`EVP_*` behind conditional compilation), so a pattern
  pack over them would be fragile in exactly the way this project has said it
  will not ship. It wants tree-sitter, or reading the compiled binary instead --
  which is Scanner D's territory rather than Scanner A's. Rust
  (`RustCrypto`, `ring`, `rustls`) and C# (`System.Security.Cryptography`) are
  ordinary additive packs and are simply not started.
  *Raised: Go/JS rule-pack slice; narrowed by
  [ADR-0024](docs/adr/0024-java-rules.md).*
- ~~**`scanners/binary` is an empty directory.**~~ **Resolved** by
  [ADR-0025](docs/adr/0025-binary-scanner.md). Scanner D reads ELF and PE with
  five techniques -- symbols (0.90), OIDs (0.85), embedded PEM (0.95), version
  banners (0.80) and well-known constants (0.60) -- at recall 100% and zero
  findings on a non-crypto decoy. Nothing it emits is ever confidence 1.0.
  *Raised: Phase 0. Resolved: binary-scanner slice.*
- **The binary scanner cannot see inside a container image.** It takes a
  `directory` target and walks it for ELF/PE files; `image` targets belong to
  the container scanner, which reads package databases out of layer blobs and
  does NOT hand its extracted contents on. That wiring is the obvious next step
  and is where most shipped binaries actually live -- an image scan today
  inventories what dpkg says is installed, not what the binaries contain. Until
  it exists, scanning a container's binaries means extracting the image
  yourself and pointing a `directory` target at it.
  *Raised: binary-scanner slice, see [ADR-0025](docs/adr/0025-binary-scanner.md).*
- **A stripped or statically linked binary genuinely reduces recall, and the
  honest report does not aggregate.** `BinaryScanner.coverage()` says per
  binary what it could not read -- "the finding count here is a FLOOR, not a
  total" -- and that is logged, but nothing folds those limitations into the
  scan-level result, the API response or the coverage PDF. So a scan of fifty
  stripped binaries reports its limits fifty times in a log and zero times
  where a reader would look.
  *Raised: binary-scanner slice.*
- **PE support is shallower than ELF, and Mach-O is untested.** The import
  directory is read (which is where Windows CNG lives) and the byte techniques
  are format-independent, but PE export tables, resource sections and .NET
  metadata are untouched, and the only PE fixture is one this project
  assembled by hand -- there is no Windows cross-toolchain on the build host.
  Mach-O is recognised by magic number and otherwise has no fixture and no
  test.
  *Raised: binary-scanner slice.*
- **A symbol proves a LINK, not a call; and ambiguous APIs report `unknown`.**
  `RSA_sign` in an import table means the linker resolved it, not that any
  reachable path calls it -- closing that needs call-graph analysis. Separately,
  `EC_KEY_new_by_curve_name` carries both ECDSA and ECDH keys and
  `BCryptSignHash` takes its algorithm from a provider handle, so those
  findings name a primitive or algorithm of `unknown`. That is honest and it is
  also less useful than a name; closing it needs argument tracking.
  *Raised: binary-scanner slice.*
- **No firmware, no packers, no obfuscation.** Every technique reads the file
  as laid out on disk, so a UPX-packed or otherwise obfuscated binary presents
  compressed bytes and yields close to nothing. The coverage report will not
  currently notice that case and call it out, which it should.
  *Raised: binary-scanner slice.*
- **`java-keygenerator-aes` reports the key size and does not flag AES-128.**
  Deliberate: CNSA 2.0's requirement is conditional -- AES-128 is acceptable
  under NIST SP 800-131A Rev.2 for shorter-lived data and unacceptable for
  anything that must stay confidential past 2035 -- and the POLICY engine
  already scores key size against the data class. A rule flagging it
  unconditionally would assert the conditional half as a fact and duplicate the
  scorer. **That gap is now closed**: `policy/packs/symmetric.yaml`
  ([ADR-0029](docs/adr/0029-typed-params-symmetric-scoring.md)) scores
  symmetric key length against `x_years` the way mosca scores the asymmetric
  side -- 0 for data with a sub-10-year life, 25 for 25 years or more, and 12
  where nobody has classified the system. So the Java rule was right to report
  and not flag.
  *Raised: Java rule-pack slice. Scorer gap closed: symmetric-scoring slice.*
- **`x_years` comes from the data class, and most targets do not set one.** In
  practice `symmetric-grover-weakened-lifetime-unknown` will be the rule that
  fires most often until systems are classified -- the honest outcome, and not
  a satisfying one. The same is true of the mosca pack's own unknown-lifetime
  rule; what would move both is making the data class a required input on a
  system manifest rather than an optional one.
  *Raised: symmetric-scoring slice.*
- **The symmetric lifetime thresholds are ECDAT's judgement, not a standard.**
  25 years as "long-lived" lines up with the `Personal` data class and with
  published CRQC estimates; no document says 25. The Grover halving and the
  SP 800-131A "acceptable" status are cited and verified; where the boundary
  between them falls is a decision this project made and should say so.
  Separately, the pack's two rule families -- one selecting on `key_size`, one
  on algorithm NAMES that carry their size -- must be kept in step by hand, and
  a verdict added to one and not the other applies to half the estate.
  *Raised: symmetric-scoring slice.*
- **The Java pack is 32 rules, not the JCA surface.** Unmatched:
  `SecretKeyFactory` / PBKDF2 iteration counts, `KeyStore` types (JKS vs
  PKCS12), `SSLParameters` cipher-suite lists, explicit JCA provider selection,
  and the JCE unlimited-strength policy. Each is additive YAML against the
  existing contract.
  *Raised: Java rule-pack slice.*
- **The Go and JS packs are a starting set, not a complete inventory.** 23 and
  20 rules. Unmatched today: Go's `crypto/ecdh` X25519 path and
  `golang.org/x/crypto` (nacl, bcrypt, argon2); browser WebCrypto
  (`crypto.subtle.*`); the `jose` / `node-jose` JWT families. Each is additive
  YAML against the existing contract. Also unmatched in every language:
  a suite or algorithm passed as a VARIABLE rather than a literal --
  `createCipheriv(algo, ...)` does not fire, deliberately, because
  `cipher_suite: algo` is a parameter nobody can act on. Constant propagation
  is the fix and is the same limit ADR-0004 recorded for Python.
  *Raised: Go/JS rule-pack slice.*
- **The name-scoped weak-RNG rules are heuristics in all three languages.**
  `Math.random()` assigned to `sessionToken` fires; assigned to `t` does not.
  Same for Go's `math/rand`. The decoy files pin the FALSE-POSITIVE side
  (jitter, a display shuffle, a banner pick, all of which must stay silent);
  the false-negative side is unbounded and untested, and closing it needs
  taint tracking from the RNG to a key-consuming sink rather than a name regex.
  *Raised: Scanner A slice; extended to Go and JS by ADR-0023.*
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
- ~~**`dep-bump` is BLOCKED on its producer scanner.**~~ **Resolved** by
  [ADR-0022](docs/adr/0022-dep-bump-fix.md). `scanners/deps` (ADR-0021) is the
  producer that re-verifies it, so the template ships and is proved end to end:
  below-floor pin -> manifest bump -> sandbox re-scan clean. See the three
  entries below for what it still cannot do.
  *Raised: fix-it slice. Resolved: dep-bump slice.*
- **`dockerfile-base-bump` is STILL BLOCKED on a Dockerfile parser.** Held out
  of ADR-0015 because a fix that cannot be re-verified by a scanner is a fix
  ECDAT will not ship, and nothing parses a Dockerfile yet. The container
  scanner reads `dpkg`/`apk` databases from inside layer blobs, which a unified
  text diff cannot patch, so the parser is genuinely the blocker rather than a
  formality. `test_every_shipped_template_names_a_registered_scanner` is what
  stops an unverifiable template creeping in.
  *Raised: fix-it slice.*
- **`dep-bump` proposes nothing on the shipped pack, and that is the gate
  working.** All fifteen dependency entries added by ADR-0021 carry
  `pqc_capable_verified: false`, and ADR-0022 refuses to propose a bump to an
  unconfirmed floor -- a fix is a stronger claim than a score, so ADR-0017's
  verified-fact rule binds harder here. `test_no_shipped_library_has_a_verified_floor_today`
  pins the state. Turning a refusal into a fix is a RESEARCH task, not a code
  task: confirm one library's post-quantum floor against upstream release
  material, cite it, set the flag. The first entry verified is the first entry
  that produces fixes.
  *Raised: dep-bump slice, see [ADR-0022](docs/adr/0022-dep-bump-fix.md).*
- **Lockfile regeneration after a `dep-bump` is MANUAL, and a lockfile-sourced
  bump comes back unverified.** ECDAT never hand-edits `package-lock.json`,
  `poetry.lock`, `Pipfile.lock`, `yarn.lock` or `go.sum`: a bumped version
  beside its old integrity hash is a lockfile that fails on the next install.
  So the diff edits the manifest and names the regenerate command
  (`pip-compile` / `npm install` / `go mod tidy`). But Scanner B is
  lockfile-preferred, so when a lock is present the re-scan still reads it,
  still sees the old version, and the engine correctly reports `verified=False`
  -- "the finding is still present". Where a resolved lockfile is the ONLY file
  present, the template declines outright. Closing this needs either a resolver
  ECDAT is allowed to run (it is not: offline, read-only) or a lockfile-aware
  verification mode that can reason about a manifest edit the lock has not
  caught up with. Related: the refusal the operator SEES in that case is the
  engine's generic one -- *"the template did not fix what it claimed to fix"* --
  which reads as a template bug when the real cause is the lockfile masking a
  correct edit. `FixResult` has no way for a template to attach a "why this may
  not verify" hint, and adding one touches `correlate/fixit/engine.py` and all
  five templates.
  *Raised: dep-bump slice.*
- **The `dep-bump` EOL trigger is NOT built, and the pack cannot support it
  yet.** ADR-0022 was framed to also fire on "the version is EOL with a
  verified successor". `libraries.yaml`'s `eol` is an end-of-support **date**,
  one per library, `null` on every entry -- so there is no version to compare,
  and one date per library would make every version EOL at once including
  versions already above the floor. Needs a pack schema change (a per-series
  `eol`, or an `eol_version` beside the date) before the trigger means
  anything. Not built rather than built wrong.
  *Raised: dep-bump slice.*
- **`dep-bump` edits three manifest formats.** `requirements.txt`,
  `package.json`, `go.mod`. `pyproject.toml` is READ by Scanner B but not
  bumpable -- a TOML-preserving edit is its own piece of work and a naive line
  edit would reflow tables; it declines with that reason. `Cargo.toml`,
  `pom.xml` and `build.gradle` are not read at all (ADR-0021 deferred Java and
  Rust), so there is nothing to bump.
  *Raised: dep-bump slice.*
- **A fix template resolves the knowledge pack from the environment, not from
  the `ScanContext`.** `FixTemplate.preconditions` takes no context and the
  protocol was not widened for one template, so `dep-bump` reads
  `ECDAT_KNOWLEDGE_DIR` (default `knowledge/`) exactly as every other entry
  point does. In every real caller the scan and the fix resolve the same
  directory; a caller that passes a `ScanContext` pointing elsewhere would get a
  template reading a different pack from its own verifier. Widening the protocol
  is the fix, and it touches all five templates.
  *Raised: dep-bump slice.*
- **Fixes are verified one at a time, and the loop is expensive.** One sandbox
  copy plus two scans per finding — negligible for config, ~3s per finding for
  source, because semgrep runs twice. Two verified diffs touching the same file
  are each proved ALONE; nothing proves they apply together or that the
  combination is still clean. For the five shipped templates they touch
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
- **`scanners_ran` records the scanners OFFERED, not the ones that ran.**
  `core/orchestrator.run_scan` stores `scanner_records(scanners)` -- every
  scanner offered -- while its own ran / skipped / failed split goes only to the
  `scan_completed` log line. Verified: a `minimal_repo` scan's row lists all six
  ids, while the log says `binary`, `container` and `runtime-spool` were
  skipped. So ADR-0016's promise is weaker than stated: null / `[]` / list does
  separate "not recorded" from "none offered", but a LISTED scanner may never
  have looked. The coverage PDF (`reports/coverage.py`) prints "— ran" for every
  entry and therefore over-claims today. The console avoids the claim by saying
  SELECTED, never "ran" (ADR-0031 §4), and leans on the per-scanner attributed
  artefact count, which does prove a scanner looked.
  **Fix:** persist the outcome (ran / skipped / failed, with the failure) on the
  row, expose it on `ScanSummary`, and render it in the report and the Coverage
  screen. `packs_applied` is likewise in the log and not exposed by the API.
  *Raised: Q-orbit console slice (ADR-0031).*
- **The coverage report's standing gap list is stale.** `reports/coverage.py`
  `KNOWN_GAPS` still says Java source is not scanned and that binary scanners are
  "designed, not built". The Java rules shipped in ADR-0024 and the binary
  scanner in ADR-0025. The document that exists to state the tool's limits now
  mis-states them, and a reader holding the PDF cannot tell. Deriving the
  scanner-family line from the registry would stop it drifting again.
  *Raised: Q-orbit console slice.*
- **Crypto-agility sub-metrics are not computed.** The Agility screen's
  configurable share is real (`ecdat:configurable`, ADR-0026). **Key store** —
  whether key material is held in a key store, HSM or KMS rather than a file —
  and **protocol negotiation** — whether an endpoint can change algorithms
  without a release — are shown as *not computed*. Backend work would fill
  them: key-custody detection (PKCS#11 configuration, Java KeyStore, cloud KMS
  references), and a per-endpoint renegotiation fact from the config and TLS
  scanners. *Raised: Q-orbit console slice.*
- **Risk Analysis is a placeholder.** Cross-scan risk trend, business-impact
  weighting and a blast-radius view are not computed, so the screen says so and
  sends the reader to Inventory → Drift → Roadmap. Blast radius could start from
  the correlator's peer data. *Raised: Q-orbit console slice.*
- **No scan start time or duration is stored.** The row carries its save time
  only, so the Scans screen's **Started** column says "not recorded".
  **Update (ADR-0035):** a JOB now records `started_at` and `finished_at`, but
  only for work the API ran, and the scan row itself still carries neither. The
  column keeps saying "not recorded" rather than showing a time for some rows
  and not others. *Raised: Q-orbit console slice.*
- **Drift has no "next check".** Nothing re-runs a scan on a schedule, so each
  drift panel says *not scheduled — re-scan to re-check*. A monitoring job
  (the eBPF agent in daemon mode, plus a periodic system scan) would give it a
  date. *Raised: Q-orbit console slice.*
- **There is no HTML report.** Reports are PDF only. The Reports screen shows
  HTML as *not available*; CSV is a browser-side projection of the stored CBOM
  (the Inventory's values), labelled as such rather than presented as a server
  report. *Raised: Q-orbit console slice.*
- **Compare cannot pair an artefact across a new sighting place.** The
  bom-ref hashes the set of places an artefact was seen, so an artefact that
  gains or loses a place reports as resolved + new rather than changed (a moved
  LINE is fine -- positions are dropped). That is the identity's stated limit
  and is shown on the Compare screen; a fuzzy pairing was deliberately not
  built. *Raised: Q-orbit console slice.*
- ~~**The console was built without the design images and without a visual
  check.**~~ **Design matched** in [ADR-0032](docs/adr/0032-qorbit-design-match.md)
  from the twelve screenshots in `web/design/`, screen by screen. **Still owed:**
  a visual check of the RENDERED console against them -- there is still no
  headless browser on the build machine, so the human's screenshot is the
  first look at the result. *Raised: Q-orbit console slice. Design matched:
  design-match slice.*
- **Design elements (`web/design/`) the backend does not compute yet.** Each is
  rendered as an honest empty / not-computed state or left out, never with the
  mockup's sample figures (ADR-0032). What would fill each:
  - **Scan names** ("System Security Scan", "Quarterly Baseline"): the scan row
    has no name, so the console shows the target ref. An optional `name` on
    `TargetIn` / the row would carry one.
  - **Scanner outcomes and work counts** (COMPLETE / PARTIAL, "42 manifests
    indexed", "7 / 12 binaries"): needs the ran / skipped / failed record owed
    above, plus a per-scanner count of what it examined, not only what it found.
  - **A TLS / SSH probe scanner card**: no active probe scanner exists; the only
    runtime view is the eBPF spool (`runtime-spool`).
  - **Per-component agility percentages and an agility target** ("target 80%"):
    no per-component agility model and no pack-defined target.
  - **Deltas against a baseline on the Overview** ("+4 pts since baseline",
    "3 introduced this scan"): computable from `GET /scans/{a}/compare/{b}`
    (ADR-0031) against the default baseline, but not wired into the cards.
  - **Stable drift finding ids** ("FINDING DR-007"): drift records have no id;
    the console numbers findings by position on screen.
  - **A roadmap priority distinct from band** ("Critical · High"): no such fact.
  - **Notifications** (the top-bar bell): nothing raises alerts; the bell is left
    out rather than shown silent.
  - **A named user** ("Alex Kim, Analyst / Tier 2"): ECDAT has API keys, not
    accounts (ADR-0035). The menu shows the key's name and role, which is as
    much of a person as ECDAT knows.
  *Raised: design-match slice (ADR-0032).*
- **v2 design rebuild (ADR-0038): screens still on the ADR-0032 layout.** The
  shell and the Overview are rebuilt on `web/design-v2/`. Cryptographic Drift,
  Verified Fixes and Inventory are next (after review of the Overview), then
  Scans, Roadmap, Agility, Coverage, Reports and Compare; until its turn, each
  keeps its current layout inside the v2 frame and palette. **Still owed:** a
  visual check of the rendered v2 console against the mockups (no headless
  browser on the build machine). v2 elements with no backing, beyond the list
  above:
  - **An average risk score per scan** (the Risk trend's "54.2"): a stored row
    has band counts and a max score, not an average. The trend plots Critical +
    High per stored scan instead, and needs two scans of the target.
  - **A weighted estate score** ("Overall risk 63/100 Elevated"): no such
    model. The gauge shows the peak artefact score, named as the peak.
  - **An agility history** (the agility panel's line): nothing records agility
    per scan. Computable from the stored documents; not wired.
  *Raised: v2 design slice (ADR-0038).*
