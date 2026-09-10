# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

**Smart India Hackathon 2026 · Problem Statement SIH26164 · NTRO**

India's DST/NQM roadmap gives critical information infrastructure a deadline to
migrate off quantum-vulnerable cryptography — and the first thing every one of
those organisations needs is an inventory of what they are actually running.
ECDAT builds that inventory. It scans **source, configuration, container images
and running processes**, produces a standards-compliant **CycloneDX 1.6 CBOM**,
scores every artefact for quantum risk (Mosca's inequality) and against the DST
roadmap and NIST IR 8547 deadlines, and — the part nothing else does — detects
**drift** between what a config *declares*, what an image *ships*, and what a
process *actually negotiates*.

---

## Why it matters

Encrypted traffic captured today can be decrypted the day a
cryptographically-relevant quantum computer arrives — **harvest now, decrypt
later** — so data with a long confidentiality horizon is already at risk.
Migration is a multi-year programme, and **you cannot migrate what you cannot
see**: most organisations have no reliable list of where RSA, ECDH and their
key sizes actually live. The DST/NQM roadmap puts dates on that migration, and
critical sectors are first. Existing SBOM and scanning tools inventory
*packages*; none of them are India-roadmap-aware, none run fully offline, and
none catch the case where a config claims post-quantum readiness that the
shipped library cannot deliver.

---

## The four pillars

| | Pillar | Status |
|---|---|---|
| **P1** | India DST roadmap compliance — CII deadlines, assurance levels, cited packs | ✅ **built** |
| **P2** | Three-view drift — declared vs shipped vs observed, via eBPF | ✅ **built, proven on hardware** |
| **P3** | Usage-aware recommendation + verified fix-it | ✅ **built** |
| **P4** | Mosca + blast-radius prioritisation | ✅ **built** |

**On P3, honestly:** the *recommendation* half carries a cited, usage-aware
action on every policy rule, and the schema deliberately preserves `usage` (a
generated RSA key is recorded as `usage: unknown`, not guessed, precisely
because ML-KEM and ML-DSA are different answers):

> *Replace with a post-quantum algorithm chosen by **USAGE**: ML-KEM (FIPS 203)
> for key establishment and key transport, ML-DSA (FIPS 204) for signatures, or
> SLH-DSA (FIPS 205) where a conservative hash-based signature is preferred.
> Increasing the key size does not help.*

The **fix half now exists too** ([ADR-0015](docs/adr/0015-fixit.md)). `ecdat
fix <scan-id>` generates a unified diff, applies it to a throwaway sandbox
copy, re-runs the scanner that found the problem, and releases the diff **only
if the original finding is gone and no new Critical appeared**. It never writes
to the target and never auto-applies — ECDAT produces a verified patch, a human
applies it.

```
$ ecdat fix 32f584a0 --scanner config --sector bfsi --exposure internet
=== fix 2/2 -- component 5083a6a37971 ===
  template : nginx-add-hybrid-group
  status   : verified: re-scanned clean -- 'config' no longer reports this
             finding on the patched sandbox copy, and no new Critical finding
             appeared. Apply it yourself; ECDAT has not touched
             testdata/quantumbank.
  source   : NIST FIPS 203 (ML-KEM); OpenSSL 3.5.0 CHANGES.md (2025-04-08)...

--- a/deploy/nginx.conf
+++ b/deploy/nginx.conf
@@ -19,6 +19,6 @@
         ssl_ciphers         AES128-SHA:DES-CBC3-SHA;
-        ssl_ecdh_curve      prime256v1;
+        ssl_ecdh_curve      X25519MLKEM768;
```

Five templates ship — `dep-bump`, `nginx-weak-protocol`,
`nginx-add-hybrid-group`, `openssl-cnf-groups`, `md5-to-sha256` — chosen by one
rule: a template ships only where a **registered scanner can re-read the file it
edits**. That rule is why `dockerfile-base-bump` is *not* here, and why
`dep-bump` only arrived once the dependency scanner existed to re-verify it; see
the limitations below.

The refusals are as much of the feature as the patches. `md5-to-sha256` fires
only where MD5 is a checksum; over a password it declines and says why —
SHA-256 there is a faster wrong answer, and the real fix is a memory-hard KDF.
Where usage cannot be read from the call site at all, it declines rather than
guessing. `dep-bump` refuses to bump to a version floor the knowledge pack has
not *verified* against upstream release material — which today means it declines
every library in the pack ([ADR-0022](docs/adr/0022-dep-bump-fix.md)). A fix is
a stronger claim than a score, so ADR-0017's verified-fact rule binds hardest
here.

---

## Architecture

```
  ┌──────────── scanners (read-only, offline) ────────────┐
  │  source     config      container     runtime-spool   │
  │  (Python)   (nginx,     (docker save  (JSONL from     │
  │             sshd,        / OCI dir)    the eBPF agent)│
  │             openssl.cnf)                              │
  └───────────────────────┬───────────────────────────────┘
                          │  one Finding type
                          ▼
              CycloneDX 1.6 CBOM  ── the single internal model
                          │            (deterministic, schema-validated)
                          ▼
            policy engine  ──►  signed + cited packs
                          │      quantum · mosca · india_dst · nist_ir8547
                          ▼
              correlator  ──►  three-view drift
                          │
                          ▼
                    SQLite store ──► REST API

  eBPF agent (separate ROOT process)  ──writes JSONL──►  spool directory
      uprobe on SSL_do_handshake                          (read by a scanner)
```

**Design invariants**, each enforced by tests rather than convention:

- **Offline by construction.** No outbound network call in the scan path. The
  eBPF agent's air-gap is proved by patching `socket.socket` and asserting
  nothing opens.
- **Read-only against targets.** Container layers are *streamed*, never
  extracted. The BPF program calls no helper that can write to, block or alter
  the observed process.
- **Deterministic.** Same input + same knowledge packs ⇒ byte-identical CBOM,
  pinned by a committed golden file.
- **Evidence on every finding.** No finding without at least one occurrence you
  can go and look at.
- **No secret key material, ever.** Private keys are recorded by presence,
  location and a fingerprint of their *public* half.
- **Signed, cited policy.** A pack whose signature fails, or whose rule lacks a
  citation, does not load.
- **A privileged sensor holds no API credential.** The root agent writes files;
  a scanner reads them. The filesystem is the trust boundary.

---

## What's built today

**Scanners** — `core/registry.py` returns exactly these six:

| id | view | what it reads |
|---|---|---|
| `source` | declared | Python, Go, JS/TS and Java source via Semgrep — 28 + 23 + 20 + 32 cited rules |
| `config` | declared | nginx `server{}` blocks, `sshd_config`, `openssl.cnf` |
| `deps` | declared | Python/Node/Go manifests and lockfiles, lockfile-preferred |
| `container` | shipped | `docker save` tar / OCI dir — dpkg+apk DBs, certs, keys |
| `binary` | shipped | ELF/PE — symbols, OIDs, embedded PEM, version banners, constants |
| `runtime-spool` | observed | JSONL the eBPF agent left in a directory |

Plus the **eBPF agent** — a separate root process, deliberately *not* a
registered scanner, since the scan path needs no privileges.

**Also built:**

- **Policy engine** with four signed, cited packs (`quantum`, `mosca`,
  `india_dst`, `nist_ir8547`), a no-eval data selector, and per-category score
  caps.
- **Three-view drift correlation** — four rules, proven live end-to-end from a
  parsed nginx config through to an observed handshake.
- **CycloneDX 1.6 CBOM** — deterministic, validated against the official schema.
- **KPI harness** over the QuantumBank seeded repo, with known gaps printed.
- **REST API**: `/health`, `/scanners`, `POST /scans`, `GET /scans`,
  `GET /scans/{id}/cbom`.

**570 tests** (2 docker-marked, opt-in), ~8,700 lines of Python.
`make check` runs ruff + mypy + pytest + CycloneDX schema validation.

**Not built:** dashboard (`web/`), report export (`reports/`), and the
dependency, binary and network scanners — those directories are empty.

---

## Quickstart

```bash
git clone git@github.com:pavanthakor/ecdat.git
cd ecdat
make setup            # apt, docker, node, semgrep, .venv — idempotent
#   ... log out and back in, for the docker group ...
make verify           # read-only health check
make images           # pull the container test images
```

Then:

```bash
make test                        # the full suite
make kpi                         # score against the QuantumBank seeded repo
sudo scripts/prove_pillar2.sh    # the eBPF proof: handshake → observed CBOM
```

**Read [`docs/ONBOARDING.md`](docs/ONBOARDING.md) before the agent.** The one
thing that trips everyone: there are **two Pythons**. `.venv` runs the app; the
eBPF agent runs on the *system* `python3` because `bcc` is a distro package that
cannot be pip-installed into a venv. `make verify` checks both.

`make help` lists every target.

## The console

```bash
make web      # build the dashboard into web/dist (needs npm; run once, ahead of time)
make serve    # uvicorn on :8000, serving the API *and* the built console
```

Then open <http://127.0.0.1:8000/>. A dark, data-dense SOC-style console over
the CBOM: a risk summary strip read off the denormalised scan row, a sortable
and filterable inventory table, a drill-down drawer with evidence, fired rules
and drift — and the **Mosca slider**, which re-scores the stored document
against a different CRQC horizon through the real rescore endpoint. Pulling the
horizon from 11 years to 5 moves 15 of QuantumBank's 17 components across a
band boundary, without re-scanning anything.

Verified and provisional facts are visually distinct: a rule nobody has
confirmed renders dashed and greyed, states `provisional · scored 0`, and its
deadline is struck through — so a fact that could not move the score cannot
look like one that did ([ADR-0017](docs/adr/0017-verified-facts.md),
[ADR-0018](docs/adr/0018-dashboard.md)).

Everything is bundled locally — fonts included — so the console works
air-gapped. The demo machine runs no Node: `make web` produces static files and
FastAPI serves them. See [`web/README.md`](web/README.md).

---

## Usage

```bash
# a repository — source + config scanners
.venv/bin/python cli.py scan ./myrepo --kind repo \
    --system payments --sector bfsi --data-class Personal --exposure internet

# a container image — no registry pull, local file only
.venv/bin/python cli.py scan ./payments.tar --kind image --system payments

# a spool directory the agent wrote
.venv/bin/python cli.py scan /tmp/ecdat-spool --kind spool --system payments

# a whole SYSTEM — every target in one manifest, one correlated CBOM.
# This is the one that finds DRIFT: a single-target scan never can.
.venv/bin/python cli.py scan-system testdata/quantumbank/system.yaml

# propose verified fixes for a stored scan — NEVER writes to the target
.venv/bin/python cli.py fix <scan-id>
.venv/bin/python cli.py fix <scan-id> --out patches/   # save verified .patch files

# re-score a stored CBOM against a different CRQC horizon — no re-scan
.venv/bin/python cli.py rescore <scan-id> --z-years 30
```

`fix` re-reads the target (a diff must be generated against the bytes that are
there *now*, not the ones a stored CBOM remembers), proposes a patch per
fixable finding, and proves each one on a sandbox copy before printing it. It
takes **no context flags**: sector, exposure and the CRQC horizon are read from
the scan being fixed, so a fix is judged in the same context as the scan that
found the problem. Flags override; they no longer have to be remembered.

`rescore` re-applies the scoring pipeline to the **stored** document without
running a single scanner — this is what the dashboard's Mosca slider calls.
Both write a **new row** linked to the parent by `parent_scan_id`; neither
amends it. An inventory somebody acted on is a record of what was true when
they acted, so ECDAT adds to a scan's history rather than revising it:

```
$ ecdat rescore d3bd3e3d --z-years 30
rescore_scan_id=29844d83 parent_scan_id=d3bd3e3d z_years=30 max_score=10
                                    # was 40 at the 7-year horizon it was scanned with
```

`scan-system` is what makes Pillar 2 a product feature rather than a benchmark
number. Drift is a property of the **union** of the views — a config promising a
post-quantum group and an image that cannot negotiate one are each individually
unremarkable, and only a document containing both is a finding. On QuantumBank:

```
scan_id=0b7f919c system=quantumbank targets=3 component_count=26 drift_count=6
  drift cipher-outside-declared-set=2
  drift declared-pqc-observed-classical=2
  drift shipped-cannot-do-declared=2
```

…including the two on `payments.quantumbank.invalid:443` the demo turns on:
the config declares `X25519MLKEM768`, the shipped image carries OpenSSL 3.0.2
(PQC floor 3.5.0), and the observed handshake negotiated `x25519`. See
[ADR-0019](docs/adr/0019-system-scan.md).

`--sector`, `--data-class` and `--exposure` are the context that decides
severity: the same RSA-2048 scores **98/Critical** in a BFSI system holding
personal data on the internet, and **45/Medium** in an internal lab holding
public data. Criticality comes from context, never from tuning a number — and,
since [ADR-0017](docs/adr/0017-verified-facts.md), never from a fact nobody
checked. Those 98 points are quantum 40 + Mosca 28 + criticality 20 +
exposure 10, and every rule behind them names the document and section it was
confirmed against. Criticality stays reachable from quantum + Mosca + exposure
alone, so the band never *depends* on the roadmap pack.

A scored component, abbreviated from a real run:

```json
{
  "name": "RSA-2048",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "pke",
      "parameterSetIdentifier": "2048",
      "nistQuantumSecurityLevel": 0
    }
  },
  "properties": [
    { "name": "ecdat:view",            "value": "declared" },
    { "name": "ecdat:band",            "value": "Critical" },
    { "name": "ecdat:score",           "value": "98" },
    { "name": "ecdat:quantum_status",  "value": "broken" },
    { "name": "ecdat:deadline",        "value": "2027-12-31" },
    { "name": "ecdat:category_score",  "value": "criticality=20" },
    { "name": "ecdat:category_score",  "value": "quantum=40" },
    { "name": "ecdat:fired_rules",     "value": "quantum-shor-broken-asymmetric,dst-cii-priority-migration,..." },
    { "name": "ecdat:x_years",         "value": "25" },
    { "name": "ecdat:actions",         "value": "Replace with a post-quantum algorithm chosen by USAGE: ML-KEM (FIPS 203) ..." }
  ],
  "evidence": { "occurrences": [
    { "location": "services/auth/tokens.py", "line": 6 }
  ]}
}
```

Every score names the rules that produced it; every rule cites its source — and
a rule whose source nobody has checked contributes `0`, says so
(`ecdat:provisional`), and still shows what it would have said.

---

## KPIs

`make kpi` scans the **QuantumBank** seeded repo — five services, four configs,
a container image and two observed handshakes — and scores against a committed
answer key:

```
  view          planted   found    recall
  declared           14      14   100.0%
  shipped             3       3   100.0%
  observed            3       3   100.0%
  OVERALL            20      20   100.0%

  precision (decoys) : 100.0%   (0 decoy hits of 26 emitted)
  drift recall       : 100.0%   (3/3 expected)
  drift precision    : 100.0%   (0 invented)
  scan time          : ~2.5s    components: 26
```

> **100% recall is a statement about a fixture we wrote** — it means the
> pipeline detects what it claims to detect on a realistic-but-small estate,
> **not** that ECDAT finds all cryptography.

The harness **prints every known gap on every run**, including artefacts
deliberately planted that ECDAT *cannot* detect (the Go gateway's ECDSA), plus
every miss and every unattributable drift. Leaving undetectable crypto out of
the fixture would produce a better number by making the test easier; the answer
key lists it instead.

---

## Reports

```bash
ecdat report <scan-id> --kind executive    # 2 pages for a decision
ecdat report <scan-id> --kind technical    # every artefact, with its evidence
ecdat report <scan-id> --kind coverage     # what this scan did NOT look at
```

PDFs land in `./reports-out/` unless `-o` says otherwise, and
`GET /scans/{id}/report/{kind}` serves the same bytes. Nothing is re-scanned: a
report is a projection of the stored CBOM, so it cannot disagree with the
dashboard about the same scan, and it re-renders byte-identically.

The **coverage statement** is the one to read first. It says which views were
collected, which were not, and what ECDAT cannot detect at all — because a
finding count means nothing without the list of what it declined to measure.

---

## Honest limitations

The living list is [`PUNCHLIST.md`](PUNCHLIST.md). The ones a reader should know
before believing anything above:

- **Source scanning covers Python, Go, JavaScript/TypeScript and Java.** C/C++,
  Rust and C# are not scanned — three of seven planned language families.
  QuantumBank's Go gateway was a *measured* known gap until
  [ADR-0023](docs/adr/0023-go-js-rules.md) closed it; the KPI denominator grew
  from 20 to 22 rather than the gap being quietly dropped. C/C++ is the hard
  one and is deliberately not a Semgrep job: OpenSSL call sites are macro-heavy,
  so that pack wants tree-sitter, or reading the compiled binary instead.
- **The network scanner is designed, not built.** Six of a planned seven
  scanner families exist; a packet capture is still invisible. The dependency
  scanner landed in [ADR-0021](docs/adr/0021-deps-scanner.md) and the binary
  scanner in [ADR-0025](docs/adr/0025-binary-scanner.md).
- **Everything the binary scanner says is a heuristic, and it says so.** No
  finding is ever confidence 1.0: symbols score 0.90, OIDs 0.85, version
  banners 0.80, well-known constants 0.60, and each carries the technique that
  produced it. A stripped or statically linked binary genuinely reduces recall,
  so the scanner reports what it could not read per binary rather than
  returning fewer findings silently — but saying so does not recover them, and
  nothing yet aggregates those limits into the coverage report. It also cannot
  see inside a container image yet: wiring `container` → `binary` is the next
  step.
- **Fix templates are a starter set** — five templates over nginx,
  `openssl.cnf`, Python MD5 and dependency manifests.
  `dockerfile-base-bump` is still absent because nothing reads a Dockerfile, so
  its diff could be generated but never verified by re-scan, and ECDAT does not
  ship a fix it cannot confirm.
- **`dep-bump` currently proposes nothing, by design.** It bumps
  `requirements.txt`, `package.json` and `go.mod` to a *verified* post-quantum
  floor, and every one of the fifteen dependency entries in the pack is still
  provisional — so it declines them all with a reason. That is the honesty gate,
  and clearing it is research, not code. It also never hand-edits a resolved
  lockfile (a bumped version beside a stale integrity hash is a broken install),
  so the diff says to regenerate, and a bump proposed beside a lockfile comes
  back **unverified** until someone does.
- **A fix is verified alone.** Two diffs touching one file are each proved on
  their own; nothing proves they apply together. The loop also costs a sandbox
  copy and two scans per finding, which is why it is opt-in rather than part of
  every scan.
- **Runtime enrichment depends on the application.** The negotiated cipher and
  group are read via uretprobes on libssl's public accessors, so they are
  captured only when the process asks libssl for them. A silent service yields
  `enrichment=partial` with a reason — never a guess.
- **Group-level drift is often the weaker signal.** Because of the above, the
  common result is "declared hybrid, observed **unconfirmed**" rather than a
  confirmed downgrade. That is deliberate: a partial observation must not become
  a hard claim.
- **A system scan's observed view is a committed fixture, not a live
  measurement.** `scan-system` reads a checked-in spool so it is deterministic,
  offline and needs no root. The live eBPF attach is `make prove-pillar2`, and
  the two must not be conflated.
- **Observed findings carry no endpoint.** A uprobe sees a process, not a
  listening socket, so an observed handshake joins every declared endpoint in a
  system. Unattributable drift is printed as such, scored neither way.
- **Unverified facts are structurally unscoreable — and the DST facts are now
  verified.** Every policy rule and library floor carries `verified` + `source`,
  and **the engine adds nothing to a score from an unverified rule**
  ([ADR-0017](docs/adr/0017-verified-facts.md)). That gate briefly cost the
  headline demo 20 points, because the India DST deadlines had never been
  checked. They have since been confirmed against the published roadmap
  (document, URL and section on every rule), so they score again — and
  confirming them was a data edit, not a code change. The confirmation also
  found a real error: the CII sector list had four entries where the roadmap
  gives seven, so assets in government, strategic and transport estates had
  been silently under-scoring. **Still unverified:** the GnuTLS, libgcrypt and
  NSS post-quantum floors, which stay unscored until upstream NEWS is checked.
- **Policy packs are signed with a committed DEV key.** It proves a pack was
  built by this repo's tooling and nothing about who approved it. Production key
  management is deferred.
- **`scripts/setup.sh` has not run on a truly fresh machine.** Its dry run is
  verified; the real path is not.
- **The API has no authentication** and `GET /scans` is unpaginated.

---

## Design decisions

Every decision is recorded in [`docs/adr/`](docs/adr/) with its alternatives and
consequences:

| | |
|---|---|
| [0001](docs/adr/0001-architecture.md) | Architecture and the scanner contract |
| [0002](docs/adr/0002-cbom-normaliser.md) | CycloneDX 1.6 normaliser, deterministic dedup, cross-view non-merge |
| [0003](docs/adr/0003-scan-pipe.md) | The scan pipe: orchestrator, store, API |
| [0004](docs/adr/0004-source-scanning-semgrep.md) | Source scanning with Semgrep; rules carry the knowledge |
| [0005](docs/adr/0005-scanner-registry.md) | The scanner registry |
| [0006](docs/adr/0006-container-scanning.md) | Container scanning; certs parsed, keys redacted |
| [0007](docs/adr/0007-policy-engine.md) | Policy engine; signed, cited, no-eval packs |
| [0008](docs/adr/0008-mosca-dst-nist-packs.md) | Mosca/DST/NIST packs and the score inputs |
| [0009](docs/adr/0009-ebpf-agent-slice1.md) | The eBPF agent; attach-first, enrich-second |
| [0010](docs/adr/0010-spool-seam.md) | The spool seam: a file, not an HTTP endpoint |
| [0011](docs/adr/0011-enrichment.md) | Enrichment via accessor uretprobes, not struct offsets |
| [0012](docs/adr/0012-correlator-drift.md) | The correlator and three-view drift |
| [0013](docs/adr/0013-config-scanner.md) | The config scanner; endpoint as the join key |
| [0014](docs/adr/0014-quantumbank-kpi.md) | QuantumBank and the honest KPI harness |
| [0015](docs/adr/0015-fixit.md) | Verified fix-it: propose a diff, prove it by re-scan, never auto-apply |
| [0016](docs/adr/0016-store-migration.md) | Self-describing re-runnable scan rows; a fix is a new row, never an amend |
| [0017](docs/adr/0017-verified-facts.md) | The verified-fact gate and engine version pinning |
| [0018](docs/adr/0018-dashboard.md) | The dashboard console |
| [0019](docs/adr/0019-system-scan.md) | Unified system scan: three views, one CBOM |
| [0020](docs/adr/0020-reports.md) | Executive/technical/coverage PDFs and DB-path visibility |
| [0021](docs/adr/0021-deps-scanner.md) | Scanner B: dependencies, lockfile-preferred |
| [0022](docs/adr/0022-dep-bump-fix.md) | dep-bump: manifest bump, verified target only |
| [0023](docs/adr/0023-go-js-rules.md) | Go and JS/TS rule packs; the QuantumBank Go gap closed |
| [0024](docs/adr/0024-java-rules.md) | Java rule pack; a language-neutral redaction net |
| [0025](docs/adr/0025-binary-scanner.md) | Scanner D: binaries, heuristic and confidence-scored |
| [0026](docs/adr/0026-dataflow.md) | Source dataflow: constant propagation and taint |
| [0027](docs/adr/0027-const-prop-reach.md) | Const-prop reach for every value-classifying rule |
| [0028](docs/adr/0028-dataflow-all-languages.md) | Const-prop in every pack; cross-language contract test |
| [0029](docs/adr/0029-typed-params-symmetric-scoring.md) | Typed params before identity; symmetric key size vs data lifetime |
| [0030](docs/adr/0030-usage-classification.md) | Usage classification drives the PQC target; JS weak-RNG taint |
| [0031](docs/adr/0031-qorbit-dashboard.md) | The Q-orbit console: every screen real or "not computed"; compare endpoint |
| [0032](docs/adr/0032-qorbit-design-match.md) | Console matched to the design screenshots; dead frontend code removed |
| [0033](docs/adr/0033-source-scanner-resilience.md) | Source scanner tolerates unparseable files; each recorded as a coverage gap |

---

## Standards & references

- **CycloneDX 1.6** — the CBOM format, including `cryptoProperties`.
- **FIPS 203 / 204 / 205** — ML-KEM, ML-DSA, SLH-DSA (NIST, August 2024).
- **NIST IR 8547** — *Transition to Post-Quantum Cryptography Standards*
  (initial public draft, November 2024): the 2030 deprecation / 2035 disallow
  timetable.
- **NIST SP 800-131A Rev. 2** — algorithm and key-length transitions.
- **DST / National Quantum Mission** — India's quantum-safe ecosystem roadmap
  (deadlines encoded in `policy/packs/india_dst.yaml`; see the verification note
  in that file's header).
- **Mosca's inequality** — Michele Mosca, *Cybersecurity in an era with quantum
  computers: will we be ready?*, IEEE Security & Privacy 16(5), 2018.
- **OpenSSL 3.5.0 release notes** — the ML-KEM availability floor used by the
  drift rules.

---

## Team

**Team Skill Issue** — Karnavati University
Smart India Hackathon 2026 · SIH26164 · NTRO

**License:** TBD.
