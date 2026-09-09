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
| **P3** | Usage-aware recommendation + verified fix-it | 🟡 **partial — see below** |
| **P4** | Mosca + blast-radius prioritisation | ✅ **built** |

**On P3, honestly:** the *recommendation* half exists and is real — every policy
rule carries a cited, usage-aware action, and the schema deliberately preserves
`usage` (a generated RSA key is recorded as `usage: unknown`, not guessed,
precisely because ML-KEM and ML-DSA are different answers). What the tool
actually prints today:

> *Replace with a post-quantum algorithm chosen by **USAGE**: ML-KEM (FIPS 203)
> for key establishment and key transport, ML-DSA (FIPS 204) for signatures, or
> SLH-DSA (FIPS 205) where a conservative hash-based signature is preferred.
> Increasing the key size does not help.*

The **fix-it half does not exist**. There is no sandbox copy, no generated
patch, no verified diff — `correlate/fixit/` is an empty directory. Calling P3
"in progress" would overstate it.

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

**Scanners** — `core/registry.py` returns exactly these four:

| id | view | what it reads |
|---|---|---|
| `source` | declared | Python source via Semgrep, 28 cited rules |
| `config` | declared | nginx `server{}` blocks, `sshd_config`, `openssl.cnf` |
| `container` | shipped | `docker save` tar / OCI dir — dpkg+apk DBs, certs, keys |
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
```

`--sector`, `--data-class` and `--exposure` are the context that decides
severity: the same RSA-2048 scores **98/Critical** in a BFSI system holding
personal data on the internet, and **45/Medium** in an internal lab holding
public data. Criticality comes from context, never from tuning a number.

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
    { "name": "ecdat:deadline",        "value": "2028-12-31" },
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

Every score names the rules that produced it; every rule cites its source.

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

## Honest limitations

The living list is [`PUNCHLIST.md`](PUNCHLIST.md). The ones a reader should know
before believing anything above:

- **Source scanning is Python-only.** Go, JavaScript, Java and C/C++ are not
  scanned. QuantumBank contains Go crypto specifically so this gap is *measured*
  rather than hidden.
- **Dependency, binary and network scanners are designed, not built.** Four of a
  planned seven scanner families exist.
- **P3 fix-it does not exist** — recommendations are emitted, patches are not.
- **Runtime enrichment depends on the application.** The negotiated cipher and
  group are read via uretprobes on libssl's public accessors, so they are
  captured only when the process asks libssl for them. A silent service yields
  `enrichment=partial` with a reason — never a guess.
- **Group-level drift is often the weaker signal.** Because of the above, the
  common result is "declared hybrid, observed **unconfirmed**" rather than a
  confirmed downgrade. That is deliberate: a partial observation must not become
  a hard claim.
- **Observed findings carry no endpoint.** A uprobe sees a process, not a
  listening socket, so an observed handshake joins every declared endpoint in a
  system. Unattributable drift is printed as such, scored neither way.
- **Some knowledge-pack facts need verification.** The DST deadlines and
  assurance labels are encoded as supplied and have *not* been checked line by
  line against the published roadmap; GnuTLS and libgcrypt PQC floors are
  deliberately `null` rather than guessed. Both are flagged in the packs
  themselves.
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
