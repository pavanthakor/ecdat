# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

## What this is
SIH 2026 problem statement SIH26164 (NTRO). A cryptographic discovery, risk
and migration-planning tool. It scans source, dependencies, containers,
binaries, running processes and network handshakes; produces a CycloneDX 1.6
CBOM; scores each artefact for quantum risk (Mosca) and Indian DST roadmap
deadlines; detects drift between what is declared, shipped and observed; and
recommends usage-correct post-quantum replacements with verified fix diffs.

## Architecture (see docs/adr/0001-architecture.md)
Scanner plugins -> one Finding type -> normaliser -> CycloneDX 1.6 CBOM (the
single internal model, stored in SQLite) -> policy engine + correlator -> API
-> dashboard / exports. Four pillars: (1) India roadmap compliance engine,
(2) three-view drift detection via eBPF, (3) usage-aware recommendation +
verified fix-it, (4) Mosca + blast-radius prioritisation.

## Working method — follow this strictly
- One small slice at a time: FRAME (given to you) -> write FAILING tests first
  -> implement until green -> stop and report. Never build ahead of the frame.
- Test-first always. No feature merges without tests. Security-critical logic
  (policy engine, CBOM mapper, drift comparator, fix-it verifier, offline
  guarantee) gets mutation-style negative tests, not just happy-path.
- Every knowledge-pack entry cites its source (FIPS number, NIST/DST section,
  library changelog). No uncited crypto facts.
- Determinism: same input + same knowledge packs -> byte-identical CBOM.
- Offline by construction: no outbound network calls in the scan path.
- Read-only against targets: never modify a repo, image or host. Fix-it works
  on a sandbox copy and only ever proposes a diff.
- Every Finding carries evidence (>=1 occurrence). Every score carries the
  rule id that produced it. No secret key material is ever stored.
- Each slice that makes a design decision gets a short ADR in docs/adr/.
- Nothing silently dropped. Deferrals go in docs/adr/ and a PUNCHLIST.md.
- Stop and report before expanding scope. Existing work outranks new work.

## Standards / stack
Python 3.11+, FastAPI, pydantic, SQLAlchemy, SQLite. Semgrep + tree-sitter
for source scanning. cyclonedx-python-lib for the CBOM (validate against the
official 1.6 schema). React + Vite + Tailwind + Recharts for the dashboard.
eBPF via bcc (agent). ruff + mypy + pytest in CI; conventional commits.

## Human vs agent
The human runs all sudo / docker / tcpdump / eBPF-attach commands personally.
You build and commit code; you do not run privileged commands.
