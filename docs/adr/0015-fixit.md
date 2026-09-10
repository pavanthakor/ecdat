# ADR-0015: Verified fix-it — a diff nobody trusts until a re-scan agrees

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** Pillar 3, fix half (completes Pillar 3)
**Supersedes / amends:** nothing. Extends ADR-0001 ("Fix-it operates on a
sandbox copy and only ever proposes a diff") from a principle into an
implementation.

## Context

ADR-0007 and ADR-0008 gave every policy rule a cited, usage-aware `action`.
That is the recommendation half of Pillar 3 and it is real: the schema keeps
`usage` unmerged precisely so an RSA key-transport site is told to become
ML-KEM and an RSA signing site is told to become ML-DSA. The README said so and
also said the other half did not exist — `correlate/fixit/` was an empty
directory.

The gap matters because a recommendation is where remediation stalls. "Replace
with a post-quantum algorithm chosen by usage" is correct and is still a
research task for whoever reads it. The thing that moves an estate is a patch.

But a patch is also the first artefact ECDAT produces that can *break
something*. Every other output is a claim about the world; a diff is a change
to it. That asymmetry drives every decision below.

## Decision

### 1. Never auto-apply. ECDAT produces a verified diff; a human applies it.

There is no `--apply`, no `--write`, no flag that makes ECDAT edit a target,
and no code path that could be talked into one: `propose_fix` writes only
inside a `tempfile.TemporaryDirectory` it also removes.

This is not timidity about tooling — it is about what ECDAT can and cannot
know. It reads a repo, an image and a handshake. It does not know that the
nginx block it is about to harden fronts a payment terminal fleet that still
speaks TLS 1.0, that a change window exists, or that the config is generated
from a template three repositories away. A tool that cannot know those things
must not be the thing that decides.

The CLI says so on every run, and `ecdat fix` prints diffs to stdout for a
human to review.

### 2. Verify by RE-SCAN on a sandbox copy — never by trusting the template.

A template asserts "replacing this line fixes this finding". That assertion is
not evidence, and the failure modes are quiet ones: an off-by-one line number,
a directive whose value re-parses to the same thing, an edit to a commented-out
block. Each produces a plausible diff and a false "fixed".

So the engine round-trips the claim through the producer:

1. select the matching template; check its preconditions;
2. generate a unified diff — **the real target is never opened for writing**;
3. copy the target into a fresh sandbox directory;
4. scan the *pristine* copy and confirm the finding reproduces there — if it
   does not, this sandbox is not evidence about this finding, and the run says
   so instead of concluding anything;
5. apply the diff **as a diff** to the copy;
6. re-run `scanner_to_reverify` and require **both**:
   - the original finding is gone, and
   - no NEW `Critical` finding appeared;
7. only then is `verified=True` and only then is the diff released.

Step 5 is load-bearing in a way that is easy to miss. The engine applies the
template's *own diff text*, not the template's in-memory idea of the resulting
file. A template whose patch does not say what it meant fails here rather than
in a reviewer's working tree.

Step 6's second clause is the one that took the most thought. Removing a
finding is easy — delete the line. The interesting failure is a fix that
removes the finding and makes things worse, and it is not hypothetical: a
template that "fixes" MD5 by swapping in an RSA-2048 keypair genuinely removes
the MD5 finding. `tests/test_fixit.py` constructs exactly that template and
asserts the rejection, with the new Critical named in the reason.

### 3. Read-only on the real target, proved rather than asserted.

`_sandbox_root` is the single point at which the real target stops being
involved. Three tests defend the property:

- `test_the_real_target_is_byte_identical_after_propose_fix` hashes every path
  and every byte of the tree before and after proposing fixes for every
  finding;
- `test_propose_fix_never_opens_the_target_for_writing` wraps `Path.open` and
  asserts nothing under the target root is ever opened in a writing mode —
  which survives a fix that happens to write identical bytes;
- `test_mutation_pointing_the_sandbox_at_the_real_target_modifies_it` disables
  the copy and asserts the tree *does* change, so the guard is demonstrably
  load-bearing rather than decorative.

The committed `testdata/quantumbank/` fixture is itself a standing check: the
suite runs the engine against it repeatedly and `git status` stays clean.

### 4. The template contract

Each template in `correlate/fixit/templates/` is:

| member | responsibility |
|---|---|
| `id` | stable; lands in `ecdat:fix:template` |
| `scanner_to_reverify` | id of a **registered** scanner that re-reads this file |
| `source` | the citation for the crypto claim the fix makes |
| `matches(finding) -> bool` | pure, reads the finding only, never the disk |
| `preconditions(finding, target) -> Precondition` | may read the target; decides whether the edit is *appropriate* |
| `make_diff(finding, target) -> str` | a unified diff, target-relative; writes nothing |

Templates are deliberately dumb. A template knows one edit to one file format
and nothing about whether that edit is safe — safety is decided by re-scanning.
That split is what lets a wrong template be *caught* rather than *trusted*.

`source` is not in the original sketch of the contract. It was added because
CLAUDE.md forbids uncited crypto facts in a knowledge pack, and a rule that
rewrites somebody's TLS configuration is held to at least that standard.

### 5. The four shipped templates, and the two that are not shipped

| template | edit | re-verified by |
|---|---|---|
| `nginx-weak-protocol` | `ssl_protocols` naming a retired version → `TLSv1.3` | `config` |
| `nginx-add-hybrid-group` | classical `ssl_ecdh_curve` → `X25519MLKEM768` | `config` |
| `openssl-cnf-groups` | `Groups` gains the hybrid group at its head; `MinProtocol` raised to `TLSv1.2` | `config` |
| `md5-to-sha256` | `hashlib.md5(` → `hashlib.sha256(`, **integrity only** | `source` |

The selection rule is the same rule as the verification decision: **a template
ships when a registered scanner can re-read the file it edits.** Four templates
across two producers, all covering the QuantumBank demo path.

`dockerfile-base-bump` and `dep-bump` were in the slice as framed and are
**deliberately not shipped**. Nothing in ECDAT reads a Dockerfile or a
dependency manifest — `scanners/deps` is an empty directory, and the container
scanner reads `dpkg`/`apk` databases from inside layer blobs of an image tar,
which a unified text diff cannot patch. Both diffs could be *generated* and
neither could be *confirmed*, which would contradict the one decision this ADR
exists to enforce. They are in PUNCHLIST, blocked on their producer scanner.
`test_every_shipped_template_names_a_registered_scanner` is the guard that
keeps an unverifiable template from creeping into the shipped set later.

### 6. `md5-to-sha256` refuses more often than it fires, on purpose

MD5 does three different jobs and the correct replacement differs in each:

- **integrity** (a checksum over a file or payload) — SHA-256 is a drop-in
  improvement, and this is the one case the template edits;
- **password storage** — SHA-256 is *also* wrong here, just faster. The real
  fix is a memory-hard KDF (Argon2id/scrypt/PBKDF2 — NIST SP 800-63B
  §5.1.1.2), which changes the storage format and the verification path. A
  one-token substitution would look like remediation, close the finding, and
  leave the credentials exactly as recoverable;
- **anything else** — unknown, and ECDAT says so.

So classification is asymmetric by design. A password marker in the call-site
context is **disqualifying and is checked first**; an integrity marker is
**required** to proceed. The default for an unrecognised call site is refusal.
`.hexdigest()` / `.digest()` are stripped before the integrity vote because
they appear on essentially every MD5 line ever written and therefore carry no
information about what the hash is *for* — without that, `legacy_digest(password)`
would vote "integrity" on the word "digest".

This is Pillar 3's usage-awareness applied to the fix: a fix that guessed usage
would undo the reason the schema keeps `usage` in the first place.

### 7. The CBOM pass is post-correlation, and is not part of every scan

`correlate/fixit/apply.py` writes `ecdat:fix:template`, `ecdat:fix:verified`,
`ecdat:fix:reason`, `ecdat:fix:source` and `ecdat:fix:diff` onto components,
in the same strip-then-write shape as `policy.apply` and `correlate.apply`, so
it is idempotent.

It is **not** wired into `run_scan`. Policy and drift are cheap reasoning over
components already in hand; verifying a fix copies the target, re-scans it
twice and scores whatever arrived, *per finding*. Making every scan pay that is
how a scan becomes something people stop running. `ecdat fix <scan-id>` drives
the pass instead, which is also the honest model: a fix is something you ask
for about an inventory you already have.

**The invariant a dashboard can rely on:** `ecdat:fix:diff` is written **only**
when `ecdat:fix:verified` is `true`. A refusal keeps its template and its
reason — "MD5 here is a password, use Argon2id" is worth showing — but never a
patch. An unverified diff rendered next to an apply button is exactly how an
unproven change reaches production.

## Consequences

**Good.**

- Pillar 3 is complete: detect → recommend → **fix → verify**. On QuantumBank,
  `legacy.quantumbank.invalid:8443`'s classical `prime256v1` becomes a
  `X25519MLKEM768` diff that is applied to a sandbox copy, re-parsed by the
  same config scanner that found it, and confirmed gone — with the target
  provably untouched.
- The three safety properties each have a paired mutation test. A future edit
  that makes a guard decorative turns one of those tests green in the wrong
  direction while its partner goes red.
- A refusal is a first-class output. `not applicable` with a cited reason is
  frequently *more* useful than a patch, and the CLI and CBOM both carry it.

**Costs and limits, stated plainly.**

- **The fix loop is expensive.** One copy plus two scans per finding. Cheap for
  config, ~3s per finding for source (semgrep runs twice). This is why the pass
  is opt-in, and it will need batching — one sandbox verifying several
  independent fixes — before it runs over a large estate.
- **Fixes are verified one at a time.** Two verified diffs touching the same
  file are each proved *alone*; nothing proves they apply together or that the
  combination is still clean. For the shipped templates they touch distinct
  lines, but that is a property of these four templates, not a guarantee.
- **"No new Critical" is the only blast-radius gate.** A fix that introduces a
  new *High* is accepted, and reported in `new_findings`. Critical is the
  defensible line for an automatic refusal; anything lower is a judgement a
  reviewer should make with the diff in front of them.
- **The verifier is the scanner, so the scanner's blind spots are the
  verifier's.** `md5-to-sha256` is confirmed by semgrep — if a rule pack stopped
  matching MD5 entirely, every MD5 fix would verify trivially. The baseline
  scan of the pristine copy (step 4) is what makes that failure loud: a finding
  that does not reproduce is refused rather than assumed fixed.
- **CRLF files are refused**, not converted. Rewriting line endings would turn
  a one-line diff into a whole-file diff and bury the change that matters.
- **`sector` and `exposure` are not persisted on the scan row** (a pre-existing
  PUNCHLIST item), so `ecdat fix` re-takes them as flags. They are not
  cosmetic here: they decide whether an introduced finding counts as Critical,
  and therefore whether a fix is rejected. Defaults are `other`/`unknown`,
  which is the *permissive* direction — worth closing with the same store
  migration that owes `scanners_ran`.
- **The dashboard cannot see fixes yet.** `ecdat fix` prints, saves patches and
  can write a fix-annotated CBOM to a file; it does not update the stored scan
  row, because silently rewriting stored history is worse than not showing
  fixes. An API route belongs with the store migration.
