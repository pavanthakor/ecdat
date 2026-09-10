# ADR-0022: dep-bump — a version bump ECDAT will stand behind

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** the `dep-bump` fix template
**Depends on:** ADR-0015 (verify a fix by re-scan, never auto-apply),
ADR-0017 (the verified-fact gate), ADR-0021 (Scanner B, the producer that
unblocked this)

## Context

ADR-0015 shipped four fix templates and deliberately left two out. The rule it
enforced was single-sentence: **a fix that no registered scanner can re-verify
is not shipped.** `dep-bump` failed that test because `scanners/deps/` was an
empty directory — a diff bumping a pinned library version could be generated,
but nothing in ECDAT could re-read the manifest afterwards and confirm the
problem was gone. Verification by re-scan is the entire safety argument, so an
unverifiable fix is not a weaker fix; it is a different product.

ADR-0021 built that producer. `dep-bump` is now the first template to pass the
gate it was originally excluded by.

## Decision

### 1. Only ever bump to a VERIFIED target version

A bump is proposed **only** when the library's `pqc_capable_from` carries
`pqc_capable_verified: true`. A provisional floor produces a refusal:

> not applicable: cryptography's post-quantum floor (42.0.0) is provisional —
> target version unverified against source, so ECDAT cannot propose a bump to
> an unconfirmed fact (ADR-0017).

ADR-0017 established that an unverified pack fact is demoted to a labelled note
and never *scored*. **A fix is a stronger claim than a score.** A score says
"this looks risky"; a fix tells an operator to change a dependency their
service is built on, in a diff shaped to be applied without further thought. If
an unverified number is not good enough to move a risk band, it is nowhere near
good enough to move somebody's production manifest — so the verified-fact
mechanism extends to fixes, and it binds harder here than anywhere else.

The template makes no cryptographic claim of its own. It proposes the floor the
pack records and cites the pack's own `pqc_capable_source`.

**The consequence, stated plainly: today `dep-bump` declines every library in
the shipped pack.** All fifteen dependency entries added by ADR-0021 are
`pqc_capable_verified: false`. A test asserts exactly that against the real
`knowledge/libraries.yaml`, so the state is pinned rather than assumed. This is
the honesty gate working, not a failure — and the work that turns it into
output is research (confirm a floor against upstream release material), not
code. The first entry verified is the first entry that starts producing fixes.

### 2. Bump the MANIFEST; never hand-edit a resolved lockfile

`package-lock.json`, `poetry.lock`, `Pipfile.lock`, `yarn.lock` and `go.sum`
carry integrity hashes over the exact version they pin. Rewriting the version
string and leaving the hash produces a lockfile that fails on the next install:
a **broken tree, delivered as remediation**. ADR-0015 rejects a fix that trades
one problem for a worse one, and this is that, with the added insult of looking
like a security improvement in the diff.

So the edit lands in the human-authored manifest — `requirements.txt`,
`package.json`, `go.mod` — and every diff carries a note naming the regenerate
command for its ecosystem (`pip-compile`, `npm install`, `go mod tidy`). ECDAT
does not run package managers; CLAUDE.md's read-only rule covers the target,
and running a resolver would also mean network access.

Where a resolved lockfile is the only file present, the template declines with
the regenerate reason rather than producing anything.

The note lives in **prose above the first `---`**, not inside a hunk. `git
apply` and `correlate.fixit.patch.apply_unified_diff` both ignore everything
before the first file header (verified against real `git apply`), and
`package.json` cannot hold a comment at all — an in-file note would say this on
some formats and not others.

### 3. The honest cost of rule 2, reported rather than hidden

Scanner B is lockfile-preferred (ADR-0021): when a lock exists, the lock is the
file that gets read. So when a finding comes from `package-lock.json` and there
*is* a `package.json` beside it, `dep-bump` bumps the manifest — and the engine
then correctly returns **`verified=False`**, because the re-scan still reads the
lockfile, which still pins the old version:

> not verified: the diff applied, but the finding is still present when 'deps'
> re-scans the patched copy.

That is exactly true. Only regenerating the lock would move it. A test pins
this behaviour so it is a documented outcome rather than a surprise, and the
diff's own header says which command closes the gap. The alternative —
suppressing the check for this one template — would mean ECDAT asserting a fix
worked because a template said so, which is the thing ADR-0015 exists to
prevent.

### 4. A range bump moves the floor, not the ceiling

`cryptography>=41.0,<43` with a verified floor of 42.0.0 becomes
`cryptography>=42.0.0,<43`, with an in-file note. The lower bound is what
decides whether a range *permits* a non-capable install, and it is the only
part of a specifier a capability floor speaks to. Rewriting `<43` would be
ECDAT deciding which future major version is acceptable for somebody else's
service, which it cannot know. The note says the ceiling may still exclude the
target and asks the reader to check.

The comparison for "is this below the floor" uses the range's lower bound for
the same reason: a range starting below the floor admits a non-capable install
however the resolver happens to land today.

### 5. Formats this slice

`requirements.txt`, `package.json`, `go.mod` — the manifest side of the three
ecosystems Scanner B reads. `pyproject.toml` is read by the scanner but not
bumpable: a TOML-preserving edit is its own piece of work and a naive line edit
would reflow tables. It declines with that reason.

### 6. The EOL branch is NOT built, and why

The frame asked for a second trigger: "the version is EOL with a verified
successor". **It is not implemented, and could not be honestly.**
`knowledge/libraries.yaml`'s `eol` field is an upstream end-of-support **date**,
one per library, and it is `null` on every entry in the pack. Two problems, both
fatal to the branch as specified:

- There is no version comparison to make. A date cannot be compared to
  `42.0.5`, and with one `eol` per library rather than per version-series,
  every version of a library becomes EOL simultaneously — including versions
  already above the PQC floor, which have nothing to bump to.
- No entry pairs an EOL date with a verified successor version, so the branch
  would be unreachable on real data as well as semantically wrong.

Building it would have meant inventing pack semantics to make a trigger fire.
The pack schema change it needs — a per-series `eol`, or an `eol_version`
alongside the date — is in PUNCHLIST. Recorded here rather than dropped
silently, per CLAUDE.md.

## Consequences

**Good.**

- `dep-bump` ships with the same verification loop as every other template:
  sandbox copy → apply the diff *as a diff* → re-run `deps` → the finding is
  gone and no new Critical arrived. Proven on the happy path end to end.
- The A/B that makes the gate meaningful: two knowledge packs, byte-identical
  except `pqc_capable_verified`, produce a verified bump and a refusal. A test
  asserts the packs differ in exactly that one line, so the gate cannot quietly
  start passing for another reason.
- Read-only holds: the target tree is byte-identical either side of
  `propose_fix`, and a `Path.open` guard proves nothing under the target root is
  even *opened* for writing.
- Five templates, three producers. The template registry's docstring is again
  the one place that answers "what can ECDAT fix?".

**Costs and limits.**

- **`dep-bump` produces no fixes on the shipped pack today.** Fifteen
  provisional floors, fifteen refusals. Research task, tracked in PUNCHLIST.
- **Lockfile regeneration is manual**, and a bump proposed beside a resolved
  lockfile comes back unverified until someone runs the regenerate command.
- **`pyproject.toml`, `Cargo.toml`, `pom.xml` and `build.gradle` are not
  bumpable.** The first is read but not edited; the rest are not read at all
  (ADR-0021 deferred Java and Rust).
- **The template resolves the knowledge pack from `ECDAT_KNOWLEDGE_DIR`, not
  from the `ScanContext`.** `FixTemplate.preconditions` takes no context and the
  protocol was not widened for one template. In every real entry point the scan
  and the fix resolve the same directory from the same variable, but a caller
  that passes a `ScanContext` pointing somewhere else gets a template reading a
  different pack from its own verifier. Tests set both together for that reason.
- **Version comparison is numeric-prefix only**, inherited from
  `scanners/libraries.py` — not PEP 440, not semver. `42.0.5rc1` compares as
  `(42, 0, 5)`.
- **A bump is not a migration.** Reaching a PQC-capable version means the
  library *can* do ML-KEM, not that the application asks it to. The call sites
  that select algorithms are Scanner A's, and joining the two is the correlation
  work ADR-0021 already listed as not done.
