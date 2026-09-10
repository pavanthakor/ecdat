# ADR-0021: Scanner B — dependencies, the crypto a project takes on

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** dependency scanner (Python / Node / Go)
**Depends on:** ADR-0001 (the Finding contract), ADR-0002 (cross-view
non-merge), ADR-0006 (the knowledge pack decides what counts), ADR-0017 (the
verified-fact gate)

## Context

`scanners/deps/` has been an empty directory since Phase 0, and the README has
said so: *"Dependency, binary and network scanners are designed, not built."*

That gap is not cosmetic. The source scanner finds a call site; the container
scanner finds what an image ships. Neither answers the question a migration
plan actually starts from: **what cryptography did this project take on by
depending on somebody else's?** A repo with no `hashlib` call and
`cryptography==41.0` in its lockfile is carrying an RSA implementation, a set of
weak defaults and an end-of-support date — and only the manifest says so.

It also blocks the `dep-bump` fix template, which ADR-0015 had to leave out for
exactly this reason: a fix that cannot be re-verified by a scanner is a fix
ECDAT will not ship.

## Decision

### 1. A fourth producer of the `declared` view

`id="deps"`, `view="declared"`, `supports` repo and directory. It walks for
known manifest and lockfile names and dispatches by filename:

| ecosystem | files, most certain first |
|---|---|
| `pypi` | `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml` |
| `npm` | `package-lock.json`, `yarn.lock`, `package.json` |
| `go` | `go.mod`, `go.sum` |

Explicit filenames, not a glob. Parsing "anything that looks like a lockfile"
produces confident nonsense.

### 2. LOCKFILE-PREFERRED, and a range recorded AS a range

Per directory, per ecosystem, **the first file in the precedence order wins**.
Reading both a lockfile and a manifest would report the same dependency twice
with two different versions and give the reader no way to tell which one is
installed.

When only a manifest range exists, it is recorded as a range —

```
version           ">=41.0,<43"
version_is_range  true
version_note      "…no lockfile resolves it, so the installed version is not
                   known from this repository. Capability and end-of-support are
                   left unanswered rather than assumed at either end."
confidence        0.7
```

— and **no `pqc_capable` parameter is emitted at all.** A capability verdict on
"somewhere between 41 and 43" is a verdict on a version nobody has installed.
Answering at the low end understates the estate and at the high end overstates
it; the honest answer is that this repository does not say.

`confidence` drops to 0.7 rather than staying at 1.0 because the *dependency*
is certain and its *version* is not — and every downstream statement rests on
the version.

### 3. The library / source-algorithm boundary

**This scanner finds third-party crypto LIBRARIES. It does not find stdlib
crypto usage.** `hashlib.md5(...)` in Python and `crypto/aes` in Go appear in no
manifest; they are call sites, and Scanner A owns them.

The two are different assets about different things:

| | Scanner B | Scanner A |
|---|---|---|
| asset_type | `library` | `algorithm` |
| name | `cryptography` | `RSA` |
| params | version 42.0.5, ecosystem pypi | key_size 2048 |
| evidence | `poetry.lock:4` | `keys.py:12` |

They never merge — ADR-0002 keys identity on asset type, algorithm, params and
locus, and all four differ. A scan carrying both is not double-counting: it is
saying a library is present AND naming where it is used, which is what a
migration plan needs. A test scans one repo with both scanners and asserts the
identities stay distinct.

CycloneDX 1.6 has no `library` in its `cryptoProperties.assetType` vocabulary
(algorithm / certificate / protocol / relatedCryptoMaterial), so the normaliser
emits a library as a plain `type: library` component with a `version` and the
kind in `ecdat:asset_type` — already the shape the container scanner produced
for shipped libraries.

### 4. The knowledge pack gains an `ecosystem`, and namespaces do not mix

`knowledge/libraries.yaml` entries now carry `ecosystem`: `distro` (the default,
what an image ships) or `pypi`/`npm`/`go`. **A lookup is always scoped to one.**

That is not tidiness. `python3-cryptography` the dpkg package and
`cryptography` the PyPI wheel are different artefacts with different version
numbering; letting one inherit the other's capability floor would put a verdict
on the wrong software. A PyPI package called `openssl` can never be matched
against the system OpenSSL.

Both scanners now read the pack through **one** module, `scanners/libraries.py`.
Two readers of one pack is how a version comparison drifts until the same
OpenSSL is PQC-capable in one view and not in the other — the container
scanner's `_load_library_pack`, `_is_pqc_capable` and `_upstream_version` are
now thin, distro-scoped delegates.

### 5. Every new entry is PROVISIONAL, deliberately

Fifteen libraries were added — cryptography, pyOpenSSL, PyCryptodome, PyNaCl,
PyJWT, bcrypt, passlib, paramiko, node-forge, crypto-js, jsonwebtoken,
bcrypt/bcryptjs, tweetnacl, elliptic, golang.org/x/crypto.

**Every one has `pqc_capable_from: null` and `pqc_capable_verified: false.**
None of them has a post-quantum floor this project has confirmed against
upstream release material, so under ADR-0017 none of them produces a capability
verdict. Each carries a `FILL:` marker naming exactly what would settle it.

Several are marked `NOT APPLICABLE` rather than unconfirmed, with the reason —
bcrypt and passlib are password hashes where the field is not meaningful;
`crypto-js` implements no public-key algorithm, so there is nothing for Shor to
break; `elliptic` and `tweetnacl` are entirely Shor-broken and the replacement
is a different library, not a later version of the same one.

`provides`, `weak_defaults` and `source` **are** confirmed — they come from each
project's own documentation, and several weak-default notes are the useful part
of the entry (node-forge shipping DES and RC2; crypto-js's MD5-based default
KDF; jsonwebtoken's pre-9.0 algorithm confusion; bcrypt's 72-byte truncation).

### 6. A malformed manifest degrades the scan

Truncated JSON, half-written TOML, a lockfile mid-`git checkout`: logged with
its path and reason, skipped, and the other manifests in the same repo still
parse. Same plugin-isolation discipline as ADR-0003 — this is somebody else's
data and may be hostile.

`node_modules`, `vendor`, `site-packages`, `.venv`, `dist` and `build` are
skipped: **a dependency's own manifest is not this project's dependency**, and
walking into them would turn one project into its whole transitive world.

## Consequences

**Good.**

- Recall 100% (5/5 planted) and precision 100% (0 of 3 decoys) on
  `testdata/deps_fixtures`, printed on every run.
- Lockfile-preferred is proved on a repo carrying both: `requirements.txt` says
  `cryptography>=41.0,<43`, `poetry.lock` pins `42.0.5`, and the finding
  reports 42.0.5 from `poetry.lock:4`.
- `requests`, `lodash` and `github.com/gorilla/mux` produce nothing. An
  inventory that lists `lodash` is an inventory nobody will read.
- **The `dep-bump` fix template is unblocked** — it now has a producer that can
  re-verify it, which is the one thing ADR-0015 requires before shipping a fix.

**Costs and limits.**

- **Every new pack entry is provisional**, so the deps scanner currently
  inventories libraries without answering the post-quantum question for any of
  them. That is the mechanism working, not a bug — but it is a data-fill task
  and it is the difference between "we found node-forge" and "node-forge cannot
  do ML-KEM".
- **Java and Rust are not scanned** (`pom.xml`, `build.gradle`, `Cargo.toml` /
  `Cargo.lock`). A fast follow; the parser-per-format shape makes each addition
  self-contained.
- **Transitive dependencies are read where the lockfile lists them and not
  otherwise.** `package-lock.json` and `go.sum` name the whole graph;
  `requirements.txt` names only what was asked for. So the same project can
  report a different dependency count depending on which file it has, and
  nothing in the output says which kind of list it is.
- **Version comparison is numeric-prefix only.** `42.0.5rc1` compares as
  `(42, 0, 5)` — the conservative reading for a capability question, and not
  PEP 440 or semver. A pre-release that genuinely precedes its release will
  compare as equal to it.
- **A dependency is not evidence that the library is USED.** A manifest entry
  says the code can reach it, not that it does. Pairing a library finding with
  the source call sites that import it is real correlation work and is not
  done: the two views sit side by side in the CBOM and nothing joins them.
- **`go.sum` lists build-graph modules, including test-only ones.** It is read
  only when there is no `go.mod`, which is rare, but when it is the result
  over-reports what the binary actually links.
