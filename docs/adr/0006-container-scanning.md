# ADR-0006: Container image scanning, and the shipped view

* Status: accepted
* Date: 2026-09-09
* Slice: Scanner C — container image crypto detection
* Extends: [ADR-0001](0001-architecture.md) (scanner contract),
  [ADR-0002](0002-cbom-normaliser.md) (cross-view non-merge),
  [ADR-0005](0005-scanner-registry.md) (registry)

## Context

`shipped` is the second of the three drift views, and the one that most often
contradicts the first. A repository can declare a post-quantum-ready
dependency and still ship an OpenSSL with no ML-KEM compiled into it. Scanner C
produces the evidence that makes that contradiction visible.

## Decision

### Evidence is addressed by layer digest

Every occurrence locator is `sha256:<layer-diff-id>/<path-inside-layer>`, using
the real `diff_id` from the image config's `rootfs.diff_ids` rather than an
invented identifier. The digest is the layer's content identity, so the same
layer in two images produces the same locator — which is what will let the
correlator say "this came in with the base image, not with your Dockerfile".

Where the image config carries `history`, the creating instruction is attached
as `params.created_by`. `history` entries marked `empty_layer` (ENV, LABEL) are
dropped first, because only non-empty entries correspond to filesystem layers;
without that the instructions misalign with the layers by one for every
metadata step. Best-effort: an image built by a tool that omits history yields
no `created_by` at all rather than a wrong one.

### Local images only — no registry pull in the scan path

`target.ref` is a `docker save` tar or an OCI layout directory on disk. There
is no pull inside `scan()`, not even as a fallback when the path is missing —
a missing path raises. The scan path is air-gapped by construction rather than
by configuration, and a test patches `socket.socket` and
`socket.create_connection` to prove it. Pulling is a separate step someone runs
deliberately, before scanning.

### Streamed, never extracted

Layers are read as nested tar streams via `mode="r|*"`, which also transparently
handles a gzipped blob. Nothing is unpacked to disk, so a hostile image cannot
escape a scratch directory it is never given, and `../` in a member name has
nothing to traverse. Members are filtered by path and extension *before* being
read, and any single member over 32 MiB is skipped.

### Certificates are parsed; private keys are not

A certificate is public by design, so it is read out in full: subject, issuer,
validity window, public-key algorithm and size, signature algorithm,
self-signed flag. Its snippet is the common name — public metadata.

A private key gets the opposite treatment. It is recorded by **presence,
location, and a fingerprint of its public half**, with the snippet replaced by
`<redacted key material>`. The private half is loaded only long enough to
derive the public key and is never placed in a Finding, a snippet, or `raw`.

The fingerprint is deliberately SHA-256 over the SubjectPublicKeyInfo DER — the
same construction as an SSH or TLS key fingerprint. It correlates the same key
across images and views while revealing nothing. It is explicitly **not** a
hash of the private key bytes: that would be a verifier for the secret we are
refusing to store, and would let anyone holding a candidate key confirm it
against our database. When a key is encrypted or unparseable the fingerprint is
omitted and `fingerprint_unavailable` says why, rather than falling back to
hashing the secret.

Keystores (`.jks`, `.p12`, `.pfx`) are recorded by presence and format only.
Their contents are never opened.

### The knowledge pack decides what counts as cryptography

Package names live in `knowledge/libraries.yaml`, not in the scanner, the same
way algorithm names live in the semgrep rules and not in the source scanner
(ADR-0004). The scanner maps `libssl3` → `OpenSSL` without knowing either name.

Versions are normalised to upstream before comparison: `3.0.2-0ubuntu1.10` →
`3.0.2`, `3.5.7-r0` → `3.5.7`. Without that, `3.5.7-r0` sorts below `3.5.0` as
a string and the PQC floor gives the wrong answer.

`pqc_capable` is tri-state. `true`/`false` where the pack knows the floor,
**absent** where it does not — the GnuTLS and libgcrypt entries carry
`pqc_capable_from: null` with a note saying their PQC support was not verified
against upstream NEWS. Recording a guessed version there would be exactly the
uncited crypto fact CLAUDE.md forbids.

## The two-layer test strategy

This is the part worth arguing for, because the obvious approach is wrong.

**Layer (a): synthetic tarballs, committed, exhaustively scored.**
`tests/fixtures/build_container_fixtures.py` generates three `docker save`
images under `testdata/images/synthetic/` with real dpkg and apk record
formats, a genuinely valid self-signed certificate, and a planted RSA private
key. Recall and precision are measured against `answer_key.yaml` and precision
is asserted at exactly 1.0.

**Layer (b): the real `ubuntu:22.04` and `alpine:3.22`,** marked `docker` and
skipped automatically when Docker or the image is absent. Must-include
assertions only.

The reason for the split: **`ubuntu:22.04` is a moving tag.** Canonical pushes
point updates into it, so a test asserting `libssl3 == 3.0.2-0ubuntu1.10` is
asserting what Canonical published this morning. A parser regression and a
routine upstream release would look identical, and the build would go red for
the wrong reason often enough that someone would eventually pin the test to
whatever it currently returns — which is how a test stops measuring anything.

So the *logic* is pinned against inputs that cannot drift, and the real images
are used for the thing they are actually good for: proving the parser still
matches reality, and producing the demo's ground truth. The real-image
assertions use a `version_prefix` (`3.0.`, `3.5.`) rather than an exact
version, so an Alpine point release is not a build failure.

The synthetic record formats were copied from the real images field for field.
A made-up format would make the synthetic tests prove nothing about a real
image, which would defeat the whole arrangement.

## Consequences

* First `shipped` view in the system, and the input the drift correlator needs.
  The multi-view non-merge from ADR-0002 is now proved with real data rather
  than hand-built findings: a declared OpenSSL 3.0.2 and a shipped OpenSSL
  3.0.2 produce two components with different `bom-ref`s, because their loci
  differ. Merging them would destroy the signal drift detection exists to find.
* PUNCHLIST #3 (snippet redaction) now covers a second scanner and a second
  view, with a negative test that reads the planted key back out of the fixture
  and asserts none of its base64 body appears anywhere in any Finding.
* **`libssl3` and `libcrypto3` are reported as two components.** They are one
  source package (`openssl`) shipped as two binary packages, and the image
  really does ship both. `params.source_package` carries the link, and rolling
  them up is the correlator's job, not the scanner's.
* **Real CA bundles contain certificates that violate RFC 5280.** Alpine's
  `ca-certificates` ships one with a non-positive serial number, which newer
  `cryptography` warns on today and will reject outright later. A bulk PEM load
  failing would lose the whole ~150-certificate bundle, so the scanner falls
  back to loading block-at-a-time and skipping only the offender. This was
  found by running the integration test, which is precisely what it is for.
* **No layer-deletion (whiteout) handling.** A file deleted in a later layer
  still produces a finding from the layer that introduced it. That is arguably
  correct for supply-chain purposes — the bytes were in the image at some point
  — but it is not the same as "present in the running filesystem", and the
  distinction is not currently recorded. Punchlisted.
* **Image config is read into memory per layer.** Layers are streamed for
  iteration, but each layer blob is held as bytes while it is walked. Fine for
  base images; a multi-gigabyte application image will want a spooled temporary
  file. Punchlisted.

## Alternatives considered

* **Pull from a registry inside `scan()`.** Convenient, and fatal to the
  air-gap guarantee CLAUDE.md states as a design constraint. Rejected outright;
  a pull helper, if one is ever wanted, is a separate CLI step.
* **Shell out to `docker` / `skopeo` / `trivy`.** Rejected: `docker` requires a
  daemon and privileges the scanner should not need, and per CLAUDE.md the
  human runs privileged commands. Reading a tar needs neither. Trivy would also
  put the crypto knowledge in someone else's database rather than in
  `knowledge/`.
* **Extracting layers to the scratch directory and walking the filesystem.**
  Simpler to write, and it hands an untrusted archive the ability to write
  paths of its choosing. Streaming avoids the entire class of problem.
* **Fingerprinting private keys by hashing their bytes.** Rejected on the
  reasoning above: it is a confirmation oracle for the secret. The public-key
  fingerprint gives the same correlation value with none of the exposure.
