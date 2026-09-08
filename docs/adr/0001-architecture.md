# ADR-0001: One Finding type, one CBOM, many views

- Status: accepted
- Date: 2026-09-08
- Slice: Phase 0 — core schema and scanner contract

## Context

ECDAT (SIH26164, NTRO) has to discover cryptography from six very different
places: source code, dependency manifests, container images, compiled binaries,
running processes and network handshakes. Each source has its own detector
(Semgrep and tree-sitter, SBOM parsers, image layer walkers, ELF symbol
readers, eBPF probes, handshake capture) and its own natural output shape.

Four capabilities then have to reason across all of it at once:

1. compliance against the Indian DST post-quantum roadmap deadlines,
2. drift detection between what is *declared*, what is *shipped* and what is
   *observed*,
3. usage-aware post-quantum recommendations with verified fix diffs,
4. Mosca-inequality and blast-radius prioritisation.

If each detector kept its own shape, every one of those four would need N
adapters, and the risk score for "RSA-2048" would depend on which scanner
happened to find it. The obvious failure mode for a tool like this is N
detectors × M consumers of ad-hoc data.

## Decision

**Scanner plugins emit exactly one type — `Finding` — and a normaliser turns
findings into a CycloneDX 1.6 CBOM that is the single internal model.**

```
scanners/*  --Finding-->  normaliser  --> CycloneDX 1.6 CBOM (SQLite)
                                              |
                                +-------------+-------------+
                                |                           |
                          policy engine               correlator
                                |                           |
                                +-------------+-------------+
                                              |
                                             API
                                              |
                                    dashboard / exports
```

Concretely:

- **`core.schema.Finding`** is the only thing a scanner may produce. It carries
  the view it came from, the asset type, the primitive family, a canonical
  algorithm name, algorithm parameters, the usage, whether the choice is
  configurable, its evidence, and a confidence.
- **`core.scanner.Scanner`** is a structural `Protocol` (`id`, `view`,
  `supports()`, `scan()`), not a base class. Scanner packages therefore import
  nothing from the orchestrator, and a plugin is testable in isolation with a
  `Target` and a `ScanContext`.
- **The CBOM is the single internal model.** After normalisation, no component
  reads findings directly. The policy engine, correlator, recommender and API
  all read the CBOM stored in SQLite.
- **Every output is a view of that one store.** The dashboard, the compliance
  report, the drift report and the exports are projections — never parallel
  data models that could disagree with each other.

`view` is a property of the *finding*, not of a separate pipeline. All three
views land in the same CBOM and drift is computed by the correlator comparing
them, rather than by running three separate stacks.

### Why CycloneDX 1.6 rather than our own model

1.6 is the version that added `cryptoProperties` (asset types, algorithm
properties, certificate properties, protocol properties, related material), so
it already models what we discover. It is an external standard with a published
schema we can validate against, and it is what downstream consumers expect to
be handed. `AssetType` here deliberately mirrors the CycloneDX asset-type
vocabulary so mapping stays close to identity, plus the container assets
(`library`, `module`, `service`) needed for blast-radius reasoning.

## Invariants

These are contractual. Each is enforced in code, and each gets negative tests,
not just happy-path tests.

1. **Evidence on every finding.** `Evidence.occurrences` must contain at least
   one `Occurrence`; a validator rejects an empty list. Every claim ECDAT makes
   is traceable to a locator a human can go and look at. A finding with no
   evidence is never emitted.
2. **Rule id on every score.** Nothing scores an artefact anonymously. Each
   score records the identifier of the rule that produced it, so any number on
   the dashboard can be traced to the policy that generated it and the evidence
   underneath it. `Occurrence.detail` carries the detector and version
   (`rule=py-jwt-rs256@1.3`) for the same reason on the discovery side.
3. **Offline scan path.** No outbound network calls during a scan. All
   cryptographic knowledge comes from the packs under
   `ScanContext.knowledge_dir`. This is a hard requirement for an NTRO-facing
   tool that will run inside air-gapped estates, and it also makes scans
   reproducible.
4. **Read-only against targets.** A scanner never modifies a repo, image or
   host. Anything that must be unpacked goes under `ScanContext.scratch_dir`.
   Fix-it operates on a sandbox copy and only ever proposes a diff.
5. **Deterministic CBOM.** The same input with the same knowledge packs
   produces a byte-identical CBOM. Findings are frozen after emission,
   vocabularies are closed literals, and validation happens on deserialisation
   as well as construction, so a round-trip cannot alter a fact.
6. **No secret key material, ever.** `Occurrence.snippet` holds a code line, a
   certificate subject or a symbol name. Private keys, seeds, passphrases and
   session secrets are never stored, logged or exported.

## Consequences

Good:

- New scanners are additive: implement `Scanner`, emit `Finding`, done. Nothing
  downstream changes.
- Risk scoring is scanner-independent — RSA-2048 scores the same whether it was
  found in source or on the wire.
- Frozen models mean the correlator and policy engine cannot corrupt evidence;
  they derive new objects.
- Closed vocabularies plus `extra="forbid"` turn scanner typos into loud
  validation errors instead of silently dropped data.

Costs, accepted:

- `Finding` is a lowest-common-denominator shape. Detector-specific detail has
  to live in `params` or `raw`, which are untyped at this layer; the knowledge
  packs give meaning to the keys they care about.
- Canonicalising algorithm names is pushed onto scanners. Two scanners spelling
  ECDSA differently would produce two components. A shared canonicaliser is the
  likely follow-up.
- CycloneDX 1.6 does not model everything we want (notably observed-runtime
  nuance); anything that does not fit goes in properties rather than expanding
  the internal model.
- Frozen models with `dict` fields are not hashable, so deduplication cannot
  key on the object itself. See PUNCHLIST.md.

## Alternatives rejected

- **Per-scanner output shapes with adapters at the consumer.** N×M adapters;
  scoring drifts per scanner. Rejected.
- **A bespoke internal model, exporting CycloneDX only at the edge.** Two
  models to keep in sync, and the export becomes the untested path — exactly
  the artefact judges and downstream tools care about most. Rejected.
- **Three separate pipelines, one per view, joined at the end.** Triples the
  storage and scoring surface, and makes drift a join across three schemas
  instead of a query over one. Rejected.
- **`Scanner` as an abstract base class.** Forces plugin packages to import the
  core and inverts the dependency we want. A structural `Protocol` gives the
  same checking without the coupling.
