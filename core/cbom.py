"""Findings -> a CycloneDX 1.6 CBOM (ADR-0002).

This module writes down only what a finding already states. It maps ECDAT's
vocabularies onto the CycloneDX ones, merges findings that share an identity,
and lays everything out in a fixed order so the same input always produces the
same bytes.

NO SCORING HAPPENS HERE. No Mosca value, no risk rating, no DST roadmap
deadline, no severity. Those are judgements about a fact, and they belong to
the policy slice, which reads the CBOM. The only numbers this module writes are
structural properties of the algorithm itself -- see _NIST_CATEGORY below --
each of which is a definition, not an assessment.

Anything ECDAT-specific goes in the standard ``properties`` list under an
``ecdat:`` name. Nothing ECDAT-specific is written anywhere else, so the
document stays a plain CycloneDX 1.6 BOM to any other reader.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from hashlib import blake2b
from typing import Any, NamedTuple

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence
from cyclonedx.model.component_evidence import Occurrence as CdxOccurrence
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)

from core.identity import finding_identity
from core.params import canonicalise_params
from core.scanner import CoverageLog, Target
from core.schema import AssetType, Evidence, Finding, Occurrence, Primitive, Usage

__all__ = ["build_cbom", "dedup"]

# --------------------------------------------------------------------------
# vocabulary mapping
#
# CycloneDX 1.6 is narrower than ECDAT in two places, so these are not identity
# maps:
#   * CryptoAssetType has four values. `key` becomes related-crypto-material;
#     `library` / `module` / `service` are not cryptographic assets at all --
#     they are the things that *contain* crypto -- so they become ordinary
#     components and keep their ECDAT type in an ecdat:asset_type property.
#   * CryptoFunction has no name for key exchange or key transport, so those
#     map to `other` and the exact term survives in ecdat:usage.
# --------------------------------------------------------------------------

_CRYPTO_ASSET_TYPE: dict[str, CryptoAssetType] = {
    "algorithm": CryptoAssetType.ALGORITHM,
    "certificate": CryptoAssetType.CERTIFICATE,
    "protocol": CryptoAssetType.PROTOCOL,
    "key": CryptoAssetType.RELATED_CRYPTO_MATERIAL,
}

_COMPONENT_TYPE: dict[str, ComponentType] = {
    "library": ComponentType.LIBRARY,
    "module": ComponentType.LIBRARY,
    "service": ComponentType.APPLICATION,
}

_PRIMITIVE: dict[Primitive, CryptoPrimitive] = {
    "pke": CryptoPrimitive.PKE,
    "signature": CryptoPrimitive.SIGNATURE,
    "kem": CryptoPrimitive.KEM,
    "key-agreement": CryptoPrimitive.KEY_AGREE,
    "block-cipher": CryptoPrimitive.BLOCK_CIPHER,
    "stream-cipher": CryptoPrimitive.STREAM_CIPHER,
    "hash": CryptoPrimitive.HASH,
    "mac": CryptoPrimitive.MAC,
    "kdf": CryptoPrimitive.KDF,
    "drbg": CryptoPrimitive.DRBG,
    "unknown": CryptoPrimitive.UNKNOWN,
}

_CRYPTO_FUNCTION: dict[Usage, CryptoFunction] = {
    "sign": CryptoFunction.SIGN,
    "verify": CryptoFunction.VERIFY,
    "encrypt": CryptoFunction.ENCRYPT,
    "decrypt": CryptoFunction.DECRYPT,
    "hash": CryptoFunction.DIGEST,
    "kdf": CryptoFunction.KEYDERIVE,
    "key-exchange": CryptoFunction.OTHER,
    "key-transport": CryptoFunction.OTHER,
}

_MATERIAL_TYPE: dict[str, RelatedCryptoMaterialType] = {
    m.value: m for m in RelatedCryptoMaterialType
}

# --------------------------------------------------------------------------
# structural algorithm facts
#
# nistQuantumSecurityLevel is the NIST PQC *security strength category* (0-6),
# not a bit strength. Categories 1-5 are DEFINED by these anchors in the NIST
# PQC Call for Proposals (Section 4.A.5, "Security Strength Categories", 2016),
# which is the page the CycloneDX 1.6 schema cites for the field:
#   1 = key search on AES-128   2 = collision search on SHA-256
#   3 = key search on AES-192   4 = collision search on SHA-384
#   5 = key search on AES-256
# Only those definitional anchors appear here. Anything else -- SHA-512,
# ChaCha20, RSA-3072-is-roughly-AES-128 -- is an inference about strength, and
# inferences belong to the policy engine, not the normaliser.
# --------------------------------------------------------------------------

_NIST_CATEGORY: dict[tuple[str, int | None], int] = {
    ("AES", 128): 1,
    ("AES", 192): 3,
    ("AES", 256): 5,
    ("SHA-256", None): 2,
    ("SHA3-256", None): 2,
    ("SHA-384", None): 4,
    ("SHA3-384", None): 4,
}

#: Shor's algorithm solves the factoring and discrete-log problems these rest
#: on, so they meet none of the categories above. The CycloneDX schema defines
#: 0 as exactly that: "none of the categories are met". (NIST IR 8413; NSA
#: CNSA 2.0.) This is a structural consequence of the algorithm's hard problem,
#: not a risk score.
_QUANTUM_BROKEN = frozenset(
    {
        "RSA",
        "DSA",
        "DH",
        "DHE",
        "ECDH",
        "ECDHE",
        "ECDSA",
        "EDDSA",
        "ED25519",
        "ED448",
        "ELGAMAL",
    }
)

#: Key search on AES-k costs 2^k classically (FIPS 197). Stated for AES only:
#: for everything else the classical level is an estimate, not a definition.
_CLASSICAL_LEVEL: dict[tuple[str, int | None], int] = {
    ("AES", 128): 128,
    ("AES", 192): 192,
    ("AES", 256): 256,
}


class _Group(NamedTuple):
    """One artefact: its identity, the merged finding, and who reported what."""

    identity: str
    finding: Finding
    #: occurrence -> the scanners that reported it, sorted.
    sources: dict[Occurrence, tuple[str, ...]]


def _occurrence_sort_key(occurrence: Occurrence) -> tuple[str, str, str, str]:
    return (
        occurrence.view,
        occurrence.locator,
        occurrence.detail,
        occurrence.snippet or "",
    )


def _merge(identity: str, group: Sequence[Finding]) -> _Group:
    """Fold findings that mean the same artefact into one.

    Every identifying field already agrees by construction, so only the
    sighting-level fields need a rule:

    * evidence  -- union of occurrences, deduplicated, sorted by (view, locator)
    * confidence-- the most confident report wins
    * configurable -- hard-coded (False) beats configurable (True) beats unknown;
      one site that cannot be changed without a code edit makes the artefact
      not freely configurable
    """
    ordered = sorted(
        group,
        key=lambda f: (
            f.view,
            f.scanner_id,
            tuple(_occurrence_sort_key(o) for o in f.evidence.occurrences),
        ),
    )
    base = ordered[0]

    sources: dict[Occurrence, list[str]] = {}
    for finding in ordered:
        for occurrence in finding.evidence.occurrences:
            scanners = sources.setdefault(occurrence, [])
            if finding.scanner_id not in scanners:
                scanners.append(finding.scanner_id)

    occurrences = sorted(sources, key=_occurrence_sort_key)

    configurable: bool | None = None
    if any(f.configurable is False for f in ordered):
        configurable = False
    elif any(f.configurable is True for f in ordered):
        configurable = True

    merged = base.model_copy(
        update={
            "evidence": Evidence(occurrences=occurrences),
            "confidence": max(f.confidence for f in ordered),
            "configurable": configurable,
        }
    )
    return _Group(
        identity=identity,
        finding=merged,
        sources={o: tuple(sorted(sources[o])) for o in occurrences},
    )


def _canonical(finding: Finding) -> Finding:
    """The same finding with its params in canonical form (ADR-0029)."""
    canonical = canonicalise_params(finding.params)
    if canonical == finding.params:
        return finding
    return finding.model_copy(update={"params": canonical})


def _revalidated(finding: Finding) -> Finding:
    """The finding, through the schema's validators AGAIN (ADR-0036).

    ``model_construct`` and ``model_copy(update=...)`` both skip validation, so
    a Finding reaching the normaliser is no proof it passed the schema. Every
    one is re-validated here -- the key-material redaction with the rest -- so
    no path around the validators reaches a CBOM. Idempotent: a finding that
    did pass comes back equal, and the guard does not fire twice.
    """
    return Finding.model_validate(finding.model_dump())


def _group_findings(findings: Iterable[Finding], target: Target) -> list[_Group]:
    grouped: dict[str, list[Finding]] = {}
    for reported in findings:
        # Canonicalise params BEFORE the identity hash (ADR-0029). params are
        # identifying, so `key_size: 2048` and `key_size: "2048"` -- the same
        # RSA-2048 reported by two scanners that disagreed about a type -- would
        # otherwise hash to two components. `core/params.py` is the one place
        # that says what a known param is; an unknown one passes through.
        finding = _canonical(_revalidated(reported))
        grouped.setdefault(finding_identity(finding, target), []).append(finding)
    # Sorting by identity is what makes the output independent of input order.
    return [_merge(identity, grouped[identity]) for identity in sorted(grouped)]


def dedup(findings: Iterable[Finding], target: Target) -> list[tuple[str, Finding]]:
    """Collapse findings onto one merged Finding per artefact, sorted by identity.

    Re-hashing a merged finding yields the identity it was grouped under, so
    dedup is idempotent across scan runs.
    """
    return [(g.identity, g.finding) for g in _group_findings(findings, target)]


# --------------------------------------------------------------------------
# component construction
# --------------------------------------------------------------------------


def _int_param(params: dict[str, Any], key: str) -> int | None:
    value = params.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str_param(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    return value if isinstance(value, str) else None


def _component_name(finding: Finding) -> str:
    if finding.asset_type == "protocol":
        version = _str_param(finding.params, "version")
        return f"{finding.algorithm} {version}" if version else finding.algorithm
    if finding.asset_type in _COMPONENT_TYPE:
        return finding.algorithm
    key_size = _int_param(finding.params, "key_size")
    curve = _str_param(finding.params, "curve")
    if key_size is not None:
        return f"{finding.algorithm}-{key_size}"
    return f"{finding.algorithm}-{curve}" if curve else finding.algorithm


def _parse_datetime(params: dict[str, Any], key: str) -> datetime | None:
    raw = _str_param(params, key)
    if raw is None:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        # Unparseable dates are not invented; the raw value still reaches the
        # CBOM as an ecdat:param property.
        return None


def _algorithm_properties(finding: Finding) -> AlgorithmProperties:
    params = finding.params
    key_size = _int_param(params, "key_size")
    curve = _str_param(params, "curve")
    algorithm = finding.algorithm.upper()

    nist_level: int | None = _NIST_CATEGORY.get((finding.algorithm, key_size))
    if nist_level is None and algorithm in _QUANTUM_BROKEN:
        nist_level = 0

    mode_value = (_str_param(params, "mode") or "").lower()
    padding_value = (_str_param(params, "padding") or "").lower()
    function = _CRYPTO_FUNCTION.get(finding.usage)

    return AlgorithmProperties(
        primitive=_PRIMITIVE[finding.primitive],
        parameter_set_identifier=str(key_size) if key_size is not None else curve,
        curve=curve,
        mode=CryptoMode(mode_value) if mode_value in _MODES else None,
        padding=CryptoPadding(padding_value) if padding_value in _PADDINGS else None,
        crypto_functions=[function] if function is not None else None,
        classical_security_level=_CLASSICAL_LEVEL.get((finding.algorithm, key_size)),
        nist_quantum_security_level=nist_level,
    )


_MODES = {m.value for m in CryptoMode}
_PADDINGS = {p.value for p in CryptoPadding}
_PROTOCOL_TYPES = {p.value for p in ProtocolPropertiesType}


def _certificate_properties(finding: Finding) -> CertificateProperties:
    params = finding.params
    return CertificateProperties(
        subject_name=_str_param(params, "subject"),
        issuer_name=_str_param(params, "issuer"),
        not_valid_before=_parse_datetime(params, "valid_from"),
        not_valid_after=_parse_datetime(params, "valid_to"),
        certificate_format=_str_param(params, "format"),
        certificate_extension=_str_param(params, "extension"),
    )


def _protocol_properties(finding: Finding) -> ProtocolProperties:
    params = finding.params
    name = finding.algorithm.lower()
    suites = params.get("cipher_suites")
    cipher_suites = (
        [ProtocolPropertiesCipherSuite(name=str(s)) for s in suites]
        if isinstance(suites, list)
        else None
    )
    return ProtocolProperties(
        type=ProtocolPropertiesType(name)
        if name in _PROTOCOL_TYPES
        else ProtocolPropertiesType.OTHER,
        version=_str_param(params, "version"),
        cipher_suites=cipher_suites,
    )


def _related_material_properties(finding: Finding) -> RelatedCryptoMaterialProperties:
    params = finding.params
    material = (_str_param(params, "material") or "").lower()
    # `value` is never set: no secret key material is ever stored (ADR-0001).
    return RelatedCryptoMaterialProperties(
        type=_MATERIAL_TYPE.get(material, RelatedCryptoMaterialType.KEY),
        size=_int_param(params, "key_size"),
        format=_str_param(params, "format"),
    )


def _crypto_properties(finding: Finding) -> CryptoProperties | None:
    asset_type: AssetType = finding.asset_type
    cdx_type = _CRYPTO_ASSET_TYPE.get(asset_type)
    if cdx_type is None:
        return None
    return CryptoProperties(
        asset_type=cdx_type,
        algorithm_properties=(
            _algorithm_properties(finding) if asset_type == "algorithm" else None
        ),
        certificate_properties=(
            _certificate_properties(finding) if asset_type == "certificate" else None
        ),
        protocol_properties=(
            _protocol_properties(finding) if asset_type == "protocol" else None
        ),
        related_crypto_material_properties=(
            _related_material_properties(finding) if asset_type == "key" else None
        ),
        oid=_str_param(finding.params, "oid"),
    )


def _properties(group: _Group) -> list[Property]:
    """Everything ECDAT-specific, in the one place CycloneDX reserves for it.

    ``ecdat:occurrence`` packs one sighting as
    ``view|locator|scanner[,scanner]|detail``; the view leads so the list sorts
    by (view, locator). The snippet is deliberately not repeated here -- it
    lives on the standard evidence occurrence.
    """
    finding = group.finding
    properties = [
        Property(name="ecdat:asset_type", value=finding.asset_type),
        Property(name="ecdat:usage", value=finding.usage),
        Property(name="ecdat:confidence", value=str(finding.confidence)),
    ]
    if finding.configurable is not None:
        properties.append(
            Property(
                name="ecdat:configurable",
                value="true" if finding.configurable else "false",
            )
        )
    properties.extend(
        Property(name="ecdat:view", value=view)
        for view in sorted({o.view for o in finding.evidence.occurrences})
    )
    properties.extend(
        Property(
            name="ecdat:occurrence",
            value="|".join((o.view, o.locator, ",".join(group.sources[o]), o.detail)),
        )
        for o in finding.evidence.occurrences
    )
    # Every param reaches the CBOM even when CycloneDX has no field for it, so
    # nothing a scanner reported is silently dropped.
    properties.extend(
        Property(name=f"ecdat:param:{key}", value=str(finding.params[key]))
        for key in sorted(finding.params)
    )
    return properties


def _evidence(group: _Group) -> ComponentEvidence:
    """Standard CycloneDX evidence: one occurrence per sighting.

    Each occurrence gets an explicit bom-ref of ``<identity>#<n>``. That is not
    decoration: an occurrence whose bom-ref is unset hashes on ``id(self)`` and
    compares non-transitively, so the library's SortedSet would order evidence
    by memory address and the CBOM would not be byte-reproducible. Numbering
    them also gives the correlator a stable address for a single sighting.
    """
    occurrences = []
    for index, o in enumerate(group.finding.evidence.occurrences):
        location, _, tail = o.locator.rpartition(":")
        positional = bool(location) and tail.isdigit() and o.view != "observed"
        context = o.detail if o.snippet is None else f"{o.detail} :: {o.snippet}"
        occurrences.append(
            CdxOccurrence(
                bom_ref=f"{group.identity}#{index}",
                location=location if positional else o.locator,
                line=int(tail) if positional else None,
                additional_context=context,
            )
        )
    return ComponentEvidence(occurrences=occurrences)


def _component(group: _Group) -> Component:
    finding = group.finding
    version = (
        _str_param(finding.params, "version")
        if finding.asset_type in _COMPONENT_TYPE
        else None
    )
    return Component(
        name=_component_name(finding),
        type=_COMPONENT_TYPE.get(finding.asset_type, ComponentType.CRYPTOGRAPHIC_ASSET),
        bom_ref=group.identity,
        version=version,
        properties=_properties(group),
        evidence=_evidence(group),
        crypto_properties=_crypto_properties(finding),
    )


#: Namespace for content-derived serial numbers. Fixed forever: changing it
#: would change the serial number of every CBOM ECDAT has ever produced.
_SERIAL_NAMESPACE = uuid.UUID("6f0c1f6a-9d4e-4b7a-8c21-ecda700cb0b0")


def _content_serial_number(
    groups: Sequence[_Group], target: Target, coverage: CoverageLog | None = None
) -> uuid.UUID:
    """A serial number derived from the content, so re-scanning is a no-op diff.

    Coverage gaps count as content (ADR-0033): a document that says "two files
    could not be parsed" is not the same document as one that does not. Folded
    in ONLY when there is a gap, so every existing serial number is unchanged.
    """
    gaps = [
        f"gap:{g.scanner}:{g.kind}:{g.path}"
        for g in (coverage.gaps if coverage else [])
    ]
    digest = blake2b(
        "\x1f".join(
            [target.system or target.ref, *(g.identity for g in groups), *gaps]
        ).encode("utf-8"),
        digest_size=16,
    ).hexdigest()
    return uuid.uuid5(_SERIAL_NAMESPACE, f"urn:ecdat:cbom:{digest}")


def _files(count: int) -> str:
    return f"{count} file" if count == 1 else f"{count} files"


def _coverage_note(coverage: CoverageLog, scanner: str) -> str:
    examined = coverage.examined.get(scanner, 0)
    unparsed = len(
        {g.path for g in coverage.gaps if g.scanner == scanner and g.kind == "unparsed"}
    )
    partial = len(
        {
            g.path
            for g in coverage.gaps
            if g.scanner == scanner and g.kind == "partially-parsed"
        }
    )
    if coverage.nothing_parsed(scanner):
        return (
            f"{scanner}: nothing could be parsed -- {unparsed} of {_files(examined)} "
            "examined failed to parse, so this document says nothing about them. It "
            "is not a clean result."
        )
    verb = "was" if partial == 1 else "were"
    return (
        f"{scanner}: {unparsed} of {_files(examined)} examined could not be parsed "
        f"and {partial} {verb} only partially parsed; findings from what could not "
        "be read are absent, not clean."
    )


def _coverage_properties(coverage: CoverageLog | None) -> list[Property]:
    """What the scanners could not read, as scan-level metadata (ADR-0033).

    Written ONLY when there is a gap, so a fully-read scan keeps exactly the
    bytes it had before this existed. Metadata rather than a component: a file
    that could not be read is not an artefact, and inventing one would inflate
    every count in the document.
    """
    if coverage is None or not coverage.gaps:
        return []
    unparsed = sorted({g.path for g in coverage.gaps if g.kind == "unparsed"})
    partial = sorted({g.path for g in coverage.gaps if g.kind == "partially-parsed"})
    properties = [
        Property(name="ecdat:coverage:unparsed", value=str(len(unparsed))),
        *(Property(name="ecdat:coverage:unparsed:file", value=p) for p in unparsed),
        Property(name="ecdat:coverage:partially_parsed", value=str(len(partial))),
        *(
            Property(name="ecdat:coverage:partially_parsed:file", value=p)
            for p in partial
        ),
    ]
    for scanner in sorted({g.scanner for g in coverage.gaps}):
        properties.append(
            Property(
                name=f"ecdat:coverage:{scanner}:examined",
                value=str(coverage.examined.get(scanner, 0)),
            )
        )
        properties.append(
            Property(
                name="ecdat:coverage:note", value=_coverage_note(coverage, scanner)
            )
        )
    return properties


def build_cbom(
    findings: Iterable[Finding],
    target: Target,
    *,
    coverage: CoverageLog | None = None,
    serial_number: uuid.UUID | None = None,
    timestamp: datetime | None = None,
) -> Bom:
    """Normalise findings into a CycloneDX 1.6 BOM.

    Deterministic by construction: findings are merged by identity, components
    are emitted in identity order, occurrences in (view, locator) order, and
    the two fields CycloneDX would otherwise randomise are pinned -- the serial
    number is derived from the content, and the timestamp is left unset unless
    a caller supplies one. A timestamp is a fact about the scan run, not about
    the artefacts, so it is the caller's to add.
    """
    groups = _group_findings(findings, target)
    bom = Bom(components=[_component(g) for g in groups])
    bom.serial_number = serial_number or _content_serial_number(
        groups, target, coverage
    )
    # cyclonedx types this setter as non-optional, but None is accepted and
    # serialises as "no timestamp", which is what determinism needs.
    bom.metadata.timestamp = timestamp  # type: ignore[assignment]
    # A SortedSet ordered by (name, value): deterministic without further help.
    bom.metadata.properties.update(_coverage_properties(coverage))
    return bom
