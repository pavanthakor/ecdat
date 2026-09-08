"""The single Finding type every ECDAT scanner emits (ADR-0001).

Scanner plugins across all three views -- what a repo *declares*, what an
artefact *ships*, what a host is *observed* doing -- produce exactly one shape:
:class:`Finding`. The normaliser consumes that shape and nothing else, which is
what lets the CBOM stay the one internal model.

Invariants enforced here, because this is the trust boundary between untrusted
scanner output and the CBOM:

* every Finding carries at least one :class:`Occurrence` of evidence;
* ``confidence`` is a probability in ``[0.0, 1.0]``;
* every vocabulary is closed -- unknown views/types/primitives/usages are
  rejected rather than silently passed through;
* models are frozen, so a Finding cannot be edited after it is emitted; the
  correlator and policy engine derive new objects instead of mutating evidence.

Nothing in this module reaches the network or the filesystem.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "AssetType",
    "Evidence",
    "Finding",
    "Occurrence",
    "Primitive",
    "Usage",
    "View",
]

#: Which of the three drift views a fact came from.
#:
#: ``declared``  -- source, manifests, config: what the team says it uses.
#: ``shipped``   -- images, binaries, certificates: what actually got built.
#: ``observed``  -- runtime probes and handshakes: what is really running.
View = Literal["declared", "shipped", "observed"]

#: The kind of cryptographic asset a finding is about. Mirrors the CycloneDX
#: 1.6 ``cryptoProperties.assetType`` vocabulary plus the container assets
#: (library/module/service) ECDAT needs for blast-radius reasoning.
AssetType = Literal[
    "algorithm",
    "certificate",
    "protocol",
    "key",
    "library",
    "module",
    "service",
]

#: The cryptographic primitive family. Drives quantum-risk scoring: Shor breaks
#: pke/signature/key-agreement outright, Grover only halves the effective
#: strength of block ciphers and hashes.
Primitive = Literal[
    "pke",
    "signature",
    "kem",
    "key-agreement",
    "block-cipher",
    "stream-cipher",
    "hash",
    "mac",
    "kdf",
    "drbg",
    "unknown",
]

#: What the asset is being used *for*. A recommendation is only correct if it
#: matches usage: an RSA key-transport site becomes ML-KEM, an RSA signing site
#: becomes ML-DSA. Never collapse these.
Usage = Literal[
    "sign",
    "verify",
    "key-exchange",
    "key-transport",
    "encrypt",
    "decrypt",
    "hash",
    "kdf",
    "unknown",
]


class _Frozen(BaseModel):
    """Base for the schema: immutable, closed, and strict about vocabularies."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=False,
    )


class Occurrence(_Frozen):
    """One concrete sighting of a cryptographic asset.

    An Occurrence is the auditable "where and how did you know that": a
    reviewer must be able to go to ``locator`` and see the thing for
    themselves.
    """

    view: View
    #: Where it was seen, in a view-appropriate address form. Examples:
    #: ``"services/auth/jwt.py:42"``, ``"sha256:9f3a/layer/4"``,
    #: ``"host-07:pid2231"``.
    locator: str
    #: How it was seen -- the detector and its version, or the parsed fact.
    #: Examples: ``"rule=py-jwt-rs256@1.3"``, ``"libssl.so.3=3.0.2"``,
    #: ``"probe=RSA_sign nid=rsaEncryption"``.
    detail: str
    #: A short human-readable excerpt: the code line, certificate subject or
    #: symbol name.
    #:
    #: NEVER secret key material. Scanners must not place private keys, seeds,
    #: passphrases or session secrets here; ECDAT stores no secret key
    #: material anywhere.
    snippet: str | None = None


class Evidence(_Frozen):
    """The set of occurrences backing a finding. Never empty."""

    occurrences: list[Occurrence]

    @field_validator("occurrences")
    @classmethod
    def _at_least_one_occurrence(cls, value: list[Occurrence]) -> list[Occurrence]:
        if not value:
            raise ValueError(
                "evidence requires at least one occurrence; "
                "a finding with no evidence must not be emitted"
            )
        return value


class Finding(_Frozen):
    """One cryptographic fact discovered by one scanner, in one view.

    A Finding is a claim plus its receipts. It is deliberately pre-normalisation:
    scanners report what they saw in canonical spelling, and the normaliser --
    not the scanner -- decides how it maps into the CBOM.
    """

    #: Stable identifier of the emitting plugin, e.g. ``"source.semgrep"``.
    scanner_id: str
    view: View
    asset_type: AssetType
    primitive: Primitive
    #: Canonical algorithm name, e.g. ``"RSA"``, ``"ECDSA"``, ``"AES"``,
    #: ``"SHA-1"``. Canonicalisation is the scanner's job; the normaliser
    #: assumes these names are already agreed.
    algorithm: str
    #: Algorithm-specific detail: ``key_size``, ``curve``, ``mode``,
    #: ``padding``, ``version``, ``cipher_suites``, ``group``, ``valid_to``, ...
    #: Untyped on purpose at this layer; the knowledge packs give meaning to the
    #: keys they care about.
    params: dict[str, Any] = Field(default_factory=dict)
    usage: Usage = "unknown"
    #: Whether the choice can be changed without a code edit.
    #: ``False`` = hard-coded, ``True`` = read from config, ``None`` = unknown.
    #: Feeds migration effort estimates.
    configurable: bool | None = None
    evidence: Evidence
    #: ``1.0`` for a parsed fact (a certificate field, a package version);
    #: below ``1.0`` for a heuristic match. Must be a probability.
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    #: Verbatim detector output, kept for traceability and re-scoring. Never
    #: interpreted by the normaliser.
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def _confidence_is_a_probability(cls, value: float) -> float:
        # Written as a positive range test so NaN -- for which every comparison
        # is False -- is rejected rather than sailing through a `> 1.0` check.
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {value!r}")
        return value
