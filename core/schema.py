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
  correlator and policy engine derive new objects instead of mutating evidence;
* **no secret key material in evidence** (ADR-0036). Private-key armour and
  DER private-key structure are redacted from every free-text field and every
  string param. A secret-named high-entropy literal is redacted from every
  snippet, and every literal from the snippet of a finding its own scanner
  called key material. Enforced HERE rather than trusted to each scanner, so a
  scanner that forgets cannot put key bytes in the CBOM. See
  :mod:`core.redaction`.

Nothing in this module reaches the network or the filesystem.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from core.redaction import (
    is_key_context,
    redact_evidence,
    redact_key_context,
    redact_params,
)

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
    #: NEVER secret key material. Scanners must still not place private keys,
    #: seeds, passphrases or session secrets here -- and when one does, the
    #: validator below redacts them before the Occurrence exists (ADR-0036).
    #: ECDAT stores no secret key material anywhere.
    snippet: str | None = None

    @field_validator("locator", "detail", "snippet")
    @classmethod
    def _no_key_material(cls, value: str | None, info: ValidationInfo) -> str | None:
        """The structural backstop (ADR-0036), on every free-text field.

        A scanner is still expected to redact its own key matches; this is what
        holds when one does not.
        """
        if value is None:
            return None
        field = info.field_name or "evidence"
        # A locator that needed redacting is not repeated into the log line
        # that reports it.
        where = None if field == "locator" else info.data.get("locator")
        return redact_evidence(value, field=field, locator=where)


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
    #: Declared AFTER ``scanner_id``, ``asset_type`` and ``params`` on purpose:
    #: its validator reads them to decide whether this is key material.
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

    @field_validator("params")
    @classmethod
    def _no_key_material_in_params(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Params reach the CBOM as ``ecdat:param:*`` properties: evidence too."""
        return redact_params(value)

    @field_validator("evidence")
    @classmethod
    def _no_literal_in_key_material(
        cls, value: Evidence, info: ValidationInfo
    ) -> Evidence:
        """A finding its own scanner called key material keeps no literal.

        ``asset_type == "key"`` (not a public key) or ADR-0034's ``candidate``
        flag is the scanner saying "this line is about a key". Rule 4 of
        ADR-0036 takes it at its word.
        """
        if not is_key_context(
            info.data.get("asset_type"), info.data.get("params") or {}
        ):
            return value
        scanner = info.data.get("scanner_id")
        redacted = [
            occurrence
            if occurrence.snippet is None
            else occurrence.model_copy(
                update={
                    "snippet": redact_key_context(
                        occurrence.snippet,
                        locator=occurrence.locator,
                        scanner_id=scanner,
                    )
                }
            )
            for occurrence in value.occurrences
        ]
        unchanged = all(
            new.snippet == old.snippet
            for new, old in zip(redacted, value.occurrences, strict=True)
        )
        return value if unchanged else Evidence(occurrences=redacted)
