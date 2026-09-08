"""Contract tests for the core Finding/Evidence schema (ADR-0001).

These pin the invariants that every scanner plugin must satisfy before its
findings are allowed into the CBOM:

  * a Finding survives a JSON round-trip byte-for-byte (determinism),
  * no Finding exists without at least one occurrence of evidence,
  * confidence is a probability, not an arbitrary float,
  * every AssetType the tool can discover is expressible,
  * an emitted Finding is immutable.

Negative cases are deliberate mutations of a known-good Finding: the schema is
the trust boundary between untrusted scanner output and the CBOM, so it is
tested for what it rejects, not only for what it accepts.
"""

from __future__ import annotations

import typing
from typing import Any

import pytest
from pydantic import ValidationError

from core.schema import AssetType, Evidence, Finding, Occurrence, Primitive, Usage, View

# --------------------------------------------------------------------------
# fixtures / builders
# --------------------------------------------------------------------------


def an_occurrence(**overrides: Any) -> Occurrence:
    kwargs: dict[str, Any] = {
        "view": "declared",
        "locator": "services/auth/jwt.py:42",
        "detail": "rule=py-jwt-rs256@1.3",
        "snippet": 'jwt.encode(claims, key, algorithm="RS256")',
    }
    kwargs.update(overrides)
    return Occurrence(**kwargs)


def a_finding(**overrides: Any) -> Finding:
    kwargs: dict[str, Any] = {
        "scanner_id": "source.semgrep",
        "view": "declared",
        "asset_type": "algorithm",
        "primitive": "signature",
        "algorithm": "RSA",
        "params": {"key_size": 2048, "padding": "PKCS1v15"},
        "usage": "sign",
        "configurable": False,
        "evidence": Evidence(occurrences=[an_occurrence()]),
        "confidence": 1.0,
        "raw": {"rule_id": "py-jwt-rs256", "rule_version": "1.3"},
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


# --------------------------------------------------------------------------
# round-trip / determinism
# --------------------------------------------------------------------------


def test_finding_round_trips_through_json_unchanged() -> None:
    finding = a_finding()

    payload = finding.model_dump_json()
    restored = Finding.model_validate_json(payload)

    assert restored == finding
    # Determinism: re-serialising the restored object must reproduce the exact
    # same bytes, otherwise two identical scans could yield different CBOMs.
    assert restored.model_dump_json() == payload


def test_finding_round_trip_preserves_optional_and_default_fields() -> None:
    finding = a_finding(
        params={},
        usage="unknown",
        configurable=None,
        raw={},
        evidence=Evidence(occurrences=[an_occurrence(snippet=None)]),
    )

    restored = Finding.model_validate_json(finding.model_dump_json())

    assert restored == finding
    assert restored.configurable is None
    assert restored.evidence.occurrences[0].snippet is None


# --------------------------------------------------------------------------
# evidence invariant: >= 1 occurrence
# --------------------------------------------------------------------------


def test_evidence_with_no_occurrences_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Evidence(occurrences=[])


def test_finding_cannot_be_built_without_evidence() -> None:
    with pytest.raises(ValidationError):
        a_finding(evidence=None)


# --------------------------------------------------------------------------
# confidence invariant: 0.0 <= c <= 1.0
# --------------------------------------------------------------------------


def test_confidence_above_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        a_finding(confidence=1.5)


def test_confidence_of_one_half_is_accepted() -> None:
    assert a_finding(confidence=0.5).confidence == 0.5


@pytest.mark.parametrize("bad", [-0.1, 1.000001, float("nan"), float("inf")])
def test_confidence_outside_the_unit_interval_is_rejected(bad: float) -> None:
    with pytest.raises(ValidationError):
        a_finding(confidence=bad)


@pytest.mark.parametrize("good", [0.0, 1.0])
def test_confidence_boundaries_are_accepted(good: float) -> None:
    assert a_finding(confidence=good).confidence == good


def test_confidence_defaults_to_one() -> None:
    finding = Finding(
        scanner_id="deps.sbom",
        view="shipped",
        asset_type="library",
        primitive="unknown",
        algorithm="OpenSSL",
        evidence=Evidence(occurrences=[an_occurrence(view="shipped")]),
    )
    assert finding.confidence == 1.0


# --------------------------------------------------------------------------
# every AssetType is expressible
# --------------------------------------------------------------------------

_ASSET_TYPE_EXAMPLES: dict[str, dict[str, Any]] = {
    "algorithm": {
        "primitive": "block-cipher",
        "algorithm": "AES",
        "params": {"key_size": 128, "mode": "CBC"},
        "usage": "encrypt",
    },
    "certificate": {
        "primitive": "signature",
        "algorithm": "ECDSA",
        "params": {"curve": "P-256", "valid_to": "2027-01-01T00:00:00Z"},
        "usage": "verify",
    },
    "protocol": {
        "primitive": "key-agreement",
        "algorithm": "TLS",
        "params": {"version": "1.3", "group": "x25519"},
        "usage": "key-exchange",
    },
    "key": {
        "primitive": "pke",
        "algorithm": "RSA",
        "params": {"key_size": 4096},
        "usage": "key-transport",
    },
    "library": {
        "primitive": "unknown",
        "algorithm": "OpenSSL",
        "params": {"version": "3.0.2"},
        "usage": "unknown",
    },
    "module": {
        "primitive": "drbg",
        "algorithm": "CTR_DRBG",
        "params": {"validation": "FIPS 140-3"},
        "usage": "unknown",
    },
    "service": {
        "primitive": "hash",
        "algorithm": "SHA-1",
        "params": {"endpoint": "auth.internal:443"},
        "usage": "hash",
    },
}


@pytest.mark.parametrize("asset_type", typing.get_args(AssetType))
def test_a_valid_finding_exists_for_every_asset_type(asset_type: str) -> None:
    example = _ASSET_TYPE_EXAMPLES[asset_type]

    finding = a_finding(asset_type=asset_type, **example)

    assert finding.asset_type == asset_type
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_every_asset_type_literal_has_an_example() -> None:
    # Guards the test above: a new AssetType must come with a worked example.
    assert set(typing.get_args(AssetType)) == set(_ASSET_TYPE_EXAMPLES)


# --------------------------------------------------------------------------
# immutability
# --------------------------------------------------------------------------


def test_finding_is_immutable() -> None:
    finding = a_finding()

    with pytest.raises(ValidationError):
        finding.algorithm = "AES"


def test_occurrence_and_evidence_are_immutable() -> None:
    occurrence = an_occurrence()
    evidence = Evidence(occurrences=[occurrence])

    with pytest.raises(ValidationError):
        occurrence.locator = "elsewhere:1"
    with pytest.raises(ValidationError):
        evidence.occurrences = []


# --------------------------------------------------------------------------
# closed vocabularies
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("view", "inferred"),
        ("asset_type", "keypair"),
        ("primitive", "asymmetric"),
        ("usage", "sealing"),
    ],
)
def test_unknown_vocabulary_values_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        a_finding(**{field: value})


def test_unknown_fields_are_rejected() -> None:
    # Scanner output is untrusted input; a typo must not slip through into raw.
    with pytest.raises(ValidationError):
        a_finding(algorithim="RSA")


def test_vocabularies_are_the_agreed_sets() -> None:
    assert typing.get_args(View) == ("declared", "shipped", "observed")
    assert typing.get_args(AssetType) == (
        "algorithm",
        "certificate",
        "protocol",
        "key",
        "library",
        "module",
        "service",
    )
    assert typing.get_args(Primitive) == (
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
    )
    assert typing.get_args(Usage) == (
        "sign",
        "verify",
        "key-exchange",
        "key-transport",
        "encrypt",
        "decrypt",
        "hash",
        "kdf",
        "unknown",
    )
