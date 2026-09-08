"""Tests for the CycloneDX 1.6 CBOM normaliser.

The normaliser is fed hand-built Findings only -- no scanner is involved. What
is pinned here is the contract downstream slices depend on: the output really
validates against the official CycloneDX 1.6 schema, identical artefacts merge
instead of multiplying, nothing ECDAT-specific escapes the standard
`properties` list, and the same input always produces the same bytes.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from core.cbom import build_cbom, dedup
from core.identity import finding_identity
from core.normalise import CbomValidationError, normalise, validate_cbom_json
from tests.factories import (
    finding,
    golden_findings,
    golden_target,
    occurrence,
    repo_target,
)

GOLDEN = Path(__file__).parent / "golden" / "quantumbank.cbom.json"


def components_of(cbom_json: str) -> list[dict[str, Any]]:
    return list(json.loads(cbom_json)["components"])


def only_component(cbom_json: str) -> dict[str, Any]:
    components = components_of(cbom_json)
    assert len(components) == 1, f"expected one component, got {len(components)}"
    return components[0]


def props(component: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"], []).append(p.get("value", ""))
    return out


# --------------------------------------------------------------------------
# schema validity
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_single_rsa_finding_produces_a_schema_valid_cbom() -> None:
    _, cbom_json = normalise([finding()], repo_target())

    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(cbom_json)

    assert errors is None, str(errors)
    document = json.loads(cbom_json)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"


@pytest.mark.validation
def test_every_asset_type_produces_a_schema_valid_cbom() -> None:
    _, cbom_json = normalise(golden_findings(), golden_target())

    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(cbom_json) is None


def test_validation_failure_raises_a_clear_error() -> None:
    with pytest.raises(CbomValidationError) as excinfo:
        # A CBOM missing bomFormat/specVersion is not a CycloneDX 1.6 document.
        validate_cbom_json('{"components": []}')

    assert "CycloneDX 1.6" in str(excinfo.value)


# --------------------------------------------------------------------------
# dedup / merge
# --------------------------------------------------------------------------


def test_same_artefact_in_two_views_merges_into_one_component() -> None:
    declared = finding()
    observed = finding(
        scanner_id="runtime.ebpf",
        view="observed",
        confidence=0.9,
        occurrences=[
            occurrence(
                view="observed",
                locator="services/auth/jwt.py:pid2231",
                detail="probe=RSA_sign nid=rsaEncryption",
                snippet=None,
            )
        ],
    )

    _, cbom_json = normalise([declared, observed], repo_target())

    component = only_component(cbom_json)
    assert len(component["evidence"]["occurrences"]) == 2
    assert sorted(props(component)["ecdat:view"]) == ["declared", "observed"]


def test_merged_component_keeps_every_occurrence_and_scanner() -> None:
    declared = finding()
    shipped = finding(
        scanner_id="binary.symbols",
        view="shipped",
        occurrences=[
            occurrence(
                view="shipped",
                locator="services/auth/jwt.py",
                detail="symbol=RSA_sign",
                snippet=None,
            )
        ],
    )

    _, cbom_json = normalise([declared, shipped], repo_target())

    occurrence_props = props(only_component(cbom_json))["ecdat:occurrence"]
    assert len(occurrence_props) == 2
    assert any("source.semgrep" in v for v in occurrence_props)
    assert any("binary.symbols" in v for v in occurrence_props)


def test_findings_differing_only_in_algorithm_stay_separate() -> None:
    rsa = finding()
    dsa = finding(algorithm="DSA")

    _, cbom_json = normalise([rsa, dsa], repo_target())

    assert len(components_of(cbom_json)) == 2


def test_dedup_identity_is_stable_under_merging() -> None:
    target = repo_target()
    declared = finding()
    observed = finding(
        view="observed",
        occurrences=[occurrence(view="observed", locator="services/auth/jwt.py:pid1")],
    )

    merged = dedup([declared, observed], target)

    assert len(merged) == 1
    identity, merged_finding = merged[0]
    assert identity == finding_identity(declared, target)
    # Re-hashing the merged finding must land on the same identity, otherwise
    # dedup would not be idempotent across scan runs.
    assert finding_identity(merged_finding, target) == identity
    assert len(merged_finding.evidence.occurrences) == 2


def test_merged_occurrences_are_sorted_by_view_then_locator() -> None:
    target = repo_target()
    late = finding(
        view="observed",
        occurrences=[occurrence(view="observed", locator="services/auth/jwt.py:pid9")],
    )
    early = finding(occurrences=[occurrence(locator="services/auth/jwt.py:1")])

    results = dedup([late, early], target)

    assert len(results) == 1
    merged = results[0][1]
    assert [(o.view, o.locator) for o in merged.evidence.occurrences] == [
        ("declared", "services/auth/jwt.py:1"),
        ("observed", "services/auth/jwt.py:pid9"),
    ]


def test_identical_occurrences_are_not_duplicated() -> None:
    target = repo_target()
    a = finding()
    b = finding(scanner_id="source.treesitter")

    results = dedup([a, b], target)

    assert len(results) == 1
    assert len(results[0][1].evidence.occurrences) == 1


# --------------------------------------------------------------------------
# cryptoProperties mapping
# --------------------------------------------------------------------------


def test_rsa_signature_maps_to_signature_primitive_at_quantum_level_zero() -> None:
    _, cbom_json = normalise([finding()], repo_target())

    crypto = only_component(cbom_json)["cryptoProperties"]
    algorithm = crypto["algorithmProperties"]
    assert crypto["assetType"] == "algorithm"
    assert algorithm["primitive"] == "signature"
    assert algorithm["nistQuantumSecurityLevel"] == 0
    assert algorithm["parameterSetIdentifier"] == "2048"
    assert algorithm["cryptoFunctions"] == ["sign"]


def test_aes_256_maps_to_block_cipher_with_its_security_levels() -> None:
    aes = finding(
        primitive="block-cipher",
        algorithm="AES",
        params={"key_size": 256, "mode": "GCM"},
        usage="encrypt",
    )

    _, cbom_json = normalise([aes], repo_target())

    algorithm = only_component(cbom_json)["cryptoProperties"]["algorithmProperties"]
    assert algorithm["primitive"] == "block-cipher"
    assert algorithm["parameterSetIdentifier"] == "256"
    assert algorithm["mode"] == "gcm"
    # AES-256 *defines* NIST PQC category 5, and its classical strength is the
    # key length. Both are structural properties of the algorithm, not scores.
    assert algorithm["classicalSecurityLevel"] == 256
    assert algorithm["nistQuantumSecurityLevel"] == 5


@pytest.mark.parametrize(
    ("algorithm", "key_size", "expected_nist"),
    [("AES", 128, 1), ("AES", 192, 3), ("AES", 256, 5), ("SHA-256", None, 2)],
)
def test_structural_nist_categories(
    algorithm: str, key_size: int | None, expected_nist: int
) -> None:
    params = {"key_size": key_size} if key_size else {}
    primitive = "block-cipher" if algorithm == "AES" else "hash"
    f = finding(algorithm=algorithm, primitive=primitive, params=params, usage="hash")

    _, cbom_json = normalise([f], repo_target())

    algo_props = only_component(cbom_json)["cryptoProperties"]["algorithmProperties"]
    assert algo_props["nistQuantumSecurityLevel"] == expected_nist


def test_unknown_algorithms_get_no_invented_security_level() -> None:
    f = finding(algorithm="Blowfish", primitive="block-cipher", params={"key_size": 64})

    _, cbom_json = normalise([f], repo_target())

    algo_props = only_component(cbom_json)["cryptoProperties"]["algorithmProperties"]
    assert "nistQuantumSecurityLevel" not in algo_props
    assert "classicalSecurityLevel" not in algo_props


def test_certificate_maps_to_certificate_properties() -> None:
    cert = next(f for f in golden_findings() if f.asset_type == "certificate")

    _, cbom_json = normalise([cert], golden_target())

    crypto = only_component(cbom_json)["cryptoProperties"]
    assert crypto["assetType"] == "certificate"
    cert_props = crypto["certificateProperties"]
    assert cert_props["subjectName"] == "CN=api.quantumbank.in"
    assert cert_props["issuerName"] == "CN=QuantumBank Internal CA"
    assert cert_props["notValidAfter"].startswith("2027-03-01")
    assert cert_props["certificateFormat"] == "X.509"


def test_protocol_maps_to_protocol_properties() -> None:
    tls = next(f for f in golden_findings() if f.asset_type == "protocol")

    _, cbom_json = normalise([tls], golden_target())

    crypto = only_component(cbom_json)["cryptoProperties"]
    assert crypto["assetType"] == "protocol"
    assert crypto["protocolProperties"]["type"] == "tls"
    assert crypto["protocolProperties"]["version"] == "1.2"
    assert crypto["protocolProperties"]["cipherSuites"] == [
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
    ]


def test_key_maps_to_related_crypto_material_without_any_key_value() -> None:
    key = next(f for f in golden_findings() if f.asset_type == "key")

    _, cbom_json = normalise([key], golden_target())

    crypto = only_component(cbom_json)["cryptoProperties"]
    assert crypto["assetType"] == "related-crypto-material"
    material = crypto["relatedCryptoMaterialProperties"]
    assert material["type"] == "private-key"
    assert material["size"] == 4096
    # No secret key material is ever stored.
    assert "value" not in material


def test_a_library_is_a_library_component_not_a_crypto_asset() -> None:
    lib = next(f for f in golden_findings() if f.asset_type == "library")

    _, cbom_json = normalise([lib], golden_target())

    component = only_component(cbom_json)
    assert component["type"] == "library"
    assert "cryptoProperties" not in component
    assert props(component)["ecdat:asset_type"] == ["library"]


# --------------------------------------------------------------------------
# ecdat data lives only in standard properties
# --------------------------------------------------------------------------


def test_ecdat_facts_are_carried_as_component_properties() -> None:
    _, cbom_json = normalise([finding()], repo_target())

    component = only_component(cbom_json)
    p = props(component)
    assert p["ecdat:usage"] == ["sign"]
    assert p["ecdat:configurable"] == ["false"]
    assert p["ecdat:confidence"] == ["1.0"]
    # The property is a self-contained record of the sighting, so it keeps the
    # raw locator (line included); only the *identity* strips the position.
    assert p["ecdat:occurrence"] == [
        "declared|services/auth/jwt.py:42|source.semgrep|rule=py-jwt-rs256@1.3"
    ]


def test_no_ecdat_key_appears_outside_the_properties_list() -> None:
    _, cbom_json = normalise(golden_findings(), golden_target())
    document = json.loads(cbom_json)

    for component in document["components"]:
        stripped = {k: v for k, v in component.items() if k != "properties"}
        assert "ecdat" not in json.dumps(stripped)
    assert all(
        p["name"].startswith("ecdat:")
        for component in document["components"]
        for p in component.get("properties", [])
    )


def test_merged_confidence_is_the_most_confident_observation() -> None:
    low = finding(confidence=0.4)
    high = finding(scanner_id="source.treesitter", confidence=0.9)

    _, cbom_json = normalise([low, high], repo_target())

    assert props(only_component(cbom_json))["ecdat:confidence"] == ["0.9"]


def test_no_risk_score_or_deadline_is_written_by_the_normaliser() -> None:
    _, cbom_json = normalise(golden_findings(), golden_target())

    lowered = cbom_json.lower()
    for forbidden in ("mosca", "risk", "deadline", "severity", "score"):
        assert forbidden not in lowered


# --------------------------------------------------------------------------
# determinism
# --------------------------------------------------------------------------


def test_normalising_twice_produces_identical_bytes() -> None:
    findings = golden_findings()

    _, first = normalise(findings, golden_target())
    _, second = normalise(golden_findings(), golden_target())

    assert first == second


def test_input_order_does_not_change_the_output_bytes() -> None:
    _, expected = normalise(golden_findings(), golden_target())
    rng = random.Random(20260908)

    for _ in range(5):
        shuffled = golden_findings()
        rng.shuffle(shuffled)
        _, actual = normalise(shuffled, golden_target())
        assert actual == expected


@pytest.mark.validation
def test_output_matches_the_committed_golden_cbom() -> None:
    _, cbom_json = normalise(golden_findings(), golden_target())

    assert cbom_json == GOLDEN.read_text(encoding="utf-8"), (
        "CBOM output drifted from tests/golden/quantumbank.cbom.json; "
        "if the change is intended, regenerate it with `make golden`"
    )
    assert (
        JsonStrictValidator(SchemaVersion.V1_6).validate_str(
            GOLDEN.read_text(encoding="utf-8")
        )
        is None
    )


def test_serial_number_is_derived_from_content_not_random() -> None:
    _, first = normalise(golden_findings(), golden_target())
    _, other = normalise([finding()], repo_target())

    assert json.loads(first)["serialNumber"] != json.loads(other)["serialNumber"]
    assert json.loads(first)["serialNumber"].startswith("urn:uuid:")


def test_build_cbom_returns_a_bom_with_one_component_per_identity() -> None:
    bom = build_cbom(golden_findings(), golden_target())

    refs = [c.bom_ref.value for c in bom.components]
    assert len(refs) == len(set(refs))
    assert len(refs) == len(dedup(golden_findings(), golden_target()))
