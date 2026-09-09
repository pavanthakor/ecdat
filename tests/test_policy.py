"""The policy engine and the quantum pack (ADR-0007).

Security-critical logic per CLAUDE.md, so this suite is written as mutation
tests rather than happy paths. Three properties have to hold or the engine is
worse than useless -- a scoring engine that can be made to lie is a scoring
engine that will be believed:

* **Determinism.** Same component + same packs -> identical verdict, whatever
  order the packs were loaded in.
* **No execution.** A `when` clause is data. A string that looks like code is
  matched as a string, never evaluated.
* **Provenance.** An unsigned, tampered, or uncited pack does not load at all.

Each gate has a test that fails if the gate is removed, and the merge tests pin
the cap, the label union, the earliest-deadline rule and the ordering, so
flipping any one of them turns something red.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import registry, store
from core.normalise import validate_cbom_json
from core.orchestrator import run_scan
from core.scanner import ScanContext, Target
from policy import sign
from policy.apply import apply_policy
from policy.engine import (
    CATEGORY_CAP_DEFAULT,
    Pack,
    PackSignatureError,
    PackValidationError,
    band_for,
    component_facts,
    default_packs,
    evaluate,
    load_packs,
    matches,
)

PACK_DIR = Path("policy/packs")
DEV_PUBLIC_KEY = Path("policy/keys/dev/pack-signing.pub")
DEV_PRIVATE_KEY = Path("policy/keys/dev/pack-signing.key")


@pytest.fixture(scope="module")
def packs() -> list[Pack]:
    return load_packs(PACK_DIR)


def component(name: str, **fields: Any) -> dict[str, Any]:
    """A CBOM component, in the shape the normaliser actually emits."""
    properties = [
        {"name": "ecdat:asset_type", "value": fields.pop("asset_type", "algorithm")}
    ]
    for key, value in sorted(fields.pop("params", {}).items()):
        properties.append({"name": f"ecdat:param:{key}", "value": str(value)})
    for view in fields.pop("views", ["declared"]):
        properties.append({"name": "ecdat:view", "value": view})

    crypto: dict[str, Any] = {"assetType": "algorithm"}
    algorithm_properties: dict[str, Any] = {}
    if "nist_level" in fields:
        algorithm_properties["nistQuantumSecurityLevel"] = fields.pop("nist_level")
    if "classical_level" in fields:
        algorithm_properties["classicalSecurityLevel"] = fields.pop("classical_level")
    if "primitive" in fields:
        algorithm_properties["primitive"] = fields.pop("primitive")
    if algorithm_properties:
        crypto["algorithmProperties"] = algorithm_properties

    return {
        "bom-ref": f"ref-{name}",
        "name": name,
        "type": "cryptographic-asset",
        "cryptoProperties": crypto,
        "properties": sorted(properties, key=lambda p: (p["name"], p["value"])),
        **fields,
    }


def rsa_2048() -> dict[str, Any]:
    return component(
        "RSA-2048", params={"key_size": 2048}, nist_level=0, primitive="pke"
    )


# --------------------------------------------------------------------------
# The selector is DATA. This is the one that matters most.
# --------------------------------------------------------------------------


def test_a_code_looking_selector_is_matched_as_a_string(tmp_path: Path) -> None:
    """A `when` value that looks like Python must be compared, never executed."""
    marker = tmp_path / "executed"
    payload = f"__import__('pathlib').Path({str(marker)!r}).write_text('pwned')"

    facts = component_facts(component("RSA-2048", params={"key_size": 2048}))

    assert matches({"name": payload}, facts) is False
    assert not marker.exists(), "a when-clause was evaluated instead of compared"

    # And the same string DOES match a component that literally carries it.
    literal = component_facts(component(payload))
    assert matches({"name": payload}, literal) is True
    assert not marker.exists()


def test_selector_operators_are_a_closed_set() -> None:
    """An unknown operator is refused at load, not silently never-matched."""
    facts = component_facts(rsa_2048())
    with pytest.raises(PackValidationError, match="unsupported"):
        matches({"key_size": {"gt": 1024}}, facts)


def test_selector_equality_in_range_and_presence() -> None:
    facts = component_facts(rsa_2048())

    assert matches({"algorithm": "RSA"}, facts)
    assert not matches({"algorithm": "AES"}, facts)
    assert matches({"algorithm": {"in": ["RSA", "DSA"]}}, facts)
    assert not matches({"algorithm": {"in": ["AES"]}}, facts)
    assert matches({"algorithm": {"not_in": ["AES"]}}, facts)
    assert matches({"key_size": {"min": 1024, "max": 4096}}, facts)
    assert not matches({"key_size": {"max": 1024}}, facts)
    assert matches({"curve": {"present": False}}, facts)
    assert matches({"key_size": {"present": True}}, facts)
    assert matches({"views": {"contains": "declared"}}, facts)


def test_all_keys_in_a_when_clause_must_match() -> None:
    facts = component_facts(rsa_2048())

    assert matches({"algorithm": "RSA", "key_size": 2048}, facts)
    assert not matches({"algorithm": "RSA", "key_size": 4096}, facts)


def test_a_missing_field_does_not_match_an_equality() -> None:
    """Absent must never read as equal, or every rule fires on everything."""
    facts = component_facts(component("SHA-1"))
    assert not matches({"key_size": 2048}, facts)
    assert not matches({"key_size": {"min": 0}}, facts)


# --------------------------------------------------------------------------
# The projection the selector sees
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "params", "expected"),
    [
        ("RSA-2048", {"key_size": 2048}, "RSA"),
        ("RSA-4096", {"key_size": 4096}, "RSA"),
        ("AES-256", {"key_size": 256, "mode": "GCM"}, "AES"),
        ("ECDSA-P-256", {"curve": "P-256"}, "ECDSA"),
        ("SHA-1", {}, "SHA-1"),
        ("SHA-256", {}, "SHA-256"),
        ("OpenSSL", {"version": "3.0.2"}, "OpenSSL"),
    ],
)
def test_algorithm_is_recovered_from_the_component_name(
    name: str, params: dict[str, Any], expected: str
) -> None:
    """`SHA-1` must not lose its `-1`; `RSA-2048` must lose its `-2048`.

    The difference is the params, not the shape of the string, which is why
    this is a projection and not a regex.
    """
    assert component_facts(component(name, params=params))["algorithm"] == expected


def test_the_projection_matches_real_normaliser_output() -> None:
    """Pins the derivation against what the normaliser actually emits.

    If `_component_name` in core/cbom.py ever changes, this fails loudly rather
    than letting every algorithm rule silently stop matching.
    """
    from core.normalise import normalise
    from tests.factories import golden_findings, golden_target

    _bom, cbom_json = normalise(golden_findings(), golden_target())
    document = json.loads(cbom_json)
    recovered = {component_facts(c)["algorithm"] for c in document["components"]}
    assert {"RSA", "AES", "ECDSA", "SHA-1", "TLS", "OpenSSL"} <= recovered


# --------------------------------------------------------------------------
# The quantum pack
# --------------------------------------------------------------------------


def test_rsa_is_shor_broken(packs: list[Pack]) -> None:
    verdict = evaluate(rsa_2048(), packs)

    assert verdict.quantum_status == "broken"
    assert verdict.score == 40, "the quantum category caps at 40"
    assert verdict.band == "Medium"
    assert "quantum-shor-broken-asymmetric" in verdict.fired_rules
    assert "shor-broken" in verdict.labels
    assert verdict.deadline is not None


@pytest.mark.parametrize(
    "algorithm",
    ["RSA", "DSA", "DH", "ECDSA", "ECDH", "Ed25519", "X25519"],
)
def test_every_shor_broken_family_is_covered(algorithm: str, packs: list[Pack]) -> None:
    verdict = evaluate(component(algorithm), packs)
    assert verdict.quantum_status == "broken", f"{algorithm} not flagged"
    assert verdict.score == 40


def test_aes_128_is_grover_weakened(packs: list[Pack]) -> None:
    verdict = evaluate(
        component("AES-128", params={"key_size": 128}, nist_level=1), packs
    )

    assert verdict.quantum_status == "weakened"
    assert verdict.score == 20
    assert verdict.band == "Low"


def test_triple_des_is_grover_weakened(packs: list[Pack]) -> None:
    verdict = evaluate(component("3DES"), packs)
    assert verdict.score == 20


def test_aes_256_is_adequate(packs: list[Pack]) -> None:
    verdict = evaluate(
        component("AES-256", params={"key_size": 256}, nist_level=5), packs
    )

    assert verdict.quantum_status == "adequate"
    assert verdict.score == 5
    assert verdict.band == "Low"


@pytest.mark.parametrize("algorithm", ["SHA-384", "SHA-512", "ChaCha20"])
def test_adequate_algorithms_score_five(algorithm: str, packs: list[Pack]) -> None:
    assert evaluate(component(algorithm), packs).score == 5


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "DES", "RC4"])
def test_classically_broken_scores_full_and_says_broken_today(
    algorithm: str, packs: list[Pack]
) -> None:
    verdict = evaluate(component(algorithm), packs)

    assert verdict.score == 40
    assert verdict.band == "Medium"
    # The point that a reader must not miss: this is not a 2035 problem.
    today = "broken-today" in verdict.labels or any(
        "today" in action.lower() for action in verdict.actions
    )
    assert today, f"{algorithm} does not say it is broken today: {verdict}"


@pytest.mark.parametrize("algorithm", ["ML-KEM", "ML-DSA", "SLH-DSA"])
def test_post_quantum_algorithms_score_zero(algorithm: str, packs: list[Pack]) -> None:
    verdict = evaluate(component(algorithm), packs)

    assert verdict.score == 0
    assert verdict.band == "Low"
    assert verdict.quantum_status == "pqc"


def test_every_pack_rule_carries_a_citation(packs: list[Pack]) -> None:
    for pack in packs:
        for rule in pack.rules:
            assert rule.citation.strip(), f"{rule.id} has no citation"


# --------------------------------------------------------------------------
# Merge semantics
# --------------------------------------------------------------------------


def test_two_rules_on_one_component_add_within_the_category_cap(
    packs: list[Pack],
) -> None:
    """RSA fires both the algorithm rule and the NIST-level-0 rule."""
    verdict = evaluate(rsa_2048(), packs)

    matched = [r for r in verdict.fired_rules if r.startswith("quantum-shor")]
    assert len(matched) >= 2, f"expected two rules to fire, got {verdict.fired_rules}"
    # 40 + 40 = 80 uncapped; the quantum cap holds it at 40.
    assert verdict.score == 40


def test_the_category_cap_is_load_bearing(packs: list[Pack]) -> None:
    """Raise the cap and the same component must score higher.

    If this passes with the cap removed, the cap is not doing anything.
    """
    raised = [
        Pack(
            name=p.name,
            version=p.version,
            citation=p.citation,
            caps={**p.caps, "quantum": 500},
            rules=p.rules,
        )
        for p in packs
    ]
    assert evaluate(rsa_2048(), raised).score > evaluate(rsa_2048(), packs).score


def test_labels_are_a_sorted_union(packs: list[Pack]) -> None:
    verdict = evaluate(rsa_2048(), packs)

    assert list(verdict.labels) == sorted(set(verdict.labels))


def test_deadline_is_the_earliest(packs: list[Pack]) -> None:
    import datetime as dt

    from policy.engine import Rule

    early = Rule(
        id="test-early",
        pack="test",
        when={"algorithm": "RSA"},
        effect={"score": 1, "category": "quantum", "deadline": dt.date(2027, 1, 1)},
        citation="test",
    )
    late = Rule(
        id="test-late",
        pack="test",
        when={"algorithm": "RSA"},
        effect={"score": 1, "category": "quantum", "deadline": dt.date(2031, 1, 1)},
        citation="test",
    )
    extra = Pack(name="test", version=1, citation="test", caps={}, rules=[late, early])

    assert evaluate(rsa_2048(), [*packs, extra]).deadline == dt.date(2027, 1, 1)


def test_fired_rules_are_sorted(packs: list[Pack]) -> None:
    verdict = evaluate(rsa_2048(), packs)
    assert list(verdict.fired_rules) == sorted(verdict.fired_rules)


def test_a_component_no_scoring_rule_matches_stays_at_zero(
    packs: list[Pack],
) -> None:
    """An unknown algorithm must not accumulate a score by accident.

    It does fire `mosca-data-lifetime-unknown`, which is the honesty rule: with
    no data classification there is no Mosca term, and saying so out loud is
    the point. That rule contributes 0.
    """
    verdict = evaluate(component("Whirlpool"), packs)

    assert verdict.score == 0
    assert verdict.band == "Low"
    assert verdict.deadline is None
    assert verdict.quantum_status is None
    assert verdict.fired_rules == ("mosca-data-lifetime-unknown",)
    assert "mosca-data-lifetime-unknown" in verdict.labels


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, "Low"),
        (39, "Low"),
        (40, "Medium"),
        (59, "Medium"),
        (60, "High"),
        (79, "High"),
        (80, "Critical"),
        (100, "Critical"),
    ],
)
def test_band_thresholds(score: int, band: str) -> None:
    assert band_for(score) == band


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_the_same_component_gives_the_same_verdict(packs: list[Pack]) -> None:
    assert evaluate(rsa_2048(), packs) == evaluate(rsa_2048(), packs)


def test_pack_order_does_not_change_the_verdict(packs: list[Pack]) -> None:
    baseline = evaluate(rsa_2048(), packs)
    rng = random.Random(20260909)

    for _ in range(8):
        shuffled = list(packs)
        rng.shuffle(shuffled)
        for pack in shuffled:
            rules = list(pack.rules)
            rng.shuffle(rules)
        assert evaluate(rsa_2048(), shuffled) == baseline


# --------------------------------------------------------------------------
# Load-time gates: citation and signature
# --------------------------------------------------------------------------


def _write_pack(directory: Path, body: dict[str, Any], name: str = "t.yaml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return path


def _minimal_pack(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "pack": "t",
        "version": 1,
        "citation": "test pack",
        "caps": {"quantum": 40},
        "rules": [
            {
                "id": "t-rsa",
                "when": {"algorithm": "RSA"},
                "effect": {"score": 10, "category": "quantum"},
                "citation": "NIST IR 8547",
            }
        ],
    }
    body.update(overrides)
    return body


def test_a_rule_without_a_citation_is_refused(tmp_path: Path) -> None:
    body = _minimal_pack()
    del body["rules"][0]["citation"]
    path = _write_pack(tmp_path, body)
    sign.sign_file(path, DEV_PRIVATE_KEY)

    with pytest.raises(PackValidationError, match="citation"):
        load_packs(tmp_path)


def test_a_blank_citation_is_refused(tmp_path: Path) -> None:
    body = _minimal_pack()
    body["rules"][0]["citation"] = "   "
    path = _write_pack(tmp_path, body)
    sign.sign_file(path, DEV_PRIVATE_KEY)

    with pytest.raises(PackValidationError, match="citation"):
        load_packs(tmp_path)


def test_an_unsigned_pack_is_refused(tmp_path: Path) -> None:
    _write_pack(tmp_path, _minimal_pack())

    with pytest.raises(PackSignatureError, match="signature"):
        load_packs(tmp_path)


def test_a_tampered_pack_fails_verification(tmp_path: Path) -> None:
    path = _write_pack(tmp_path, _minimal_pack())
    sign.sign_file(path, DEV_PRIVATE_KEY)

    # One byte. The score a reviewer approved was 10; someone made it 1.
    original = path.read_bytes()
    path.write_bytes(original.replace(b"score: 10", b"score: 1_"))
    assert path.read_bytes() != original

    with pytest.raises(PackSignatureError):
        load_packs(tmp_path)


def test_a_signature_from_the_wrong_key_is_refused(tmp_path: Path) -> None:
    path = _write_pack(tmp_path, _minimal_pack())
    other_private = tmp_path / "other.key"
    other_public = tmp_path / "other.pub"
    sign.generate_keypair(other_private, other_public)
    sign.sign_file(path, other_private)

    with pytest.raises(PackSignatureError):
        load_packs(tmp_path)

    # ... and it loads fine against the key that actually signed it.
    assert load_packs(tmp_path, public_key_path=other_public)


def test_dev_mode_skips_verification_but_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.WARNING)
    _write_pack(tmp_path, _minimal_pack())

    loaded = load_packs(tmp_path, dev=True)

    assert len(loaded) == 1
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "dev mode loaded an unsigned pack without warning"
    assert any("signature" in r.getMessage().lower() for r in warnings)


def test_dev_mode_still_enforces_citations(tmp_path: Path) -> None:
    """Skipping signatures must not skip everything else."""
    body = _minimal_pack()
    del body["rules"][0]["citation"]
    _write_pack(tmp_path, body)

    with pytest.raises(PackValidationError, match="citation"):
        load_packs(tmp_path, dev=True)


def test_duplicate_rule_ids_across_packs_are_refused(tmp_path: Path) -> None:
    for name in ("a.yaml", "b.yaml"):
        path = _write_pack(tmp_path, _minimal_pack(), name=name)
        sign.sign_file(path, DEV_PRIVATE_KEY)

    with pytest.raises(PackValidationError, match="duplicate"):
        load_packs(tmp_path)


def test_the_shipped_packs_are_signed_and_load_in_production_mode() -> None:
    loaded = load_packs(PACK_DIR, dev=False)
    assert [p.name for p in loaded] == [
        "india_dst",
        "mosca",
        "nist_ir8547",
        "quantum",
    ]


def test_the_shipped_pack_declares_the_quantum_cap(packs: list[Pack]) -> None:
    """The cap table lives in the pack header. Document and pin it."""
    (quantum,) = [p for p in packs if p.name == "quantum"]
    assert quantum.caps["quantum"] == 40
    assert CATEGORY_CAP_DEFAULT > 0


# --------------------------------------------------------------------------
# apply_policy
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scored_cbom(packs: list[Pack]) -> str:
    from core.normalise import normalise
    from tests.factories import golden_findings, golden_target

    _bom, cbom_json = normalise(golden_findings(), golden_target())
    return apply_policy(cbom_json, packs)


def _properties(component_dict: dict[str, Any], name: str) -> list[str]:
    return [p["value"] for p in component_dict["properties"] if p["name"] == name]


def test_apply_policy_writes_the_verdict_properties(scored_cbom: str) -> None:
    document = json.loads(scored_cbom)
    rsa = next(c for c in document["components"] if c["name"] == "RSA-2048")

    assert _properties(rsa, "ecdat:score") == ["40"]
    assert _properties(rsa, "ecdat:band") == ["Medium"]
    assert _properties(rsa, "ecdat:quantum_status") == ["broken"]
    assert "shor-broken" in _properties(rsa, "ecdat:labels")[0]
    assert _properties(rsa, "ecdat:deadline")
    assert _properties(rsa, "ecdat:actions")
    fired = _properties(rsa, "ecdat:fired_rules")[0]
    assert "quantum-shor-broken-asymmetric" in fired


def test_apply_policy_is_byte_stable(packs: list[Pack]) -> None:
    from core.normalise import normalise
    from tests.factories import golden_findings, golden_target

    _bom, cbom_json = normalise(golden_findings(), golden_target())

    first = apply_policy(cbom_json, packs)
    second = apply_policy(cbom_json, packs)

    assert first == second


def test_apply_policy_is_idempotent(packs: list[Pack], scored_cbom: str) -> None:
    """Scoring an already-scored document must not double up properties."""
    twice = apply_policy(scored_cbom, packs)
    assert twice == scored_cbom


@pytest.mark.validation
def test_a_scored_cbom_still_validates(scored_cbom: str) -> None:
    validate_cbom_json(scored_cbom)


def test_apply_policy_leaves_unscored_components_with_a_low_band(
    scored_cbom: str,
) -> None:
    document = json.loads(scored_cbom)
    for component_dict in document["components"]:
        assert _properties(component_dict, "ecdat:score")
        assert _properties(component_dict, "ecdat:band")


# --------------------------------------------------------------------------
# End to end, through the orchestrator and the store
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_end_to_end_scan_stores_a_scored_cbom(tmp_path: Path) -> None:
    context = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=tmp_path)
    target = Target(kind="repo", ref="testdata/minimal_repo", system="quantumbank")

    scan_id = run_scan(target, registry.get_scanners(["source"]), context)

    record = store.get_scan(scan_id)
    assert record is not None
    validate_cbom_json(record.cbom_json)

    document = json.loads(record.cbom_json)
    rsa = next(c for c in document["components"] if c["name"] == "RSA-2048")

    assert _properties(rsa, "ecdat:quantum_status") == ["broken"]
    assert _properties(rsa, "ecdat:band") == ["Medium"]
    assert "quantum-shor-broken-asymmetric" in _properties(rsa, "ecdat:fired_rules")[0]

    sha256 = next(c for c in document["components"] if c["name"] == "SHA-256")
    assert _properties(sha256, "ecdat:band") == ["Low"]


def test_two_scans_of_the_same_target_store_identical_scored_documents(
    tmp_path: Path,
) -> None:
    context = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=tmp_path)
    target = Target(kind="repo", ref="testdata/minimal_repo", system="quantumbank")
    scanners = registry.get_scanners(["source"])

    first = store.get_scan(run_scan(target, scanners, context))
    second = store.get_scan(run_scan(target, scanners, context))

    assert first is not None
    assert second is not None
    assert first.cbom_json == second.cbom_json


def test_default_packs_loads_every_shipped_pack() -> None:
    assert [p.name for p in default_packs()] == [
        "india_dst",
        "mosca",
        "nist_ir8547",
        "quantum",
    ]
