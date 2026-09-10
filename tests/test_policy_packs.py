"""Mosca, India DST and NIST IR 8547 packs, and the score inputs they need.

The headline property, and the reason this slice exists: **Criticality becomes
reachable by CONTEXT, not by tuning a number.** The same RSA-2048 is Critical
in a BFSI system holding personal data on the internet, and Medium in an
internal build holding public data. Nothing about the algorithm changed. If a
future edit makes Criticality reachable by raising a cap instead,
``test_the_same_algorithm_is_critical_or_medium_by_context`` is the test that
should have stopped it.

Security-critical per CLAUDE.md, so the merge and the honesty guarantees are
written as mutation tests: break earliest-deadline, flip a cap, or let Mosca
guess at an unknown data lifetime, and something here must go red.
"""

from __future__ import annotations

import datetime as dt
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
from policy.apply import DEFAULT_Z_YEARS, ScoreInputs, apply_policy
from policy.engine import (
    MOSCA_GAP_CEILING,
    PROVISIONAL_SUFFIX,
    Y_YEARS_BASE,
    Y_YEARS_HARDCODED_PENALTY,
    Pack,
    PackSignatureError,
    PackValidationError,
    load_packs,
    mosca_contribution,
    mosca_gap,
)

PACK_DIR = Path("policy/packs")
DEV_PRIVATE_KEY = Path("policy/keys/dev/pack-signing.key")

EXPECTED_PACKS = ["india_dst", "mosca", "nist_ir8547", "quantum"]
EXPECTED_CAPS = {"quantum": 40, "mosca": 30, "criticality": 20, "exposure": 10}


@pytest.fixture(scope="module")
def packs() -> list[Pack]:
    return load_packs(PACK_DIR)


# --------------------------------------------------------------------------
# Building a CBOM to score
# --------------------------------------------------------------------------


def rsa_component(*, configurable: bool = False) -> dict[str, Any]:
    """An RSA-2048 component exactly as the normaliser emits one."""
    return {
        "bom-ref": "ref-rsa",
        "name": "RSA-2048",
        "type": "cryptographic-asset",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "pke",
                "nistQuantumSecurityLevel": 0,
                "parameterSetIdentifier": "2048",
            },
        },
        "properties": [
            {"name": "ecdat:asset_type", "value": "algorithm"},
            {
                "name": "ecdat:configurable",
                "value": "true" if configurable else "false",
            },
            {"name": "ecdat:param:key_size", "value": "2048"},
            {"name": "ecdat:usage", "value": "unknown"},
            {"name": "ecdat:view", "value": "declared"},
        ],
    }


def cbom_with(*components: dict[str, Any]) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": list(components),
        }
    )


def score(
    packs: list[Pack], component: dict[str, Any], **inputs: Any
) -> dict[str, Any]:
    """Score one component and return its properties as a dict of lists."""
    scored = apply_policy(cbom_with(component), packs, inputs=ScoreInputs(**inputs))
    (result,) = json.loads(scored)["components"]
    collected: dict[str, Any] = {}
    for prop in result["properties"]:
        collected.setdefault(prop["name"], []).append(prop["value"])
    return collected


def one(properties: dict[str, Any], name: str) -> str:
    values = properties.get(name)
    assert values, f"{name} missing; have {sorted(properties)}"
    assert len(values) == 1, f"{name} appears {len(values)} times"
    return str(values[0])


# --------------------------------------------------------------------------
# THE HEADLINE: same algorithm, different context, different band
# --------------------------------------------------------------------------


def test_the_same_algorithm_is_critical_or_medium_by_context(
    packs: list[Pack],
) -> None:
    """Criticality must come from CONTEXT, never from tuning a score.

    If this ever passes only because a cap was raised, the point of the slice
    has been lost. The two calls differ in nothing but the target's context and
    whether the key size is hard-coded.

    **Rebased on VERIFIED facts only (ADR-0017).** This case used to be
    `Personal`, and reached Critical partly on the DST pack's 20 points of
    `criticality` -- a fact nobody had checked. With that demoted the same
    component scores 78/High (pinned by
    `test_the_personal_case_is_now_high_because_dst_demoted`). Criticality is
    still reachable, from quantum 40 + mosca 30 + exposure 10, which is what
    this now asserts: the band comes from three checked facts and no unchecked
    one.
    """
    exposed = score(
        packs,
        rsa_component(configurable=False),
        data_class="Sovereign",
        sector="bfsi",
        exposure="internet",
    )
    sheltered = score(
        packs,
        rsa_component(configurable=True),
        data_class="Public",
        sector="other",
        exposure="internal",
    )

    assert one(exposed, "ecdat:band") == "Critical"
    assert int(one(exposed, "ecdat:score")) >= 80
    assert one(exposed, "ecdat:deadline") == "2028-12-31"
    # ... and none of those 80 points came from an unverified fact.
    categories = dict(
        entry.split("=", 1) for entry in exposed.get("ecdat:category_score", [])
    )
    assert categories["criticality"] == "0"
    assert {"quantum", "mosca", "exposure"} <= set(categories)

    assert one(sheltered, "ecdat:band") == "Medium"
    assert 40 <= int(one(sheltered, "ecdat:score")) < 60

    # Same algorithm. Same key size. Same quantum verdict.
    assert one(exposed, "ecdat:quantum_status") == "broken"
    assert one(sheltered, "ecdat:quantum_status") == "broken"


def test_the_critical_case_fires_rules_from_all_four_packs(
    packs: list[Pack],
) -> None:
    exposed = score(
        packs,
        rsa_component(configurable=False),
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )
    fired = one(exposed, "ecdat:fired_rules").split(",")

    by_pack = {pack.name: [r.id for r in pack.rules if r.id in fired] for pack in packs}
    for name in EXPECTED_PACKS:
        assert by_pack[name], f"no rule from pack {name!r} fired; got {fired}"


# --------------------------------------------------------------------------
# Mosca arithmetic -- the one place arithmetic is allowed to live
# --------------------------------------------------------------------------


def test_mosca_gap_is_x_plus_y_minus_z() -> None:
    assert mosca_gap(25, 5, 11) == 19
    assert mosca_gap(0, 1, 11) == -10
    assert mosca_gap(50, 5, 11) == 44


def test_mosca_gap_on_unknown_data_lifetime_is_none_not_zero() -> None:
    """Unknown X must never be silently read as 0. That would score every
    unclassified system as safe."""
    assert mosca_gap(None, 5, 11) is None


def test_mosca_contribution_scales_to_the_cap() -> None:
    assert mosca_contribution(None, 30) == 0
    assert mosca_contribution(-10, 30) == 0
    assert mosca_contribution(0, 30) == 0
    assert mosca_contribution(MOSCA_GAP_CEILING, 30) == 30
    assert mosca_contribution(MOSCA_GAP_CEILING * 2, 30) == 30, "must not exceed cap"
    assert 0 < mosca_contribution(10, 30) < 30


def test_mosca_contribution_is_monotonic() -> None:
    values = [mosca_contribution(gap, 30) for gap in range(0, 30)]
    assert values == sorted(values)


def test_a_high_gap_produces_a_high_mosca_contribution(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component(), data_class="Personal", sector="other")
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    assert int(subtotals["mosca"]) >= 25


def test_a_zero_gap_produces_no_mosca_contribution(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component(), data_class="Public", sector="other")
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    assert int(subtotals["mosca"]) == 0


def test_unknown_data_lifetime_scores_zero_and_says_so(packs: list[Pack]) -> None:
    """The honesty case: no data_class means no guess, and it is labelled."""
    properties = score(packs, rsa_component(), sector="other")

    assert "ecdat:x_years" not in properties
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    assert int(subtotals.get("mosca", 0)) == 0
    assert "mosca-data-lifetime-unknown" in one(properties, "ecdat:labels")


def test_an_unrecognised_data_class_is_unknown_not_zero(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component(), data_class="not-a-real-class")

    assert "ecdat:x_years" not in properties
    assert "mosca-data-lifetime-unknown" in one(properties, "ecdat:labels")


@pytest.mark.parametrize(
    ("data_class", "x_years"),
    [
        ("Public", 0),
        ("Internal", 3),
        ("Confidential", 10),
        ("Personal", 25),
        ("Sovereign", 50),
    ],
)
def test_data_class_x_years(packs: list[Pack], data_class: str, x_years: int) -> None:
    properties = score(packs, rsa_component(), data_class=data_class)
    assert int(one(properties, "ecdat:x_years")) == x_years


def test_data_class_aliases_and_case_are_accepted(packs: list[Pack]) -> None:
    for spelling in ("personal", "PII", "Sensitive-Personal"):
        properties = score(packs, rsa_component(), data_class=spelling)
        assert int(one(properties, "ecdat:x_years")) == 25


# --------------------------------------------------------------------------
# The Z slider
# --------------------------------------------------------------------------


def test_the_crqc_horizon_changes_the_verdict(packs: list[Pack]) -> None:
    """The dashboard slider must actually move something."""

    def mosca_for(z: int) -> int:
        properties = score(
            packs,
            rsa_component(),
            data_class="Personal",
            sector="other",
            z_years=z,
        )
        subtotals = dict(
            entry.split("=") for entry in properties["ecdat:category_score"]
        )
        return int(subtotals["mosca"])

    near = mosca_for(8)
    far = mosca_for(15)

    assert near > far, "a nearer CRQC must make migration more urgent"
    assert mosca_for(DEFAULT_Z_YEARS) > 0


def test_the_default_crqc_horizon_is_eleven_years() -> None:
    assert DEFAULT_Z_YEARS == 11


# --------------------------------------------------------------------------
# The Y model, which is an estimate and must say so
# --------------------------------------------------------------------------


def test_hard_coded_crypto_takes_longer_to_migrate(packs: list[Pack]) -> None:
    hard = score(packs, rsa_component(configurable=False), data_class="Personal")
    soft = score(packs, rsa_component(configurable=True), data_class="Personal")

    assert int(one(hard, "ecdat:y_years")) > int(one(soft, "ecdat:y_years"))
    assert int(one(soft, "ecdat:y_years")) == Y_YEARS_BASE
    assert int(one(hard, "ecdat:y_years")) == Y_YEARS_BASE + Y_YEARS_HARDCODED_PENALTY


def test_y_years_is_labelled_an_estimate(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component(), data_class="Personal")
    basis = one(properties, "ecdat:y_years_basis")
    assert "estimate" in basis.lower()


def test_z_years_is_labelled_an_estimate(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component(), data_class="Personal")
    assert "estimate" in one(properties, "ecdat:z_years_basis").lower()


# --------------------------------------------------------------------------
# Score inputs land on the component before the packs run
# --------------------------------------------------------------------------


def test_score_inputs_are_written_onto_the_component(packs: list[Pack]) -> None:
    properties = score(
        packs,
        rsa_component(),
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
        z_years=11,
    )

    assert one(properties, "ecdat:data_class") == "Personal"
    assert one(properties, "ecdat:x_years") == "25"
    assert one(properties, "ecdat:y_years") == str(
        Y_YEARS_BASE + Y_YEARS_HARDCODED_PENALTY
    )
    assert one(properties, "ecdat:z_years") == "11"
    assert one(properties, "ecdat:sector") == "bfsi"
    assert one(properties, "ecdat:exposure") == "internet"


def test_defaults_are_other_and_unknown(packs: list[Pack]) -> None:
    properties = score(packs, rsa_component())
    assert one(properties, "ecdat:sector") == "other"
    assert one(properties, "ecdat:exposure") == "unknown"


# --------------------------------------------------------------------------
# The India DST pack
# --------------------------------------------------------------------------


@pytest.mark.parametrize("sector", ["defence", "power", "telecom", "bfsi"])
def test_critical_sectors_get_the_2028_cii_deadline(
    packs: list[Pack], sector: str
) -> None:
    properties = score(packs, rsa_component(), sector=sector, data_class="Public")

    assert one(properties, "ecdat:deadline") == "2028-12-31"
    assert "CII" in one(properties, "ecdat:labels")


def test_a_non_critical_sector_gets_only_the_2029_deadline(
    packs: list[Pack],
) -> None:
    properties = score(packs, rsa_component(), sector="other", data_class="Public")

    assert one(properties, "ecdat:deadline") == "2029-12-31"
    labels = one(properties, "ecdat:labels")
    assert "CII" not in labels
    assert "dst-full-adoption" in labels


def test_aes_128_gets_the_uplift_action(packs: list[Pack]) -> None:
    aes = {
        "bom-ref": "ref-aes",
        "name": "AES-128",
        "type": "cryptographic-asset",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "block-cipher",
                "nistQuantumSecurityLevel": 1,
            },
        },
        "properties": [
            {"name": "ecdat:asset_type", "value": "algorithm"},
            {"name": "ecdat:param:key_size", "value": "128"},
        ],
    }
    properties = score(packs, aes, sector="bfsi")

    assert "dst-aes-uplift" in one(properties, "ecdat:labels")
    assert any("AES-256" in action for action in properties["ecdat:actions"])


def test_a_software_asset_gets_an_assurance_label(packs: list[Pack]) -> None:
    library = {
        "bom-ref": "ref-lib",
        "name": "OpenSSL",
        "type": "library",
        "cryptoProperties": {"assetType": "library"},
        "properties": [
            {"name": "ecdat:asset_type", "value": "library"},
            {"name": "ecdat:param:version", "value": "3.0.2"},
        ],
    }
    properties = score(packs, library, sector="bfsi")
    assert "assurance:L2A" in one(properties, "ecdat:labels")


# --------------------------------------------------------------------------
# The NIST pack, and the earliest-deadline merge it exists to exercise
# --------------------------------------------------------------------------


def test_nist_deprecates_112_bit_asymmetric_in_2030(packs: list[Pack]) -> None:
    nist_only = [p for p in packs if p.name == "nist_ir8547"]
    properties = score(nist_only, rsa_component(), sector="other")

    assert one(properties, "ecdat:deadline") == "2030-01-01"
    assert "nist-disallowed-2035" in one(properties, "ecdat:labels")
    assert any("2035" in action for action in properties["ecdat:actions"])


def test_the_earliest_deadline_wins_across_packs(packs: list[Pack]) -> None:
    """DST 2028-12-31 must beat NIST 2030-01-01 and quantum 2035-01-01.

    Break the earliest-deadline merge and this is what goes red.
    """
    properties = score(packs, rsa_component(), sector="bfsi", data_class="Public")

    assert one(properties, "ecdat:deadline") == "2028-12-31"


def test_a_later_deadline_never_relaxes_an_earlier_one(packs: list[Pack]) -> None:
    from policy.engine import Rule

    relaxing = Pack(
        name="zzz_relax",
        version=1,
        citation="test",
        caps={},
        rules=[
            Rule(
                id="zzz-relax-everything",
                pack="zzz_relax",
                when={"algorithm": "RSA"},
                effect={
                    "score": 0,
                    "category": "criticality",
                    "deadline": dt.date(2099, 1, 1),
                },
                citation="test",
            )
        ],
    )
    properties_before = score(packs, rsa_component(), sector="bfsi")
    properties_after = score([*packs, relaxing], rsa_component(), sector="bfsi")

    assert one(properties_after, "ecdat:deadline") == one(
        properties_before, "ecdat:deadline"
    )


@pytest.mark.parametrize(
    ("exposure", "expected"),
    [("internet", 10), ("internal", 5), ("build", 2), ("unknown", 0)],
)
def test_exposure_contribution(packs: list[Pack], exposure: str, expected: int) -> None:
    properties = score(packs, rsa_component(), exposure=exposure, sector="other")
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    assert int(subtotals.get("exposure", 0)) == expected


# --------------------------------------------------------------------------
# Four-pack merge
# --------------------------------------------------------------------------


def test_all_four_categories_appear_in_the_category_score(
    packs: list[Pack],
) -> None:
    properties = score(
        packs,
        rsa_component(),
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])

    assert set(subtotals) == set(EXPECTED_CAPS)
    for category, value in subtotals.items():
        assert int(value) <= EXPECTED_CAPS[category], f"{category} exceeded its cap"


def test_each_pack_declares_the_expected_cap(packs: list[Pack]) -> None:
    declared: dict[str, int] = {}
    for pack in packs:
        for category, cap in pack.caps.items():
            declared[category] = min(declared.get(category, cap), cap)
    assert declared == EXPECTED_CAPS


def test_scores_add_within_a_category_and_stop_at_the_cap(
    packs: list[Pack],
) -> None:
    properties = score(
        packs,
        rsa_component(),
        data_class="Sovereign",
        sector="defence",
        exposure="internet",
    )
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    # Sovereign X=50 gives a gap far past the ceiling; mosca must stop at 30.
    assert int(subtotals["mosca"]) == 30
    # Two quantum rules at 40 each, capped back to 40.
    assert int(subtotals["quantum"]) == 40


def test_labels_are_a_sorted_union_across_four_packs(packs: list[Pack]) -> None:
    properties = score(
        packs,
        rsa_component(),
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )
    labels = one(properties, "ecdat:labels").split(",")

    assert labels == sorted(set(labels))
    # Verified facts label plainly.
    assert {"shor-broken", "nist-disallowed-2035"} <= set(labels)
    # The DST facts are unverified (ADR-0017), so their labels are DEMOTED --
    # still present, and carrying the caveat with them.
    assert "CII" not in labels
    assert f"CII{PROVISIONAL_SUFFIX}" in labels


def test_pack_order_does_not_change_the_verdict(packs: list[Pack]) -> None:
    kwargs: dict[str, Any] = {
        "data_class": "Personal",
        "sector": "bfsi",
        "exposure": "internet",
    }
    baseline = score(packs, rsa_component(), **kwargs)
    rng = random.Random(20260909)

    for _ in range(8):
        shuffled = list(packs)
        rng.shuffle(shuffled)
        assert score(shuffled, rsa_component(), **kwargs) == baseline


def test_apply_policy_is_byte_stable_with_four_packs(packs: list[Pack]) -> None:
    document = cbom_with(rsa_component())
    inputs = ScoreInputs(data_class="Personal", sector="bfsi", exposure="internet")

    first = apply_policy(document, packs, inputs=inputs)
    second = apply_policy(document, packs, inputs=inputs)

    assert first == second


def test_apply_policy_is_idempotent_with_four_packs(packs: list[Pack]) -> None:
    """Re-scoring must replace the inputs and the verdict, not duplicate them."""
    inputs = ScoreInputs(data_class="Personal", sector="bfsi", exposure="internet")
    once = apply_policy(cbom_with(rsa_component()), packs, inputs=inputs)
    twice = apply_policy(once, packs, inputs=inputs)

    assert twice == once


# --------------------------------------------------------------------------
# Mutation-style negatives on the caps
# --------------------------------------------------------------------------


def test_raising_the_mosca_cap_changes_the_score(packs: list[Pack]) -> None:
    """If flipping the cap changes nothing, the cap is not doing anything."""
    raised = [
        Pack(
            name=p.name,
            version=p.version,
            citation=p.citation,
            caps={**p.caps, "mosca": 300} if "mosca" in p.caps else p.caps,
            rules=p.rules,
        )
        for p in packs
    ]
    baseline = score(packs, rsa_component(), data_class="Sovereign")
    lifted = score(raised, rsa_component(), data_class="Sovereign")

    assert int(one(lifted, "ecdat:score")) > int(one(baseline, "ecdat:score"))


def test_a_pack_cannot_widen_another_packs_cap(packs: list[Pack]) -> None:
    """Narrowest cap wins (ADR-0007) -- still true with four packs."""
    from policy.engine import Rule

    greedy = Pack(
        name="zzz_greedy",
        version=1,
        citation="test",
        caps={"quantum": 500},
        rules=[
            Rule(
                id="zzz-greedy",
                pack="zzz_greedy",
                when={"algorithm": "RSA"},
                effect={"score": 400, "category": "quantum"},
                citation="test",
            )
        ],
    )
    properties = score([*packs, greedy], rsa_component(), sector="other")
    subtotals = dict(entry.split("=") for entry in properties["ecdat:category_score"])
    assert int(subtotals["quantum"]) == 40


# --------------------------------------------------------------------------
# The new packs are signed and cited
# --------------------------------------------------------------------------


def test_all_four_packs_load_signed(packs: list[Pack]) -> None:
    assert sorted(p.name for p in packs) == EXPECTED_PACKS


def test_every_rule_in_every_pack_cites_a_source(packs: list[Pack]) -> None:
    for pack in packs:
        for rule in pack.rules:
            assert rule.citation.strip(), f"{pack.name}:{rule.id} has no citation"


def test_a_tampered_mosca_pack_is_refused(tmp_path: Path) -> None:
    for name in ("mosca.yaml", "quantum.yaml"):
        (tmp_path / name).write_bytes((PACK_DIR / name).read_bytes())
        (tmp_path / f"{name}.sig").write_bytes((PACK_DIR / f"{name}.sig").read_bytes())

    assert load_packs(tmp_path)

    target = tmp_path / "mosca.yaml"
    original = target.read_bytes()
    target.write_bytes(original.replace(b"cap", b"CAP", 1))
    assert target.read_bytes() != original

    with pytest.raises(PackSignatureError):
        load_packs(tmp_path)


def test_a_new_pack_rule_without_a_citation_is_refused(tmp_path: Path) -> None:
    body = yaml.safe_load((PACK_DIR / "mosca.yaml").read_text(encoding="utf-8"))
    del body["rules"][0]["citation"]
    path = tmp_path / "mosca.yaml"
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    sign.sign_file(path, DEV_PRIVATE_KEY)

    with pytest.raises(PackValidationError, match="citation"):
        load_packs(tmp_path)


def test_an_unknown_effect_type_is_refused(tmp_path: Path) -> None:
    """The effect-type vocabulary is closed, like the selector vocabulary."""
    body = {
        "pack": "t",
        "version": 1,
        "citation": "test",
        "caps": {"mosca": 30},
        "rules": [
            {
                "id": "t-bad",
                "when": {"algorithm": "RSA"},
                "effect": {"type": "exec_shell", "category": "mosca"},
                "citation": "test",
            }
        ],
    }
    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    sign.sign_file(path, DEV_PRIVATE_KEY)

    with pytest.raises(PackValidationError, match="type"):
        load_packs(tmp_path)


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_end_to_end_a_bfsi_sovereign_internet_scan_is_critical(
    tmp_path: Path,
) -> None:
    """Critical end to end, on verified facts alone.

    Was `Personal` before ADR-0017, when the unverified DST rule supplied 20 of
    the 98 points. `Sovereign` reaches Critical on quantum + mosca + exposure,
    all checked.
    """
    context = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=tmp_path)
    target = Target(
        kind="repo",
        ref="testdata/minimal_repo",
        system="quantumbank",
        data_class="Sovereign",
        sector="bfsi",
        exposure="internet",
    )

    scan_id = run_scan(target, registry.get_scanners(["source"]), context)

    record = store.get_scan(scan_id)
    assert record is not None
    validate_cbom_json(record.cbom_json)

    document = json.loads(record.cbom_json)
    rsa = next(c for c in document["components"] if c["name"] == "RSA-2048")
    values: dict[str, list[str]] = {}
    for prop in rsa["properties"]:
        values.setdefault(prop["name"], []).append(prop["value"])

    assert one(values, "ecdat:band") == "Critical"
    assert one(values, "ecdat:deadline") == "2028-12-31"
    assert one(values, "ecdat:x_years") == "50"
    assert one(values, "ecdat:sector") == "bfsi"
    # The deadline is displayed and flagged: it comes from a DST rule nobody
    # has checked, so it informs and does not score (ADR-0017).
    assert one(values, "ecdat:deadline_provisional") == "true"

    fired = one(values, "ecdat:fired_rules")
    assert "quantum-shor-broken-asymmetric" in fired
    assert "mosca-harvest-now-decrypt-later" in fired
    assert "dst-cii-priority-migration" in fired
    assert "nist-112-bit-asymmetric-deprecated" in fired


def test_the_personal_case_is_now_high_because_dst_demoted(
    packs: list[Pack],
) -> None:
    """WHAT THE DEMOTION COST, recorded rather than quietly absorbed.

    Before ADR-0017 this exact component scored 98/Critical: quantum 40 +
    mosca 28 + exposure 10 + **criticality 20 from a DST deadline nobody had
    checked**. It is now 78/High. That is a real change to the headline demo
    number, and it is the correct one -- 20% of a Critical verdict was resting
    on an unverified fact.

    Flipping `dst-cii-priority-migration` to `verified: true` with a real
    source restores the 98. That is the point of the mechanism: the fact is
    one confirmation away, not deleted.
    """
    exposed = score(
        packs,
        rsa_component(configurable=False),
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )

    assert one(exposed, "ecdat:band") == "High"
    assert int(one(exposed, "ecdat:score")) == 78
    categories = dict(entry.split("=", 1) for entry in exposed["ecdat:category_score"])
    assert categories == {
        "criticality": "0",
        "exposure": "10",
        "mosca": "28",
        "quantum": "40",
    }
    # The DST deadline is still SHOWN -- demoted, never dropped.
    assert one(exposed, "ecdat:deadline") == "2028-12-31"
    assert one(exposed, "ecdat:provisional") == "true"
    assert "dst-cii-priority-migration" in exposed["ecdat:provisional_rule"]


@pytest.mark.validation
def test_end_to_end_the_same_repo_unclassified_is_not_critical(
    tmp_path: Path,
) -> None:
    context = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=tmp_path)
    target = Target(kind="repo", ref="testdata/minimal_repo", system="lab")

    scan_id = run_scan(target, registry.get_scanners(["source"]), context)

    record = store.get_scan(scan_id)
    assert record is not None
    document = json.loads(record.cbom_json)
    rsa = next(c for c in document["components"] if c["name"] == "RSA-2048")
    values = {p["name"]: p["value"] for p in rsa["properties"]}

    assert values["ecdat:band"] != "Critical"
    assert values["ecdat:exposure"] == "unknown"
