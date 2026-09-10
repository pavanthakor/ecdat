"""The verified-fact gate: the tool CANNOT score on an unverified fact (ADR-0017).

ECDAT's packs are cited by construction -- a rule without a `citation` does not
load. But a citation says where an idea came from, not that anybody checked it.
Four facts in `india_dst.yaml` were supplied verbatim and encoded verbatim: the
2028 CII deadline, the 2029 full-adoption deadline, the CII sector list and the
L2A assurance mapping. They were carrying 20 points of `criticality` on the
strength of nobody having looked them up.

The fix is structural rather than editorial. Every rule gains `verified` and
`source`, and **the engine adds a contribution to the score only when
`verified` is true.** An unverified rule still fires, still attaches its label,
deadline and action -- marked provisional -- and contributes exactly zero. So:

* a fact nobody checked can inform a reader, and cannot move a number;
* nothing is dropped, so the gap is visible rather than absent;
* filling in a source and flipping the flag is all it takes to restore scoring,
  which means the mechanism is what gates the fact, not a hard-coded skip.

The mutation tests at the bottom disable each half -- score the unverified
effect, or drop its label instead of demoting it -- and assert something goes
red.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import registry, store
from core.scanner import ScanContext, Target
from policy import sign
from policy.apply import ScoreInputs, apply_policy
from policy.engine import (
    PROVISIONAL_SUFFIX,
    Pack,
    PackValidationError,
    Verdict,
    evaluate,
    load_packs,
)

DEV_PRIVATE_KEY = Path("policy/keys/dev/pack-signing.key")
PACK_DIR = Path("policy/packs")
KNOWLEDGE_DIR = Path("knowledge")

#: The four DST facts that were never checked against the published roadmap.
UNVERIFIED_DST_RULES = frozenset(
    {
        "dst-cii-priority-migration",
        "dst-full-adoption",
        "dst-assurance-software-l2a",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_pack(directory: Path, body: dict[str, Any], name: str = "t.yaml") -> Path:
    path = directory / name
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    sign.sign_file(path, DEV_PRIVATE_KEY)
    return path


def one_rule_pack(
    *,
    verified: bool,
    source: str | None = None,
    score: int = 25,
) -> dict[str, Any]:
    """A pack with exactly one scoring rule, so the arithmetic is unambiguous."""
    rule: dict[str, Any] = {
        "id": "t-rsa",
        "when": {"algorithm": "RSA"},
        "effect": {
            "score": score,
            "category": "quantum",
            "labels": ["needs-migration"],
            "deadline": "2028-12-31",
            "action": "Replace RSA.",
        },
        "citation": "NIST IR 8547 ipd Sec. 3",
        "verified": verified,
    }
    if source is not None:
        rule["source"] = source
    return {
        "pack": "t",
        "version": 1,
        "citation": "test pack",
        "caps": {"quantum": 40},
        "rules": [rule],
    }


def rsa_component() -> dict[str, Any]:
    return {
        "name": "RSA-2048",
        "bom-ref": "abc123",
        "properties": [
            {"name": "ecdat:algorithm", "value": "RSA"},
            {"name": "ecdat:asset_type", "value": "algorithm"},
            {"name": "ecdat:param:key_size", "value": "2048"},
        ],
    }


def verdict_for(directory: Path, body: dict[str, Any]) -> Verdict:
    write_pack(directory, body)
    return evaluate(rsa_component(), load_packs(directory))


# ---------------------------------------------------------------------------
# The gate: unverified scores zero, but is still shown
# ---------------------------------------------------------------------------


def test_an_unverified_rule_contributes_zero_to_the_score(tmp_path: Path) -> None:
    verdict = verdict_for(tmp_path, one_rule_pack(verified=False))

    assert verdict.score == 0
    assert verdict.band == "Low"


def test_a_verified_rule_scores_normally(tmp_path: Path) -> None:
    """The demotion must not break the facts we DID check."""
    verdict = verdict_for(
        tmp_path,
        one_rule_pack(verified=True, source="NIST IR 8547 ipd, checked 2026-09-10"),
    )

    assert verdict.score == 25


def test_an_unverified_rule_scores_the_same_as_if_it_were_absent(
    tmp_path: Path,
) -> None:
    """The load-bearing arithmetic claim, stated as a comparison.

    Not "scores 0" but "scores exactly what a pack without the rule scores" --
    which is the property that survives someone adding a baseline later.
    """
    absent = tmp_path / "absent"
    present = tmp_path / "present"
    absent.mkdir()
    present.mkdir()

    empty = one_rule_pack(verified=True, source="checked")
    empty["rules"][0]["when"] = {"algorithm": "NOTHING-MATCHES-THIS"}
    write_pack(absent, empty)
    write_pack(present, one_rule_pack(verified=False))

    without = evaluate(rsa_component(), load_packs(absent))
    with_unverified = evaluate(rsa_component(), load_packs(present))

    assert with_unverified.score == without.score
    assert with_unverified.band == without.band


def test_an_unverified_rule_still_fires_and_still_labels(tmp_path: Path) -> None:
    """Demoted, never dropped. The reader still learns the fact exists."""
    verdict = verdict_for(tmp_path, one_rule_pack(verified=False))

    assert "t-rsa" in verdict.fired_rules
    assert verdict.labels, "an unverified rule must still attach its label"
    assert any(PROVISIONAL_SUFFIX in label for label in verdict.labels)
    assert any("needs-migration" in label for label in verdict.labels)
    # The deadline is shown -- it is information -- but flagged as resting on
    # an unverified fact.
    assert verdict.deadline is not None
    assert verdict.deadline_provisional is True
    assert verdict.provisional_rules == ("t-rsa",)


def test_a_verified_rules_label_is_not_marked_provisional(tmp_path: Path) -> None:
    verdict = verdict_for(tmp_path, one_rule_pack(verified=True, source="checked"))

    assert verdict.labels == ("needs-migration",)
    assert verdict.provisional_rules == ()
    assert verdict.deadline_provisional is False


def test_an_unverified_rules_action_says_so(tmp_path: Path) -> None:
    """An action a human will act on must not hide that it rests on a guess."""
    verdict = verdict_for(tmp_path, one_rule_pack(verified=False))

    assert verdict.actions
    assert all("PROVISIONAL" in action for action in verdict.actions)


def test_flipping_verified_to_true_makes_the_rule_score_again(
    tmp_path: Path,
) -> None:
    """The MECHANISM gates the fact -- not a hard-coded skip of DST rule ids."""
    off = tmp_path / "off"
    on = tmp_path / "on"
    off.mkdir()
    on.mkdir()
    write_pack(off, one_rule_pack(verified=False))
    write_pack(on, one_rule_pack(verified=True, source="DST/NQM roadmap Sec. 4.2"))

    assert evaluate(rsa_component(), load_packs(off)).score == 0
    assert evaluate(rsa_component(), load_packs(on)).score == 25


def test_an_unverified_rule_cannot_launder_a_score_through_quantum_status(
    tmp_path: Path,
) -> None:
    """The laundering hole, closed explicitly.

    `quantum_status` is not display -- it is a DERIVED FACT that second-pass
    rules select on. If an unverified rule could assert it, an unchecked fact
    would move a number indirectly by making a verified rule fire. So an
    unverified rule contributes no derived facts either.
    """
    body = one_rule_pack(verified=False)
    body["rules"][0]["effect"]["quantum_status"] = "broken"
    body["rules"].append(
        {
            "id": "t-second-pass",
            "when": {"quantum_status": "broken"},
            "effect": {"score": 30, "category": "quantum"},
            "citation": "test",
            "verified": True,
            "source": "checked",
        }
    )

    verdict = verdict_for(tmp_path, body)

    assert verdict.quantum_status is None
    assert verdict.score == 0, "an unverified rule moved a score via a derived fact"
    assert "t-second-pass" not in verdict.fired_rules


def test_a_verified_rule_may_still_assert_quantum_status(tmp_path: Path) -> None:
    body = one_rule_pack(verified=True, source="checked")
    body["rules"][0]["effect"]["quantum_status"] = "broken"

    verdict = verdict_for(tmp_path, body)

    assert verdict.quantum_status == "broken"


def test_verified_defaults_to_false_when_a_rule_omits_it(tmp_path: Path) -> None:
    """Silence is not verification. A pack author must opt IN."""
    body = one_rule_pack(verified=False)
    del body["rules"][0]["verified"]

    verdict = verdict_for(tmp_path, body)

    assert verdict.score == 0
    assert verdict.provisional_rules == ("t-rsa",)


def test_claiming_verified_without_a_source_is_refused(tmp_path: Path) -> None:
    """You cannot mark a fact checked without saying what you checked it against."""
    write_pack(tmp_path, one_rule_pack(verified=True))

    with pytest.raises(PackValidationError, match="source"):
        load_packs(tmp_path)


def test_a_blank_source_on_a_verified_rule_is_refused(tmp_path: Path) -> None:
    write_pack(tmp_path, one_rule_pack(verified=True, source="   "))

    with pytest.raises(PackValidationError, match="source"):
        load_packs(tmp_path)


# ---------------------------------------------------------------------------
# The shipped packs: which facts are verified, and which are demoted
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def packs() -> list[Pack]:
    return load_packs(PACK_DIR)


def rules_of(packs: list[Pack]) -> dict[str, Any]:
    return {rule.id: rule for pack in packs for rule in pack.rules}


def test_the_unchecked_dst_facts_are_marked_unverified(packs: list[Pack]) -> None:
    """These were supplied verbatim, never checked against the published text."""
    rules = rules_of(packs)
    for rule_id in UNVERIFIED_DST_RULES:
        assert rules[rule_id].verified is False, rule_id


def test_every_unverified_rule_says_what_to_check_it_against(
    packs: list[Pack],
) -> None:
    """A demoted fact carries a FILL marker, so the work is not lost."""
    for rule in rules_of(packs).values():
        if rule.verified:
            continue
        assert rule.source, f"{rule.id} is unverified with no FILL marker"
        assert "FILL:" in rule.source, rule.id


def test_the_quantum_and_nist_facts_are_verified_and_still_score(
    packs: list[Pack],
) -> None:
    """Only the genuinely-unconfirmed DST specifics demote."""
    rules = rules_of(packs)
    for rule_id in (
        "quantum-shor-broken-asymmetric",
        "quantum-classically-broken",
        "nist-112-bit-asymmetric-deprecated",
        "exposure-internet-reachable",
        "mosca-harvest-now-decrypt-later",
    ):
        assert rules[rule_id].verified is True, rule_id
        assert rules[rule_id].source, rule_id


def test_every_verified_rule_carries_a_source(packs: list[Pack]) -> None:
    for rule in rules_of(packs).values():
        if rule.verified:
            assert rule.source and rule.source.strip(), rule.id


def test_shor_broken_rsa_still_scores_forty(packs: list[Pack]) -> None:
    """The headline quantum verdict does not depend on any DST fact."""
    verdict = evaluate(rsa_component(), packs)

    assert verdict.quantum_status == "broken"
    assert verdict.categories.get("quantum") == 40


def test_the_dst_deadline_is_still_shown_but_provisional(packs: list[Pack]) -> None:
    """The demo still says 2028-12-31 -- it just no longer scores on it."""
    component = rsa_component()
    scored = json.loads(
        apply_policy(
            json.dumps({"components": [component]}),
            packs,
            inputs=ScoreInputs(
                data_class="Personal",
                sector="bfsi",
                exposure="internet",
                knowledge_dir=KNOWLEDGE_DIR,
            ),
        )
    )
    values: dict[str, list[str]] = {}
    for prop in scored["components"][0]["properties"]:
        values.setdefault(prop["name"], []).append(prop["value"])

    assert values["ecdat:deadline"] == ["2028-12-31"]
    assert values["ecdat:provisional"] == ["true"]
    assert "dst-cii-priority-migration" in values["ecdat:provisional_rule"]
    assert values["ecdat:deadline_provisional"] == ["true"]
    # The criticality category contributed nothing, because every rule in it is
    # currently unverified.
    categories = dict(
        entry.split("=", 1) for entry in values.get("ecdat:category_score", [])
    )
    assert categories.get("criticality", "0") == "0"


def test_criticality_is_still_reachable_without_any_dst_fact(
    packs: list[Pack],
) -> None:
    """quantum 40 + mosca 30 + exposure 10 = 80. Critical, with DST scoring nil.

    This is the claim the demotion has to survive: the band must come from
    facts we actually checked.
    """
    scored = json.loads(
        apply_policy(
            json.dumps({"components": [rsa_component()]}),
            packs,
            inputs=ScoreInputs(
                data_class="Sovereign",
                sector="bfsi",
                exposure="internet",
                knowledge_dir=KNOWLEDGE_DIR,
            ),
        )
    )
    values = {p["name"]: p["value"] for p in scored["components"][0]["properties"]}

    assert values["ecdat:band"] == "Critical"
    assert int(values["ecdat:score"]) >= 80


# ---------------------------------------------------------------------------
# The knowledge pack
# ---------------------------------------------------------------------------


def library_entries() -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(
        (KNOWLEDGE_DIR / "libraries.yaml").read_text(encoding="utf-8")
    )
    return {entry["name"]: entry for entry in document["libraries"]}


def test_the_openssl_pqc_floor_is_verified() -> None:
    """The one library fact confirmed against upstream release material."""
    openssl = library_entries()["OpenSSL"]

    assert openssl["pqc_capable_from"] == "3.5.0"
    assert openssl["pqc_capable_verified"] is True
    assert "3.5" in openssl["pqc_capable_source"]


def test_the_unconfirmed_library_floors_are_unverified_with_a_fill_marker() -> None:
    entries = library_entries()
    for name in ("GnuTLS", "libgcrypt", "NSS"):
        assert entries[name]["pqc_capable_from"] is None, name
        assert entries[name]["pqc_capable_verified"] is False, name
        assert "FILL:" in entries[name]["pqc_capable_source"], name


def test_an_unverified_library_floor_produces_no_pqc_capable_param(
    tmp_path: Path,
) -> None:
    """A version filled in without a source must NOT start scoring by itself."""
    from scanners.container import _is_pqc_capable, _load_library_pack

    pack = KNOWLEDGE_DIR / "libraries.yaml"
    document = yaml.safe_load(pack.read_text(encoding="utf-8"))
    for entry in document["libraries"]:
        if entry["name"] == "OpenSSL":
            entry["pqc_capable_verified"] = False
    (tmp_path / "libraries.yaml").write_text(
        yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
    )

    facts = _load_library_pack(tmp_path)
    assert _is_pqc_capable(facts["libssl3"], "3.5.7") is None

    verified = _load_library_pack(KNOWLEDGE_DIR)
    assert _is_pqc_capable(verified["libssl3"], "3.5.7") is True


# ---------------------------------------------------------------------------
# Engine version pinning
# ---------------------------------------------------------------------------


def test_requirements_pins_the_exact_verified_semgrep_version() -> None:
    """A floor is not a pin. Detection is only reproducible within a version."""
    from scanners.source import PINNED_SEMGREP_VERSION

    requirements = Path("requirements.txt").read_text(encoding="utf-8")

    assert f"semgrep=={PINNED_SEMGREP_VERSION}" in requirements
    assert "semgrep>=" not in requirements


def test_a_scan_records_the_engine_that_produced_it(tmp_path: Path) -> None:
    from core.orchestrator import run_scan

    context = ScanContext(knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path)
    target = Target(kind="repo", ref="testdata/minimal_repo", system="lab")

    scan = store.get_scan(run_scan(target, registry.get_scanners(["source"]), context))

    assert scan is not None
    assert scan.engine_versions is not None
    assert scan.engine_versions["ecdat"]
    semgrep = scan.engine_versions["source"]
    assert semgrep["pinned"]
    assert semgrep["installed"]
    assert semgrep["matches"] is True
    assert scan.engine_warning is None


def test_an_engine_version_mismatch_is_visible_on_the_scan_but_does_not_fail_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A teammate on a slightly different patch is warned, not blocked."""
    from core.orchestrator import run_scan
    from scanners.source import SourceScanner

    def mismatched(_self: SourceScanner) -> str:
        return "9.9.9"

    monkeypatch.setattr(SourceScanner, "engine_version", mismatched)
    context = ScanContext(knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path)
    target = Target(kind="repo", ref="testdata/minimal_repo", system="lab")

    scan = store.get_scan(run_scan(target, registry.get_scanners(["source"]), context))

    assert scan is not None
    assert scan.component_count > 0, "the scan must still have run"
    assert scan.engine_versions is not None
    assert scan.engine_versions["source"]["installed"] == "9.9.9"
    assert scan.engine_versions["source"]["matches"] is False
    assert scan.engine_warning is not None
    assert "9.9.9" in scan.engine_warning
    assert "semgrep" in scan.engine_warning.lower()


def test_an_uninstallable_engine_is_reported_rather_than_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.orchestrator import engine_versions
    from scanners.source import SourceScanner

    def missing(_self: SourceScanner) -> str | None:
        return None

    monkeypatch.setattr(SourceScanner, "engine_version", missing)

    versions, warning = engine_versions([SourceScanner()])

    assert versions["source"]["installed"] is None
    assert warning is not None
    assert tmp_path is not None  # fixture kept for symmetry with the suite


# ---------------------------------------------------------------------------
# MUTATION-STYLE NEGATIVES
# ---------------------------------------------------------------------------


def test_mutation_scoring_an_unverified_effect_changes_the_score(
    tmp_path: Path,
) -> None:
    """Prove the gate is what zeroes the contribution, not an empty effect.

    The same pack, the same rule, the same effect -- ONLY `verified` differs.
    If these two ever agree, the gate has stopped gating.
    """
    off = tmp_path / "off"
    on = tmp_path / "on"
    off.mkdir()
    on.mkdir()
    write_pack(off, one_rule_pack(verified=False))
    write_pack(on, one_rule_pack(verified=True, source="checked"))

    unverified = evaluate(rsa_component(), load_packs(off))
    verified = evaluate(rsa_component(), load_packs(on))

    assert unverified.score != verified.score, (
        "the verified flag is the ONLY difference between these packs; if the "
        "scores match, the engine is scoring unverified effects"
    )
    assert unverified.score == 0
    assert verified.score == 25


def test_mutation_dropping_an_unverified_rule_would_lose_its_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Demoted, not dropped -- and the difference is observable.

    Mutating the engine to SKIP unverified rules instead of demoting them makes
    the label disappear, which is the failure this decision exists to prevent:
    a fact nobody checked becoming a fact nobody sees.
    """
    import policy.engine as engine

    write_pack(tmp_path, one_rule_pack(verified=False))
    packs_here = load_packs(tmp_path)

    demoted = evaluate(rsa_component(), packs_here)
    assert demoted.labels
    assert demoted.fired_rules == ("t-rsa",)

    monkeypatch.setattr(engine, "_scores", lambda rule: rule.verified)
    monkeypatch.setattr(engine, "_fires", lambda rule: rule.verified)
    dropped = evaluate(rsa_component(), packs_here)

    assert dropped.labels == (), (
        "dropping instead of demoting loses the label -- which is exactly what "
        "the demote-never-drop decision forbids"
    )
    assert dropped.fired_rules == ()
