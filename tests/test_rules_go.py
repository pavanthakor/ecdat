"""PART A — the Go rule pack (ADR-0023).

Scored on its own. ADR-0023 ships Go and JS/TS together but never averages
them: a combined number lets a strong pack carry a weak one, and either pack
failing has to fail the build. `tests/test_rules_js.py` is the other half and
shares nothing with this file except `tests/rulepack.py`.

The engine is unchanged and already proven — these are Semgrep rules against
the same metadata contract the Python pack has satisfied since ADR-0004
(`knowledge/rules/README.md`). What is new is two more languages under the
redaction guard: a planted sentinel in Go key material must reach no Finding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import load_answers, relative_path_of, rule_id_of, score

FIXTURE_ROOT = Path("testdata/go_fixtures")
KNOWLEDGE_DIR = Path("knowledge")
ANSWERS = load_answers(FIXTURE_ROOT)


# ---------------------------------------------------------------------------
# One semgrep run for the module. It is a subprocess; paying per assertion
# would make the suite unpleasant enough to skip.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("go-scratch")
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="go-fixtures")
    return list(SourceScanner().scan(target, context))


def _rel(finding: Finding) -> str:
    return relative_path_of(finding, FIXTURE_ROOT)


# ---------------------------------------------------------------------------
# Every rule fires on its own fixture, with the right facts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expectation"),
    [
        pytest.param(fixture, expectation, id=f"{expectation['rule_id']}::{fixture}")
        for fixture, expectation in ANSWERS.cases
    ],
)
def test_go_rule_fires_on_its_fixture(
    fixture: str, expectation: dict[str, Any], findings: list[Finding]
) -> None:
    rule_id = expectation["rule_id"]
    matched = [f for f in findings if _rel(f) == fixture and rule_id_of(f) == rule_id]

    assert matched, f"{rule_id} did not fire on {fixture}"
    assert len(matched) == expectation["count"], (
        f"{rule_id} fired {len(matched)} times on {fixture}, "
        f"expected {expectation['count']}"
    )
    for finding in matched:
        assert finding.scanner_id == "source"
        assert finding.view == "declared"
        assert finding.algorithm == expectation["algorithm"]
        assert finding.primitive == expectation["primitive"]
        assert finding.usage == expectation["usage"]
        assert finding.asset_type == expectation["asset_type"]


def test_every_declared_go_param_is_captured(findings: list[Finding]) -> None:
    """`params_any` lists values the Go rules must actually capture."""
    for fixture, expectation in ANSWERS.cases:
        for wanted in expectation.get("params_any", []):
            matched = [
                f
                for f in findings
                if _rel(f) == fixture
                and rule_id_of(f) == expectation["rule_id"]
                and all(f.params.get(k) == v for k, v in wanted.items())
            ]
            seen = [f.params for f in findings if _rel(f) == fixture]
            assert matched, (
                f"{expectation['rule_id']} on {fixture} never captured "
                f"{wanted}; saw {seen}"
            )


def test_go_rsa_keygen_captures_the_key_size(findings: list[Finding]) -> None:
    """Called out separately because it is the capture channel end to end."""
    rsa = [f for f in findings if rule_id_of(f) == "go-rsa-keygen"]
    assert rsa, "go-rsa-keygen did not fire at all"
    assert all(f.params.get("key_size") == 2048 for f in rsa), [f.params for f in rsa]
    # An int, not a string: params are identifying, and 2048 and "2048" hash to
    # different artefacts (PUNCHLIST: untyped params).
    assert all(isinstance(f.params["key_size"], int) for f in rsa)


def test_go_aes_modes_are_distinguishable(findings: list[Finding]) -> None:
    """ECB, CBC and GCM must be three different facts, not one 'AES'."""
    modes = {
        _rel(f): f.params.get("mode")
        for f in findings
        if f.algorithm == "AES" and f.params.get("mode")
    }
    assert modes.get("must_fire/go_aes_cbc.go") == "CBC"
    assert modes.get("must_fire/go_aes_gcm.go") == "GCM"
    assert modes.get("must_fire/go_aes_ecb.go") == "ECB"


def test_go_ecb_is_flagged_and_gcm_is_not(findings: list[Finding]) -> None:
    ecb = [f for f in findings if rule_id_of(f) == "go-aes-ecb"]
    gcm = [f for f in findings if rule_id_of(f) == "go-aes-gcm"]
    assert ecb and gcm
    assert all(f.params.get("flagged") is True for f in ecb), [f.params for f in ecb]
    assert all(f.params.get("flagged") is not True for f in gcm)


# ---------------------------------------------------------------------------
# Precision: the decoys
# ---------------------------------------------------------------------------


def test_no_go_rule_fires_on_the_decoys(findings: list[Finding]) -> None:
    """Comments, digest-shaped names, a non-key RNG use, a crypto-ish import."""
    hits = [
        (rule_id_of(f), f.evidence.occurrences[0].locator)
        for f in findings
        if _rel(f).startswith("must_not_fire/")
    ]
    assert hits == [], f"Go rules fired on decoys: {hits}"


def test_the_go_rng_rule_is_name_scoped(findings: list[Finding]) -> None:
    """It fires on a token, and NOT on jitter or a display shuffle."""
    rng = [f for f in findings if rule_id_of(f) == "go-weak-random"]
    assert rng, "go-weak-random did not fire on its must_fire fixture"
    assert all(_rel(f) == "must_fire/go_weak_random.go" for f in rng)


# ---------------------------------------------------------------------------
# Redaction, now covering a second scanner family
# ---------------------------------------------------------------------------


def test_no_planted_secret_reaches_any_go_finding(findings: list[Finding]) -> None:
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in ANSWERS.sentinels:
        assert sentinel not in blob, (
            f"secret sentinel {sentinel!r} escaped into a Go Finding; "
            "the redaction guard is not holding for Go"
        )


def test_go_key_material_findings_are_redacted(findings: list[Finding]) -> None:
    material = [
        f for f in findings if rule_id_of(f) in {"go-hardcoded-key", "go-pem-block"}
    ]
    assert material, "no Go key-material findings at all"
    for finding in material:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == "<redacted key material>", occurrence.snippet


# ---------------------------------------------------------------------------
# Evidence hygiene
# ---------------------------------------------------------------------------


def test_every_go_finding_has_wellformed_evidence(findings: list[Finding]) -> None:
    assert findings
    for finding in findings:
        assert finding.evidence.occurrences
        for occurrence in finding.evidence.occurrences:
            path, _, line = occurrence.locator.rpartition(":")
            assert path and line.isdigit(), occurrence.locator
            assert Path(path).exists(), occurrence.locator
            assert occurrence.view == "declared"
            assert occurrence.detail.startswith("rule=")


def test_go_rule_ids_are_language_prefixed(findings: list[Finding]) -> None:
    """`knowledge/rules/README.md`: prefix with the language."""
    for finding in findings:
        assert rule_id_of(finding).startswith("go-"), rule_id_of(finding)


# ---------------------------------------------------------------------------
# THE SCORE — Part A, on its own
# ---------------------------------------------------------------------------


def test_go_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    result = score(findings, ANSWERS)
    with capsys.disabled():
        print(result.report("GO"))

    assert result.recall >= 0.9, (
        f"Go recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, (
        f"Go precision {result.precision:.1%}; spurious {result.spurious}"
    )
