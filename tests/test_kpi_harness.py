"""The KPI harness (ADR-0014). The scorer is code, so it is tested like code.

A benchmark's number is only as trustworthy as its scorer, and a scorer is the
easiest thing in a project to make quietly generous: count a decoy as neutral
rather than as a failure, drop an undetectable artefact from the fixture, treat
a missing drift as "not applicable". Each of those produces a better slide and
a worse tool.

So the arithmetic is tested directly, on synthetic inputs where the right answer
is obvious, before it is ever pointed at QuantumBank.
"""

from __future__ import annotations

from typing import Any

import pytest

from kpi.harness import (
    DriftScore,
    FindingScore,
    score_drift,
    score_findings,
)


def planted(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "a-finding",
        "scanner": "source",
        "view": "declared",
        "algorithm": "RSA",
        "locator_contains": "services/auth/tokens.py",
        "endpoint": None,
        "count": 1,
        "known_gap": False,
    }
    entry.update(overrides)
    return entry


def emitted(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "algorithm": "RSA",
        "view": "declared",
        "asset_type": "algorithm",
        "locator": "testdata/quantumbank/services/auth/tokens.py:6",
        "endpoint": None,
    }
    entry.update(overrides)
    return entry


# --------------------------------------------------------------------------
# The arithmetic
# --------------------------------------------------------------------------


def test_one_match_and_one_miss_gives_half_recall() -> None:
    score = score_findings(
        emitted_findings=[emitted()],
        planted_findings=[
            planted(id="found"),
            planted(id="missed", algorithm="MD5", locator_contains="passwords.py"),
        ],
        decoys=[],
    )

    assert isinstance(score, FindingScore)
    assert score.planted == 2
    assert score.found == 1
    assert score.recall == 0.5
    assert [m.id for m in score.missed] == ["missed"]


def test_everything_found_gives_full_recall() -> None:
    score = score_findings(
        emitted_findings=[emitted()], planted_findings=[planted()], decoys=[]
    )
    assert score.recall == 1.0
    assert score.missed == []


def test_a_decoy_hit_is_a_precision_failure_not_an_omission() -> None:
    """The temptation is to ignore anything not in the answer key. A decoy
    firing is the one thing that must never be ignored."""
    score = score_findings(
        emitted_findings=[
            emitted(),
            emitted(locator="testdata/quantumbank/services/auth/decoys.py:8"),
        ],
        planted_findings=[planted()],
        decoys=["services/auth/decoys.py"],
    )

    assert score.decoy_hits == 1
    assert score.precision < 1.0
    assert score.emitted == 2
    assert "decoys.py" in score.false_positives[0]


def test_precision_is_one_when_no_decoy_fires() -> None:
    score = score_findings(
        emitted_findings=[emitted(), emitted(algorithm="MD5")],
        planted_findings=[planted()],
        decoys=["services/auth/decoys.py"],
    )
    assert score.decoy_hits == 0
    assert score.precision == 1.0


def test_an_empty_emission_does_not_divide_by_zero() -> None:
    score = score_findings(emitted_findings=[], planted_findings=[planted()], decoys=[])
    assert score.precision == 0.0
    assert score.recall == 0.0


# --------------------------------------------------------------------------
# Known gaps: excluded from the denominator, never from the report
# --------------------------------------------------------------------------


def test_a_known_gap_is_excluded_from_the_recall_denominator() -> None:
    """Otherwise an honest fixture would be punished for being honest."""
    score = score_findings(
        emitted_findings=[emitted()],
        planted_findings=[
            planted(id="detectable"),
            planted(id="go-ecdsa", known_gap=True, locator_contains="sign.go"),
        ],
        decoys=[],
    )

    assert score.planted == 1, "the known gap must not inflate the denominator"
    assert score.recall == 1.0
    assert score.missed == []


def test_a_known_gap_is_still_reported() -> None:
    """Excluded from the maths, never from the page. Hiding it would be the
    oldest way to lie with a benchmark."""
    score = score_findings(
        emitted_findings=[emitted()],
        planted_findings=[
            planted(id="detectable"),
            planted(
                id="go-ecdsa",
                known_gap=True,
                locator_contains="sign.go",
                note="a language ECDAT does not scan yet",
            ),
        ],
        decoys=[],
    )

    assert [g.id for g in score.known_gaps] == ["go-ecdsa"]
    assert "does not scan yet" in score.known_gaps[0].note


def test_a_known_gap_that_is_found_anyway_is_not_counted_as_a_miss() -> None:
    score = score_findings(
        emitted_findings=[emitted(locator="services/gateway/sign.go:14")],
        planted_findings=[
            planted(id="go-ecdsa", known_gap=True, locator_contains="sign.go")
        ],
        decoys=[],
    )
    assert score.missed == []


# --------------------------------------------------------------------------
# Per-view breakdown
# --------------------------------------------------------------------------


def test_recall_is_reported_per_view() -> None:
    score = score_findings(
        emitted_findings=[emitted()],
        planted_findings=[
            planted(id="declared-hit"),
            planted(
                id="shipped-miss",
                view="shipped",
                algorithm="OpenSSL",
                locator_contains="dpkg/status",
            ),
        ],
        decoys=[],
    )

    assert score.by_view["declared"].recall == 1.0
    assert score.by_view["shipped"].recall == 0.0


# --------------------------------------------------------------------------
# Drift
# --------------------------------------------------------------------------


def drift(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "kind": "shipped-cannot-do-declared",
        "endpoint": "payments.quantumbank.invalid:443",
        "declared": "X25519MLKEM768",
        "observed": "OpenSSL 3.0.2 (not PQC-capable)",
    }
    entry.update(overrides)
    return entry


def expected_drift(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "r1",
        "kind": "shipped-cannot-do-declared",
        "endpoint": "payments.quantumbank.invalid:443",
        "declared": "X25519MLKEM768",
        "observed_contains": "3.0.2",
    }
    entry.update(overrides)
    return entry


def test_a_found_drift_scores_full_drift_recall() -> None:
    score = score_drift([drift()], [expected_drift()], non_drifts=[])

    assert isinstance(score, DriftScore)
    assert score.recall == 1.0
    assert score.missing == []


def test_an_expected_drift_that_is_absent_is_a_drift_recall_miss() -> None:
    score = score_drift(
        emitted_drifts=[],
        expected_drifts=[expected_drift(), expected_drift(id="r2", kind="other")],
        non_drifts=[],
    )

    assert score.recall == 0.0
    assert sorted(m.id for m in score.missing) == ["r1", "r2"]


def test_invented_drift_on_an_agreement_case_is_a_precision_failure() -> None:
    """Drift reported where the views agree is the failure that makes a whole
    report ignorable."""
    score = score_drift(
        emitted_drifts=[drift(), drift(endpoint="sshd@quantumbank")],
        expected_drifts=[expected_drift()],
        non_drifts=[{"endpoint": "sshd@quantumbank", "why": "nothing to disagree"}],
    )

    assert score.invented, "invented drift was not counted"
    assert score.precision < 1.0
    assert "sshd@quantumbank" in score.invented[0]


def test_drift_precision_is_one_when_agreement_cases_stay_quiet() -> None:
    score = score_drift(
        emitted_drifts=[drift()],
        expected_drifts=[expected_drift()],
        non_drifts=[{"endpoint": "sshd@quantumbank", "why": "nothing"}],
    )
    assert score.precision == 1.0
    assert score.invented == []


def test_a_drift_of_the_wrong_kind_does_not_satisfy_an_expectation() -> None:
    score = score_drift(
        emitted_drifts=[drift(kind="protocol-downgrade")],
        expected_drifts=[expected_drift()],
        non_drifts=[],
    )
    assert score.recall == 0.0


def test_a_drift_on_the_wrong_endpoint_does_not_satisfy_an_expectation() -> None:
    score = score_drift(
        emitted_drifts=[drift(endpoint="legacy.quantumbank.invalid:8443")],
        expected_drifts=[expected_drift()],
        non_drifts=[],
    )
    assert score.recall == 0.0


# --------------------------------------------------------------------------
# End to end over QuantumBank
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_the_quantumbank_kpi_meets_its_gate(capsys: Any) -> None:
    from kpi.harness import run_kpi

    report = run_kpi()

    with capsys.disabled():
        report.render()

    assert report.findings.recall >= 0.9, (
        f"recall {report.findings.recall:.1%}; missed "
        f"{[m.id for m in report.findings.missed]}"
    )
    assert report.findings.decoy_hits == 0, (
        f"decoys fired: {report.findings.false_positives}"
    )
    assert report.drift.recall == 1.0, (
        f"expected drift missing: {[m.id for m in report.drift.missing]}"
    )
    assert report.drift.invented == [], f"invented drift: {report.drift.invented}"


@pytest.mark.validation
def test_both_headline_drifts_are_found() -> None:
    from kpi.harness import run_kpi

    report = run_kpi()
    kinds = {d["kind"] for d in report.emitted_drifts}

    assert "shipped-cannot-do-declared" in kinds
    assert "declared-pqc-observed-classical" in kinds


@pytest.mark.validation
def test_the_kpi_is_deterministic() -> None:
    """Two runs, identical numbers -- the determinism invariants all the way
    down mean a KPI is a measurement, not a sample."""
    from kpi.harness import run_kpi

    first = run_kpi()
    second = run_kpi()

    assert first.cbom_json == second.cbom_json
    assert first.findings.recall == second.findings.recall
    assert first.findings.precision == second.findings.precision
    assert first.drift.recall == second.drift.recall


def test_the_quantumbank_go_gateway_is_scored_not_excluded() -> None:
    """The Go gateway was the known gap. ADR-0023 closed it.

    It used to be real crypto ECDAT could not see, excluded from the recall
    denominator and printed on every run so the gap stayed visible. The Go rule
    pack detects both artefacts now, so they must be SCORED -- if they had
    stayed marked `known_gap` the denominator would never grow and recall would
    look identical whether or not the rules worked.
    """
    from kpi.harness import load_answer_key

    key = load_answer_key()
    gateway = [f for f in key["findings"] if "sign.go" in f["locator_contains"]]

    assert gateway, "the Go gateway entries vanished from the fixture"
    assert not any(f["known_gap"] for f in gateway), (
        "the Go gateway is still marked known_gap; the Go rules detect it now"
    )


def test_any_remaining_known_gap_still_says_why() -> None:
    """The mechanism outlives QuantumBank's own gaps.

    There are none in this fixture today. The invariant is what must not rot:
    an artefact excluded from the denominator has to carry the reason, or the
    exclusion becomes a way to make a score look better.
    """
    from kpi.harness import load_answer_key

    key = load_answer_key()
    gaps = [f for f in key["findings"] if f["known_gap"]]

    assert all(g.get("note") for g in gaps), "a known gap must say why"
