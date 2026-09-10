"""PART B — the JavaScript / TypeScript rule pack (ADR-0023).

Scored on its own, and never averaged with Go: see `tests/test_rules_go.py`
and ADR-0023 for why a combined number would let one pack carry the other.

The pack targets **both** `.js` and `.ts`. That is asserted rather than
assumed: `ts_*.ts` fixtures carry declared detections, `must_not_fire/decoys.ts`
proves TypeScript on the precision side, and
`test_typescript_files_are_actually_scanned` fails if the `.ts` half of the pack
silently stopped matching.
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

FIXTURE_ROOT = Path("testdata/js_fixtures")
KNOWLEDGE_DIR = Path("knowledge")
ANSWERS = load_answers(FIXTURE_ROOT)

#: Every JS rule that matches key material (ADR-0034's three branches plus the
#: PEM rule). Each must redact its snippet.
JS_KEY_MATERIAL_RULES = frozenset(
    {
        "js-hardcoded-key",
        "js-hardcoded-key-der",
        "js-hardcoded-key-candidate",
        "js-pem-block",
    }
)


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("js-scratch")
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="js-fixtures")
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
def test_js_rule_fires_on_its_fixture(
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


def test_every_declared_js_param_is_captured(findings: list[Finding]) -> None:
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


# ---------------------------------------------------------------------------
# TypeScript is scanned, not merely configured
# ---------------------------------------------------------------------------


def test_typescript_files_are_actually_scanned(findings: list[Finding]) -> None:
    """The `.ts` half of the pack, asserted as a whole.

    A rule declaring `languages: [javascript, typescript]` that silently stops
    matching `.ts` would still pass every `.js` assertion in this file. This is
    the test that notices.
    """
    ts_files = sorted({_rel(f) for f in findings if _rel(f).endswith(".ts")})
    assert ts_files, "no finding came from any .ts file"
    assert "must_fire/ts_hash_md5.ts" in ts_files
    assert "must_fire/ts_keypair_ec.ts" in ts_files
    assert "must_fire/ts_pem_certificate.ts" in ts_files


def test_the_same_rule_fires_on_both_js_and_ts(findings: list[Finding]) -> None:
    """One rule, two extensions.

    The whole point of `languages: [javascript, typescript]`.
    """
    md5 = {_rel(f) for f in findings if rule_id_of(f) == "js-hash-md5"}
    assert "must_fire/js_hash_md5.js" in md5
    assert "must_fire/ts_hash_md5.ts" in md5


# ---------------------------------------------------------------------------
# Captures that carry the migration decision
# ---------------------------------------------------------------------------


def test_js_rsa_keygen_captures_the_key_size(findings: list[Finding]) -> None:
    rsa = [f for f in findings if rule_id_of(f) == "js-keypair-rsa"]
    assert rsa, "js-keypair-rsa did not fire"
    assert all(f.params.get("key_size") == 2048 for f in rsa), [f.params for f in rsa]
    assert all(isinstance(f.params["key_size"], int) for f in rsa)


def test_js_cipher_modes_are_distinguishable(findings: list[Finding]) -> None:
    suites = {
        _rel(f): f.params.get("cipher_suite")
        for f in findings
        if rule_id_of(f) == "js-createcipheriv"
    }
    assert suites.get("must_fire/js_cipher_cbc.js") == "aes-128-cbc"
    assert suites.get("must_fire/js_cipher_gcm.js") == "aes-256-gcm"


def test_jwt_none_is_flagged_and_rs256_is_not(findings: list[Finding]) -> None:
    """`alg=none` disables verification: anyone can mint a token."""
    none = [f for f in findings if rule_id_of(f) == "js-jwt-none"]
    rs256 = [f for f in findings if rule_id_of(f) == "js-jwt-rsa"]
    assert none, "js-jwt-none did not fire"
    assert rs256, "js-jwt-rsa did not fire"
    assert all(f.params.get("flagged") is True for f in none), [f.params for f in none]
    assert all(f.params.get("flagged") is not True for f in rs256)


# ---------------------------------------------------------------------------
# Precision: the decoys, in both extensions
# ---------------------------------------------------------------------------


def test_no_js_rule_fires_on_the_decoys(findings: list[Finding]) -> None:
    hits = [
        (rule_id_of(f), f.evidence.occurrences[0].locator)
        for f in findings
        if _rel(f).startswith("must_not_fire/")
    ]
    assert hits == [], f"JS/TS rules fired on decoys: {hits}"


def test_the_js_rng_rule_is_name_scoped(findings: list[Finding]) -> None:
    """It fires on a token, and NOT on jitter, a shuffle or a banner pick."""
    rng = [f for f in findings if rule_id_of(f) == "js-math-random"]
    assert rng, "js-math-random did not fire on its must_fire fixture"
    # Two fixtures since ADR-0030: its own, and the one where the name AND the
    # flow agree (which the taint sibling also matches). Never a decoy.
    assert {_rel(f) for f in rng} == {
        "must_fire/js_math_random.js",
        "must_fire/js_rng_named_and_flowing.js",
    }


# ---------------------------------------------------------------------------
# Redaction, now covering a third scanner family
# ---------------------------------------------------------------------------


def test_no_planted_secret_reaches_any_js_finding(findings: list[Finding]) -> None:
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in ANSWERS.sentinels:
        assert sentinel not in blob, (
            f"secret sentinel {sentinel!r} escaped into a JS/TS Finding; "
            "the redaction guard is not holding for JavaScript"
        )


def test_js_key_material_findings_are_redacted(findings: list[Finding]) -> None:
    material = [f for f in findings if rule_id_of(f) in JS_KEY_MATERIAL_RULES]
    assert material, "no JS key-material findings at all"
    for finding in material:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == "<redacted key material>", occurrence.snippet


# ---------------------------------------------------------------------------
# Evidence hygiene
# ---------------------------------------------------------------------------


def test_every_js_finding_has_wellformed_evidence(findings: list[Finding]) -> None:
    assert findings
    for finding in findings:
        assert finding.evidence.occurrences
        for occurrence in finding.evidence.occurrences:
            path, _, line = occurrence.locator.rpartition(":")
            assert path and line.isdigit(), occurrence.locator
            assert Path(path).exists(), occurrence.locator
            assert occurrence.view == "declared"
            assert occurrence.detail.startswith("rule=")


def test_js_rule_ids_are_language_prefixed(findings: list[Finding]) -> None:
    for finding in findings:
        assert rule_id_of(finding).startswith("js-"), rule_id_of(finding)


# ---------------------------------------------------------------------------
# THE SCORE — Part B, on its own
# ---------------------------------------------------------------------------


def test_js_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    result = score(findings, ANSWERS)
    with capsys.disabled():
        print(result.report("JS/TS"))

    # == 1.0, not a floor: ADR-0027's lesson, and since ADR-0030 this key also
    # scores the weak-RNG taint fixtures.
    assert result.recall == 1.0, (
        f"JS recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, (
        f"JS precision {result.precision:.1%}; spurious {result.spurious}"
    )
