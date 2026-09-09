"""Scanner A: Python source crypto detection via Semgrep.

The suite is scored, not just asserted. Two numbers gate the slice:

* **RECALL** -- of every finding planted in ``testdata/python_fixtures`` and
  declared in ``answer_key.yaml``, how many did the scanner actually produce?
* **PRECISION** -- of every finding the scanner produced, how many were ground
  truth? Precision is asserted at exactly 1.0, which makes the answer key
  authoritative: a rule that fires on something not declared there fails the
  build even if the detection is arguably reasonable.

Beyond the score, the security-critical assertions are the negative ones: the
decoy file must stay silent, and no snippet may ever carry key material.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import store
from core.normalise import validate_cbom_json
from core.orchestrator import run_scan
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from scanners.source import SourceScanner

FIXTURE_ROOT = Path("testdata/python_fixtures")
ANSWER_KEY = FIXTURE_ROOT / "answer_key.yaml"
KNOWLEDGE_DIR = Path("knowledge")


def _load_answer_key() -> dict[str, Any]:
    with ANSWER_KEY.open(encoding="utf-8") as handle:
        loaded: dict[str, Any] = yaml.safe_load(handle)
    return loaded


ANSWERS = _load_answer_key()
EXPECTED: dict[str, list[dict[str, Any]]] = ANSWERS["expected"]
SENTINELS: list[str] = ANSWERS["secret_sentinels"]


# --------------------------------------------------------------------------
# One semgrep run for the whole module. Semgrep is a subprocess; paying for it
# once per assertion would make the suite unpleasant enough to skip.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR,
        scratch_dir=tmp_path_factory.mktemp("scratch"),
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="fixtures")
    return list(SourceScanner().scan(target, context))


def _rule_id(finding: Finding) -> str:
    rule = finding.raw.get("rule_id")
    assert isinstance(rule, str), f"finding carries no rule_id: {finding!r}"
    return rule


def _relative_path(finding: Finding) -> str:
    """The fixture-relative file a finding's first occurrence points at."""
    locator = finding.evidence.occurrences[0].locator
    path, _, _line = locator.rpartition(":")
    return str(Path(path).resolve().relative_to(FIXTURE_ROOT.resolve()))


def _by_file_and_rule(findings: list[Finding]) -> Counter[tuple[str, str]]:
    return Counter((_relative_path(f), _rule_id(f)) for f in findings)


# --------------------------------------------------------------------------
# Plugin contract
# --------------------------------------------------------------------------


def test_satisfies_the_scanner_protocol() -> None:
    assert isinstance(SourceScanner(), Scanner)


def test_identity_and_view() -> None:
    scanner = SourceScanner()
    assert scanner.id == "source"
    assert scanner.view == "declared"


@pytest.mark.parametrize("kind", ["repo", "directory"])
def test_supports_source_targets(kind: str) -> None:
    assert SourceScanner().supports(Target(kind=kind, ref="."))  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["image", "host", "endpoint"])
def test_declines_non_source_targets(kind: str) -> None:
    assert not SourceScanner().supports(Target(kind=kind, ref="x"))  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Per-rule detection: every rule fires on its own fixture, with the right
# algorithm / primitive / usage / asset type, the right number of times.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expectation"),
    [
        pytest.param(fixture, expectation, id=f"{expectation['rule_id']}::{fixture}")
        for fixture, expectations in EXPECTED.items()
        for expectation in expectations
    ],
)
def test_rule_fires_on_its_fixture(
    fixture: str, expectation: dict[str, Any], findings: list[Finding]
) -> None:
    rule_id = expectation["rule_id"]
    matched = [
        f for f in findings if _relative_path(f) == fixture and _rule_id(f) == rule_id
    ]

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


def test_every_declared_param_value_is_captured(findings: list[Finding]) -> None:
    """`params_any` in the answer key lists values the rules must actually capture."""
    for fixture, expectations in EXPECTED.items():
        for expectation in expectations:
            for wanted in expectation.get("params_any", []):
                matched = [
                    f
                    for f in findings
                    if _relative_path(f) == fixture
                    and _rule_id(f) == expectation["rule_id"]
                    and all(f.params.get(k) == v for k, v in wanted.items())
                ]
                seen = [f.params for f in findings if _relative_path(f) == fixture]
                assert matched, (
                    f"{expectation['rule_id']} on {fixture} never captured "
                    f"{wanted}; saw {seen}"
                )


# --------------------------------------------------------------------------
# Precision: the decoys are all shape and no substance.
# --------------------------------------------------------------------------


def test_decoys_produce_no_findings(findings: list[Finding]) -> None:
    false_positives = [
        (_rule_id(f), f.evidence.occurrences[0].locator)
        for f in findings
        if _relative_path(f) in ANSWERS["must_not_fire"]
    ]
    assert false_positives == [], (
        f"{len(false_positives)} false positive(s) on the decoy fixture: "
        f"{false_positives}"
    )


# --------------------------------------------------------------------------
# Parameter capture
# --------------------------------------------------------------------------


def test_rsa_keygen_captures_key_size(findings: list[Finding]) -> None:
    sizes = {
        f.params.get("key_size") for f in findings if _rule_id(f) == "py-rsa-keygen"
    }
    assert 2048 in sizes, f"literal key_size=2048 not captured as an int; got {sizes}"
    assert 1024 in sizes, f"pycryptodome key_size=1024 not captured; got {sizes}"


def test_aes_captures_mode_and_ecb_is_distinguishable_from_gcm(
    findings: list[Finding],
) -> None:
    modes = {f.params.get("mode") for f in findings if _rule_id(f) == "py-aes-cipher"}
    assert {"GCM", "ECB", "CTR", "CBC"} <= modes, f"modes captured: {modes}"

    ecb = [f for f in findings if f.params.get("mode") == "ECB"]
    gcm = [f for f in findings if f.params.get("mode") == "GCM"]
    assert ecb and gcm
    # Different params must mean different artefacts, not one merged AES blob.
    assert ecb[0].params != gcm[0].params


def test_ec_keygen_captures_curve(findings: list[Finding]) -> None:
    curves = {f.params.get("curve") for f in findings if _rule_id(f) == "py-ec-keygen"}
    assert "SECP256R1" in curves, (
        f"curve not normalised out of ec.SECP256R1(); got {curves}"
    )


def test_jwt_none_is_flagged(findings: list[Finding]) -> None:
    none_alg = [f for f in findings if _rule_id(f) == "py-jwt-none"]
    assert len(none_alg) == 1
    assert none_alg[0].params.get("alg") == "none"
    assert none_alg[0].params.get("flagged") is True


# --------------------------------------------------------------------------
# Confidence and configurability follow from whether the value was resolvable.
# --------------------------------------------------------------------------


def test_literal_capture_is_hard_coded_and_certain(findings: list[Finding]) -> None:
    literal = [
        f
        for f in findings
        if _rule_id(f) == "py-rsa-keygen" and f.params.get("key_size") == 2048
    ]
    assert len(literal) == 1
    assert literal[0].configurable is False
    assert literal[0].confidence == 1.0


def test_variable_capture_is_configurable_and_less_certain(
    findings: list[Finding],
) -> None:
    unresolved = [
        f
        for f in findings
        if _rule_id(f) == "py-rsa-keygen" and f.params.get("key_size") == 2048
    ]
    variable = [
        f
        for f in findings
        if _rule_id(f) == "py-rsa-keygen"
        and f not in unresolved
        and not isinstance(f.params.get("key_size"), int)
    ]
    assert variable, "the variable-key_size call site produced no finding"
    for finding in variable:
        assert finding.configurable is True
        assert finding.confidence < 1.0


def test_no_capture_rule_is_hard_coded(findings: list[Finding]) -> None:
    md5 = [f for f in findings if _rule_id(f) == "py-hashlib-md5"]
    assert md5
    for finding in md5:
        assert finding.configurable is False
        assert finding.confidence == 1.0


# --------------------------------------------------------------------------
# Redaction. PUNCHLIST #3: no secret key material anywhere in a Finding.
# --------------------------------------------------------------------------


def test_key_material_findings_carry_a_redacted_snippet(
    findings: list[Finding],
) -> None:
    redacting_rules = {
        expectation["rule_id"]
        for expectations in EXPECTED.values()
        for expectation in expectations
        if expectation.get("redacted")
    }
    assert redacting_rules, "the answer key declares no redacting rules"

    for rule in redacting_rules:
        matched = [f for f in findings if _rule_id(f) == rule]
        assert matched, f"{rule} did not fire"
        for finding in matched:
            for occurrence in finding.evidence.occurrences:
                assert occurrence.snippet == "<redacted key material>", (
                    f"{rule} leaked a snippet: {occurrence.snippet!r}"
                )


def test_no_planted_secret_reaches_any_finding(findings: list[Finding]) -> None:
    """The sentinels are planted inside the fixtures' key material."""
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in SENTINELS:
        assert sentinel not in blob, (
            f"secret sentinel {sentinel!r} escaped into a Finding; "
            "the redaction guard is not holding"
        )


# --------------------------------------------------------------------------
# Evidence hygiene
# --------------------------------------------------------------------------


def test_every_finding_has_wellformed_evidence(findings: list[Finding]) -> None:
    assert findings
    for finding in findings:
        assert finding.evidence.occurrences, "a finding was emitted with no evidence"
        for occurrence in finding.evidence.occurrences:
            path, _, line = occurrence.locator.rpartition(":")
            assert path, f"locator has no path: {occurrence.locator}"
            assert line.isdigit(), f"locator has no line number: {occurrence.locator}"
            assert Path(path).exists(), f"locator points nowhere: {occurrence.locator}"
            assert occurrence.view == "declared"
            assert occurrence.detail.startswith("rule=")


def test_scan_is_deterministic(context: ScanContext, findings: list[Finding]) -> None:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="fixtures")
    again = list(SourceScanner().scan(target, context))
    assert [f.model_dump() for f in again] == [f.model_dump() for f in findings]


# --------------------------------------------------------------------------
# Failing loud. A broken toolchain is not "zero findings".
# --------------------------------------------------------------------------


def test_missing_semgrep_binary_raises(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scanners.source as source

    monkeypatch.setattr(source, "SEMGREP_BINARY", "semgrep-does-not-exist")
    with pytest.raises(source.SemgrepUnavailableError):
        list(SourceScanner().scan(Target(kind="directory", ref="."), context))


def test_non_json_output_raises(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scanners.source as source

    def _not_json(rules_dir: Path, target_path: Path) -> str:  # noqa: ARG001
        return "not json at all"

    monkeypatch.setattr(source, "_run_semgrep", _not_json)
    with pytest.raises(source.SemgrepOutputError):
        list(SourceScanner().scan(Target(kind="directory", ref="."), context))


def test_missing_rule_pack_raises(context: ScanContext) -> None:
    import scanners.source as source

    empty = ScanContext(
        knowledge_dir=context.scratch_dir / "no-knowledge-here",
        scratch_dir=context.scratch_dir,
    )
    with pytest.raises(source.RulePackMissingError):
        list(SourceScanner().scan(Target(kind="directory", ref="."), empty))


# --------------------------------------------------------------------------
# End to end: the real orchestrator, the real normaliser, a real CBOM.
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_end_to_end_scan_produces_a_valid_cbom(context: ScanContext) -> None:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="fixtures")
    scan_id = run_scan(target, [SourceScanner()], context)

    record = store.get_scan(scan_id)
    assert record is not None
    validate_cbom_json(record.cbom_json)

    document = json.loads(record.cbom_json)
    names = {component["name"] for component in document["components"]}

    # Names the CBOM must contain, spanning capture, control and protocol paths.
    for expected in ("RSA-2048", "RSA-1024", "AES", "MD5", "SHA-256", "TLS TLSv1"):
        assert expected in names, f"{expected} missing from CBOM; got {sorted(names)}"

    for component in document["components"]:
        assert component["bom-ref"]
        assert "cryptoProperties" in component


# --------------------------------------------------------------------------
# The score.
# --------------------------------------------------------------------------


def test_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    actual = _by_file_and_rule(findings)
    expected = Counter(
        {
            (fixture, expectation["rule_id"]): expectation["count"]
            for fixture, expectations in EXPECTED.items()
            for expectation in expectations
        }
    )

    planted = sum(expected.values())
    found = sum(min(count, actual[key]) for key, count in expected.items())
    emitted = sum(actual.values())
    true_positives = sum(min(count, actual[key]) for key, count in expected.items())

    recall = found / planted
    precision = true_positives / emitted if emitted else 0.0

    missed = sorted(k for k, c in expected.items() if actual[k] < c)
    spurious = sorted(k for k in actual if k not in expected)

    with capsys.disabled():
        print(f"\n  RECALL    {recall:6.1%}  ({found}/{planted} planted findings)")
        print(f"  PRECISION {precision:6.1%}  ({true_positives}/{emitted} emitted)")
        if missed:
            print(f"  MISSED    {missed}")
        if spurious:
            print(f"  SPURIOUS  {spurious}")

    assert recall >= 0.9, f"recall {recall:.1%} below 0.9; missed {missed}"
    assert precision == 1.0, f"precision {precision:.1%}; spurious {spurious}"
