"""The Java rule pack (ADR-0024).

Scored on its own, like every other language pack — see `tests/rulepack.py` and
ADR-0023 for why packs are never averaged together.

Java is JCA-first: nearly everything goes through a `getInstance(String)`
factory, so the algorithm, the mode and the padding all arrive as ONE string
literal. That shapes the whole pack, and two of its assertions:

* the cipher MODE is parsed out of the transformation string rather than taken
  from the method name, and `AES/GCM/NoPadding` and `AES/ECB/PKCS5Padding` must
  come back as different facts with only one of them flagged;
* `Cipher.getInstance("AES")` names no mode at all, and SunJCE defaults to ECB —
  so it must be reported as ECB even though the word never appears in the source.

Java is also the fifth scanner family under the redaction guard, and the first
whose key-material fixture is written to exercise the CROSS-RULE case
deliberately: the AES-CBC rule matches the same file as the hard-coded-key rule,
and the sentinel must not escape through it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.normalise import normalise, validate_cbom_json
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import load_answers, relative_path_of, rule_id_of, score

FIXTURE_ROOT = Path("testdata/java_fixtures")
KNOWLEDGE_DIR = Path("knowledge")
ANSWERS = load_answers(FIXTURE_ROOT)

#: Every Java rule that matches key material (ADR-0034's three branches plus
#: the PEM rule). Each must redact its snippet.
JAVA_KEY_MATERIAL_RULES = frozenset(
    {
        "java-hardcoded-key",
        "java-hardcoded-key-der",
        "java-hardcoded-key-candidate",
        "java-pem-block",
    }
)


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR,
        scratch_dir=tmp_path_factory.mktemp("java-scratch"),
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="java-fixtures")
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
def test_java_rule_fires_on_its_fixture(
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


def test_every_declared_java_param_is_captured(findings: list[Finding]) -> None:
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


def test_keypairgenerator_rsa_captures_the_key_size(findings: list[Finding]) -> None:
    """The capture channel end to end, across the two-statement JCA idiom.

    `getInstance("RSA")` and `initialize(2048)` are separate statements, so the
    rule has to hold the generator across them -- which is the shape most JCA
    rules need.
    """
    rsa = [f for f in findings if rule_id_of(f) == "java-keypairgenerator-rsa"]
    assert rsa, "java-keypairgenerator-rsa did not fire at all"
    assert all(f.params.get("key_size") == 2048 for f in rsa), [f.params for f in rsa]
    # An int, not a string: params are identifying, and 2048 and "2048" hash to
    # different artefacts (PUNCHLIST: untyped params).
    assert all(isinstance(f.params["key_size"], int) for f in rsa)


# ---------------------------------------------------------------------------
# The mode comes out of the transformation string
# ---------------------------------------------------------------------------


def test_the_aes_mode_is_parsed_from_the_transformation_string(
    findings: list[Finding],
) -> None:
    """GCM, CBC and ECB are three facts, from one `getInstance(String)` call."""
    modes = {
        _rel(f): f.params.get("mode")
        for f in findings
        if f.algorithm == "AES" and f.params.get("mode")
    }
    assert modes.get("must_fire/JavaCipherAesGcm.java") == "GCM"
    assert modes.get("must_fire/JavaCipherAesCbc.java") == "CBC"
    assert modes.get("must_fire/JavaCipherAesEcb.java") == "ECB"


def test_the_whole_transformation_is_kept_alongside_the_mode(
    findings: list[Finding],
) -> None:
    """The parse must not discard what the source actually said."""
    gcm = [
        f
        for f in findings
        if _rel(f) == "must_fire/JavaCipherAesGcm.java"
        and rule_id_of(f) == "java-cipher-aes-gcm"
    ]
    assert gcm
    assert gcm[0].params.get("transformation") == "AES/GCM/NoPadding"


def test_ecb_is_flagged_and_gcm_is_not(findings: list[Finding]) -> None:
    ecb = [f for f in findings if rule_id_of(f) == "java-cipher-aes-ecb"]
    gcm = [f for f in findings if rule_id_of(f) == "java-cipher-aes-gcm"]
    assert ecb and gcm
    assert all(f.params.get("flagged") is True for f in ecb), [f.params for f in ecb]
    assert all(f.params.get("flagged") is not True for f in gcm)


def test_a_transformation_with_no_mode_is_reported_as_ecb(
    findings: list[Finding],
) -> None:
    """`Cipher.getInstance("AES")` is ECB, and the source never says so.

    The provider default is the whole point: an operator grepping for "ECB"
    finds nothing, and the cipher is still ECB.
    """
    implicit = [f for f in findings if _rel(f) == "must_fire/JavaCipherAesDefault.java"]
    assert implicit, 'Cipher.getInstance("AES") produced no finding'
    assert all(f.params.get("mode") == "ECB" for f in implicit), [
        f.params for f in implicit
    ]
    assert all(f.params.get("flagged") is True for f in implicit)


# ---------------------------------------------------------------------------
# A weak hash inside a signature transformation
# ---------------------------------------------------------------------------


def test_sha1withrsa_is_flagged_and_sha256withrsa_is_not(
    findings: list[Finding],
) -> None:
    """The RSA key size is irrelevant if the digest is forgeable."""
    weak = [f for f in findings if rule_id_of(f) == "java-signature-weak-hash"]
    strong = [f for f in findings if rule_id_of(f) == "java-signature-rsa"]
    assert weak, "java-signature-weak-hash did not fire on SHA1withRSA"
    assert strong, "java-signature-rsa did not fire on SHA256withRSA"

    # Two sites since ADR-0028: the literal, and the same transformation behind
    # a variable. Both must carry the flag -- the propagated one reports the
    # variable's NAME as its transformation, because metavariable-pattern
    # constrains a binding without rewriting it, and losing the flag there
    # would be the expensive half of the finding.
    assert {f.params.get("transformation") for f in weak} == {
        "SHA1withRSA",
        "transform",
    }
    assert all(f.params.get("flagged") is True for f in weak), [f.params for f in weak]
    assert all(f.params.get("flagged") is not True for f in strong)


def test_java_signature_verify_reports_the_verify_side(findings: list[Finding]) -> None:
    """`Signature.initVerify` VERIFIES (ADR-0030's java-signature-verify).

    Shipped in ADR-0030 with no fixture. The ALGORITHM is honestly `unknown`:
    this rule fires at `initVerify` alone, and the algorithm was chosen at
    `Signature.getInstance`. Where getInstance is in the same method, ADR-0037's
    use-site refinement now carries `verify` onto the getInstance-side finding,
    which does know the algorithm (tests/test_java_usage_refinement.py). The
    USAGE is the fact this rule adds, and it must be `verify`. A `verify(sig)`
    is not a second finding: the direction was set once, at `initVerify`.
    """
    hits = [f for f in findings if rule_id_of(f) == "java-signature-verify"]
    in_its_fixture = [
        f for f in hits if _rel(f) == "must_fire/JavaSignatureVerify.java"
    ]
    assert len(in_its_fixture) == 1, hits
    # Every hit, in every fixture that has one, is the verify side at initVerify.
    for hit in hits:
        assert (hit.algorithm, hit.primitive, hit.usage) == (
            "unknown",
            "signature",
            "verify",
        )
        assert "initVerify" in (hit.evidence.occurrences[0].snippet or "")


# ---------------------------------------------------------------------------
# Precision: the decoys
# ---------------------------------------------------------------------------


def test_no_java_rule_fires_on_the_decoys(findings: list[Finding]) -> None:
    """A comment naming RSA, an `md5Column` field, a non-key `Random`, and
    `"AES"` as a map key."""
    hits = [
        (rule_id_of(f), f.evidence.occurrences[0].locator)
        for f in findings
        if _rel(f).startswith("must_not_fire/")
    ]
    assert hits == [], f"Java rules fired on decoys: {hits}"


def test_the_java_rng_rule_is_name_scoped(findings: list[Finding]) -> None:
    """It fires on a token, and NOT on jitter or a banner pick."""
    rng = [f for f in findings if rule_id_of(f) == "java-weak-random"]
    assert rng, "java-weak-random did not fire on its must_fire fixture"
    assert all(_rel(f) == "must_fire/JavaWeakRandom.java" for f in rng)


def test_aes_as_a_map_key_is_not_a_cipher(findings: list[Finding]) -> None:
    """The string `"AES"` only means AES inside a JCA factory call."""
    decoy_hits = [f for f in findings if _rel(f) == "must_not_fire/Decoys.java"]
    assert decoy_hits == []


# ---------------------------------------------------------------------------
# Redaction — the fifth scanner family, and the cross-rule case
# ---------------------------------------------------------------------------


def test_no_planted_secret_reaches_any_java_finding(findings: list[Finding]) -> None:
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in ANSWERS.sentinels:
        assert sentinel not in blob, (
            f"secret sentinel {sentinel!r} escaped into a Java Finding; "
            "the redaction guard is not holding for Java"
        )


def test_java_key_material_findings_are_redacted(findings: list[Finding]) -> None:
    material = [f for f in findings if rule_id_of(f) in JAVA_KEY_MATERIAL_RULES]
    assert material, "no Java key-material findings at all"
    for finding in material:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == "<redacted key material>", occurrence.snippet


def test_the_cross_rule_case_does_not_leak_the_key(findings: list[Finding]) -> None:
    """A rule that knows nothing about keys must not carry one out.

    `JavaHardcodedKey.java` is matched by the AES-CBC rule as well as the
    key-material rule. That second rule has no `redact` flag and no idea a
    secret is in the file -- so this asserts on ITS findings specifically,
    rather than trusting the whole-blob check to have covered the right one.
    """
    others = [
        f
        for f in findings
        if _rel(f) == "must_fire/JavaHardcodedKey.java"
        and rule_id_of(f) != "java-hardcoded-key"
    ]
    assert others, "the cross-rule case is not exercised: no other rule matched"
    for finding in others:
        blob = json.dumps(finding.model_dump(), default=str)
        for sentinel in ANSWERS.sentinels:
            assert sentinel not in blob, (
                f"{rule_id_of(finding)} carried {sentinel!r} out of a file it "
                "does not know contains a key"
            )


def test_the_opaque_literal_net_keeps_algorithm_strings_intact() -> None:
    """The scrub that closed the cross-rule hole, tested on what it must NOT eat.

    A redaction net that swallows `"AES/CBC/PKCS5Padding"` costs every Java
    cipher finding its evidence, which is a real loss traded for a
    hypothetical one. These are the strings that decided the bound and the
    alphabet -- see `_OPAQUE_LITERAL` in `scanners/source`.
    """
    from scanners.source import REDACTED, _redact

    def scrubbed(line: str) -> bool:
        return (
            "<redacted>" in _redact(line, always=False)
            or _redact(line, always=False) == REDACTED
        )

    # Must be caught: opaque blobs with no structure at all.
    assert scrubbed('String k = "JAVASECRETSENTINELabcdef0123456789";')
    assert scrubbed('String k = "0123456789abcdef0123456789abcdef";')
    assert scrubbed('String k = "QUJDREVGR0hJSktMTU5PUFFSU1RVVld=";')

    # Must survive: every one of these is a real algorithm name.
    assert not scrubbed('Cipher.getInstance("AES/CBC/PKCS5Padding");')
    assert not scrubbed('Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");')
    assert not scrubbed('SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");')
    assert not scrubbed('Signature.getInstance("SHA256withRSA");')
    assert not scrubbed('crypto.createCipheriv("aes-256-gcm", key, iv);')


# ---------------------------------------------------------------------------
# Evidence hygiene, CBOM, determinism
# ---------------------------------------------------------------------------


def test_every_java_finding_has_wellformed_evidence(findings: list[Finding]) -> None:
    assert findings
    for finding in findings:
        assert finding.evidence.occurrences
        for occurrence in finding.evidence.occurrences:
            path, _, line = occurrence.locator.rpartition(":")
            assert path and line.isdigit(), occurrence.locator
            assert Path(path).exists(), occurrence.locator
            assert occurrence.view == "declared"
            assert occurrence.detail.startswith("rule=")


def test_java_rule_ids_are_language_prefixed(findings: list[Finding]) -> None:
    for finding in findings:
        assert rule_id_of(finding).startswith("java-"), rule_id_of(finding)


@pytest.mark.validation
def test_a_java_scan_produces_a_schema_valid_cbom(findings: list[Finding]) -> None:
    target = Target(kind="repo", ref=str(FIXTURE_ROOT), system="java-fixtures")
    _, cbom_json = normalise(findings, target)
    validate_cbom_json(cbom_json)

    document = json.loads(cbom_json)
    names = {component["name"] for component in document["components"]}
    assert "RSA-2048" in names, sorted(names)
    assert "MD5" in names, sorted(names)
    assert "AES" in names, sorted(names)
    for component in document["components"]:
        assert component["bom-ref"]


def test_the_java_scan_is_deterministic(context: ScanContext) -> None:
    """Same input, same packs -> byte-identical CBOM (CLAUDE.md)."""
    import datetime
    import uuid

    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="java-fixtures")
    fixed: dict[str, Any] = {
        "serial_number": uuid.UUID(int=0),
        "timestamp": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    }
    first = normalise(list(SourceScanner().scan(target, context)), target, **fixed)[1]
    second = normalise(list(SourceScanner().scan(target, context)), target, **fixed)[1]
    assert first == second


# ---------------------------------------------------------------------------
# THE SCORE
# ---------------------------------------------------------------------------


def test_java_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    result = score(findings, ANSWERS)
    with capsys.disabled():
        print(result.report("JAVA"))

    # == 1.0, not a floor: a floor hides a regression (ADR-0027, ADR-0037).
    assert result.recall == 1.0, (
        f"Java recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, (
        f"Java precision {result.precision:.1%}; spurious {result.spurious}"
    )
