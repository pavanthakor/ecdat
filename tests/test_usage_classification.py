"""PART A — usage classification, because usage IS the recommendation (ADR-0030).

`usage` is not decoration. It is what decides the post-quantum target:

    RSA for SIGNING        -> ML-DSA   (FIPS 204)
    RSA for KEY TRANSPORT  -> ML-KEM   (FIPS 203)
    RSA, usage unknown     -> "choose by usage" -- correct, and not actionable

So a wrong usage is a wrong recommendation, which is the one output an operator
acts on. This slice improves the INPUT. The policy engine is untouched; what
changes is that the pack now has usage-conditioned recommendation rules to
condition ON, and the scanners give them something true to read.

Three sources of usage, in descending order of confidence:

1. **The API names it.** `jwt.decode` verifies; `Cipher.WRAP_MODE` is key
   transport; `rsa.EncryptOAEP` wraps a key. Deterministic.
2. **The use site names it.** A key generated `unknown` and then passed to
   `.sign()` in the same function is a signing key. Intra-procedural only --
   the OSS limit, and honest about it.
3. **Nothing names it.** Then it STAYS `unknown`. A guessed usage is a
   confidently wrong migration target on a real key, and the engine already has
   usage-agnostic advice for exactly this case.

The bug this closes is not hypothetical: before ADR-0030 the Python and JS JWT
rules matched `jwt.decode` and `jwt.verify` and reported `usage: sign`. Every
token VERIFIER in an estate was recommended a signing migration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.normalise import normalise
from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence
from policy.apply import ScoreInputs, apply_policy
from policy.engine import default_packs
from scanners.source import SourceScanner
from tests.rulepack import rule_id_of

KNOWLEDGE_DIR = Path("knowledge")
USAGE_ROOT = Path("testdata/usage_fixtures")


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("usage-scratch")
    )


def scan(subdir: str, context: ScanContext) -> list[Finding]:
    root = USAGE_ROOT / subdir
    target = Target(kind="directory", ref=str(root), system=f"usage-{subdir}")
    return list(SourceScanner().scan(target, context))


@pytest.fixture(scope="module")
def python_findings(context: ScanContext) -> list[Finding]:
    return scan("py", context)


@pytest.fixture(scope="module")
def js_findings(context: ScanContext) -> list[Finding]:
    return scan("js", context)


@pytest.fixture(scope="module")
def go_findings(context: ScanContext) -> list[Finding]:
    return scan("go", context)


@pytest.fixture(scope="module")
def java_findings(context: ScanContext) -> list[Finding]:
    return scan("java", context)


def usages(findings: list[Finding], rule_prefix: str) -> set[str]:
    return {f.usage for f in findings if rule_id_of(f).startswith(rule_prefix)}


def line_of(finding: Finding) -> int:
    return int(finding.evidence.occurrences[0].locator.rpartition(":")[2])


# ---------------------------------------------------------------------------
# THE BUG: a verifier reported as a signer
# ---------------------------------------------------------------------------


def test_a_python_jwt_verifier_is_not_reported_as_a_signer(
    python_findings: list[Finding],
) -> None:
    """`jwt.decode` VERIFIES. It was reported `usage: sign`.

    The consequence was a signing migration recommended for every token
    verifier in an estate -- and a verifier is the side that must move FIRST,
    since nothing can accept an ML-DSA token until its verifier does.
    """
    verify = [f for f in python_findings if rule_id_of(f) == "py-jwt-rsa-verify"]
    assert verify, "no verify rule fired on jwt.decode"
    assert {f.usage for f in verify} == {"verify"}


def test_a_js_jwt_verifier_is_not_reported_as_a_signer(
    js_findings: list[Finding],
) -> None:
    verify = [f for f in js_findings if rule_id_of(f) == "js-jwt-rsa-verify"]
    assert verify, "no verify rule fired on jwt.verify"
    assert {f.usage for f in verify} == {"verify"}


def test_the_signing_site_is_still_reported_as_signing(
    python_findings: list[Finding], js_findings: list[Finding]
) -> None:
    """Splitting verify out must not cost the sign case."""
    assert "sign" in usages(python_findings, "py-jwt-rsa")
    assert "sign" in usages(js_findings, "js-jwt-rsa")


# ---------------------------------------------------------------------------
# API-LEVEL MAPPINGS, per language
# ---------------------------------------------------------------------------


def test_python_key_transport_and_key_exchange_are_named(
    python_findings: list[Finding],
) -> None:
    """RSA-as-a-cipher is key TRANSPORT; ECDH is key EXCHANGE.

    Both were absent from the Python pack entirely -- an RSA key-wrapping site
    produced no finding at all, so the artefact that most needs ML-KEM was the
    one the inventory did not have.
    """
    transport = [f for f in python_findings if rule_id_of(f) == "py-rsa-key-transport"]
    assert transport, "RSA key wrapping produced no finding"
    assert {f.usage for f in transport} == {"key-transport"}

    exchange = [f for f in python_findings if rule_id_of(f) == "py-ecdh-exchange"]
    assert exchange, "ECDH agreement produced no finding"
    assert {f.usage for f in exchange} == {"key-exchange"}


def test_go_key_transport_and_verify_are_named(go_findings: list[Finding]) -> None:
    by_rule = {rule_id_of(f): f for f in go_findings}
    assert by_rule["go-rsa-key-transport"].usage == "key-transport"
    assert by_rule["go-rsa-verify"].usage == "verify"


def test_java_wrap_mode_is_key_transport(java_findings: list[Finding]) -> None:
    """The transformation string is identical for wrapping and for encrypting.

    `Cipher.WRAP_MODE` is the only thing that distinguishes them, so without
    reading the init mode a key-wrapping site is recommended bulk-encryption
    advice.
    """
    wrap = [f for f in java_findings if rule_id_of(f) == "java-cipher-wrap-mode"]
    assert wrap, "Cipher.WRAP_MODE produced no finding"
    assert {f.usage for f in wrap} == {"key-transport"}


def test_js_key_transport_and_key_exchange_are_named(
    js_findings: list[Finding],
) -> None:
    by_rule = {rule_id_of(f): f for f in js_findings}
    assert by_rule["js-rsa-key-transport"].usage == "key-transport"
    assert by_rule["js-ecdh-exchange"].usage == "key-exchange"


# ---------------------------------------------------------------------------
# USE-SITE REFINEMENT (Python), and the honest unknown
# ---------------------------------------------------------------------------


def test_a_keygen_used_for_signing_refines_to_sign(
    python_findings: list[Finding],
) -> None:
    """ADR-0004 promised the correlator would refine this. Nothing did, until now.

    The keygen call itself cannot know: a fresh RSA key may sign or transport.
    The use site in the same function can, and the refinement lands on the
    KEYGEN finding rather than creating a second one.
    """
    keygen = [
        f
        for f in python_findings
        if rule_id_of(f) == "py-rsa-keygen" and f.params.get("key_size") == 2048
    ]
    assert len(keygen) == 1, [f.params for f in keygen]
    assert keygen[0].usage == "sign"


def test_a_keygen_used_for_wrapping_refines_to_key_transport(
    python_findings: list[Finding],
) -> None:
    keygen = [
        f
        for f in python_findings
        if rule_id_of(f) == "py-rsa-keygen" and f.params.get("key_size") == 3072
    ]
    assert len(keygen) == 1
    assert keygen[0].usage == "key-transport"


def test_a_keygen_with_no_visible_use_site_stays_unknown(
    python_findings: list[Finding],
) -> None:
    """The honest case, and the one that must not be quietly improved.

    Taint and `pattern-inside` are intra-procedural in the OSS build, so a key
    returned to a caller has no visible use. Guessing would put a confidently
    wrong PQC target on a real key; the engine already gives usage-agnostic
    advice for exactly this.
    """
    keygen = [
        f
        for f in python_findings
        if rule_id_of(f) == "py-rsa-keygen" and f.params.get("key_size") == 4096
    ]
    assert len(keygen) == 1
    assert keygen[0].usage == "unknown"


def test_the_refinement_does_not_add_a_second_finding(
    python_findings: list[Finding],
) -> None:
    """Refinement is an ANNOTATION on an existing artefact, not a new one.

    A second finding would double-count the key, and the two would carry
    different `usage` and therefore different identities -- so they would not
    even merge.
    """
    per_line: dict[int, int] = {}
    for finding in python_findings:
        if rule_id_of(finding) == "py-rsa-keygen":
            per_line[line_of(finding)] = per_line.get(line_of(finding), 0) + 1
    assert set(per_line.values()) == {1}, per_line


# ---------------------------------------------------------------------------
# THE RECOMMENDATION SHARPENS — engine unchanged, pack conditions on usage
# ---------------------------------------------------------------------------


def rsa_finding(usage: str) -> Finding:
    return Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="pke",
        algorithm="RSA",
        params={"key_size": 2048},
        usage=usage,  # type: ignore[arg-type]
        evidence=Evidence(
            occurrences=[
                Occurrence(view="declared", locator="app/k.py:1", detail="rule=r")
            ]
        ),
    )


def advice(usage: str) -> str:
    target = Target(
        kind="repo",
        ref="/srv/app",
        system="s",
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )
    _, cbom = normalise([rsa_finding(usage)], target)
    scored = apply_policy(
        cbom,
        default_packs(),
        inputs=ScoreInputs(
            data_class="Personal",
            sector="bfsi",
            exposure="internet",
            knowledge_dir=KNOWLEDGE_DIR,
        ),
    )
    component = json.loads(scored)["components"][0]
    return " ".join(
        p["value"] for p in component["properties"] if p["name"] == "ecdat:actions"
    )


def test_rsa_for_signing_is_recommended_ml_dsa() -> None:
    text = advice("sign")
    assert "ML-DSA" in text, text
    assert "ML-KEM" not in text, "a signing key was recommended a KEM"


def test_rsa_for_key_transport_is_recommended_ml_kem() -> None:
    text = advice("key-transport")
    assert "ML-KEM" in text, text
    assert "ML-DSA" not in text, "a key-transport key was recommended a signature"


def test_rsa_for_key_exchange_is_recommended_ml_kem() -> None:
    text = advice("key-exchange")
    assert "ML-KEM" in text, text
    # The OTHER target must be absent. Presence alone passed on the pre-ADR-0030
    # pack, whose single RSA action named every option -- a vacuous pass.
    assert "ML-DSA" not in text, "a key-exchange key was recommended a signature"


def test_rsa_for_verification_is_recommended_ml_dsa() -> None:
    """A verifier migrates to the same family it must accept."""
    text = advice("verify")
    assert "ML-DSA" in text, text
    # Same vacuous-pass gap as above, closed the same way.
    assert "ML-KEM" not in text, "a verifier was recommended a KEM"


def test_rsa_with_unknown_usage_gets_the_usage_agnostic_advice() -> None:
    """Both targets named, because the tool does not know which applies.

    This is the correct output for an unknown usage, and it is why guessing is
    worse than admitting: the reader is told the decision is theirs and what it
    turns on.
    """
    text = advice("unknown")
    assert "ML-KEM" in text and "ML-DSA" in text, text


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_usage_classification_is_deterministic(context: ScanContext) -> None:
    import datetime as dt
    import uuid

    root = USAGE_ROOT / "py"
    target = Target(kind="directory", ref=str(root), system="usage-py")
    fixed: dict[str, Any] = {
        "serial_number": uuid.UUID(int=0),
        "timestamp": dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    }
    first = normalise(list(SourceScanner().scan(target, context)), target, **fixed)[1]
    second = normalise(list(SourceScanner().scan(target, context)), target, **fixed)[1]
    assert first == second
