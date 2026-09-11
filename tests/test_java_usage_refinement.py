"""ADR-0037 PART C -- a Java verifier is inventoried as a VERIFIER.

`Signature.getInstance("SHA256withRSA")` names the algorithm and NOT the
direction: `initSign` or `initVerify` sets that later. The Java signature rules
reported `usage: sign` at getInstance for every Signature, so each verifier in
an estate was inventoried as a signer -- and the "migrate the VERIFIERS first"
advice (policy/packs/quantum.yaml) could never point at one. ADR-0030 fixed the
same bug class for Python and JS JWT verifiers and left Java open.

Now the signature rules declare their `sign` a DEFAULT (`usage_refinable`), and
two annotation rules read the direction off the same method's `initVerify` /
`verify` or `initSign` / `sign`: the ADR-0030 mechanism. ADR-0037's STEP 0
measured what OSS semgrep 1.176.1 can see -- a typed declaration or a later
assignment, then a call on the SAME variable in the same method -- and that is
exactly what these fixtures exercise.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

import scanners.source as source
from core.normalise import normalise
from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence
from policy.apply import ScoreInputs, apply_policy
from policy.engine import default_packs
from scanners.source import SourceScanner
from tests.rulepack import relative_path_of, rule_id_of

JAVA_ROOT = Path("testdata/java_fixtures")
KNOWLEDGE_DIR = Path("knowledge")
SIGNATURE_RULES = KNOWLEDGE_DIR / "rules" / "java" / "signatures.yaml"

VERIFIER = "must_fire/JavaSignatureVerifier.java"
ASSIGNED_VERIFIER = "must_fire/JavaSignatureWeakVerifier.java"
SIGNER = "must_fire/JavaSignatureSigner.java"
UNRELATED = "must_fire/JavaSignatureUnrelatedVerify.java"
#: getInstance returned to a caller: no visible use in the method.
NO_USE = {
    "must_fire/JavaSignatureRsa.java": "java-signature-rsa",
    "must_fire/JavaSignatureEcdsa.java": "java-signature-ecdsa",
    "must_fire/JavaSignatureSha1Rsa.java": "java-signature-weak-hash",
}
#: The rules whose `sign` is a default that a use site may replace.
REFINABLE = {"java-signature-weak-hash", "java-signature-rsa", "java-signature-ecdsa"}


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR,
        scratch_dir=tmp_path_factory.mktemp("java-usage-scratch"),
    )


def _scan(root: Path, context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(root), system="java-usage")
    return list(SourceScanner().scan(target, context))


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    return _scan(JAVA_ROOT, context)


def in_fixture(findings: list[Finding], fixture: str, rule: str) -> list[Finding]:
    return [
        f
        for f in findings
        if relative_path_of(f, JAVA_ROOT) == fixture and rule_id_of(f) == rule
    ]


def site_of(finding: Finding) -> tuple[str, int]:
    path, _, line = finding.evidence.occurrences[0].locator.rpartition(":")
    return path, int(line)


# ---------------------------------------------------------------------------
# The mislabel, fixed
# ---------------------------------------------------------------------------


def test_a_java_verifier_is_refined_to_verify(findings: list[Finding]) -> None:
    (verifier,) = in_fixture(findings, VERIFIER, "java-signature-rsa")

    assert verifier.usage == "verify"
    # And the verify side now carries the ALGORITHM, which java-signature-verify
    # at initVerify cannot know.
    assert (verifier.algorithm, verifier.params["transformation"]) == (
        "RSA",
        "SHA256withRSA",
    )


def test_a_verifier_declared_then_assigned_is_refined_too(
    findings: list[Finding],
) -> None:
    (weak,) = in_fixture(findings, ASSIGNED_VERIFIER, "java-signature-weak-hash")

    assert weak.usage == "verify"
    assert weak.params.get("flagged") is True, "refining must not drop the SHA-1 flag"


def test_a_java_signer_is_positively_identified_as_a_signer(
    context: ScanContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`sign` is also the default, so the use site's verdict is asserted
    directly: the annotation named this line a signer, it was not merely left
    alone."""
    seen: dict[tuple[str, int], str] = {}
    real = source._usage_annotations

    def recording(annotations: Any) -> dict[tuple[str, int], str]:
        chosen = real(annotations)
        seen.update(chosen)
        return chosen

    monkeypatch.setattr(source, "_usage_annotations", recording)
    shutil.copy(JAVA_ROOT / SIGNER, tmp_path / Path(SIGNER).name)

    (signer,) = [
        f for f in _scan(tmp_path, context) if rule_id_of(f) == "java-signature-ecdsa"
    ]

    assert signer.usage == "sign"
    assert seen.get(site_of(signer)) == "sign", seen


def test_a_signature_with_no_visible_use_keeps_its_default(
    findings: list[Finding],
) -> None:
    """Returned to a caller: OSS semgrep cannot follow it (STEP 0), so the rule's
    default stands -- as it did before. Nothing is guessed either way."""
    for fixture, rule in NO_USE.items():
        (finding,) = in_fixture(findings, fixture, rule)
        assert finding.usage == "sign", fixture


def test_a_verify_on_a_different_signature_does_not_refine(
    findings: list[Finding],
) -> None:
    (fresh,) = in_fixture(findings, UNRELATED, "java-signature-rsa")

    assert fresh.usage == "sign"


def test_the_refinement_adds_no_finding(findings: list[Finding]) -> None:
    """An annotation corrects an artefact; it is never a second one."""
    in_verifier = sorted(
        rule_id_of(f) for f in findings if relative_path_of(f, JAVA_ROOT) == VERIFIER
    )

    assert in_verifier == ["java-signature-rsa", "java-signature-verify"]
    assert not [f for f in findings if "used-for" in rule_id_of(f)]


# ---------------------------------------------------------------------------
# The contract: only a DEFAULT is refinable
# ---------------------------------------------------------------------------


def _finding(usage: str) -> Finding:
    return Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="signature",
        algorithm="RSA",
        usage=usage,  # type: ignore[arg-type]
        evidence=Evidence(
            occurrences=[Occurrence(view="declared", locator="A.java:1", detail="r")]
        ),
    )


def _result(**metadata: Any) -> dict[str, Any]:
    return {"extra": {"metadata": metadata}}


def test_a_usage_read_off_the_api_is_never_overridden() -> None:
    """A rule that READ its usage off the call (`initVerify`, `WRAP_MODE`) is
    better evidence than a use site. Only `unknown`, or a usage the rule itself
    declared a default, may be replaced."""
    assert source._refinable(_finding("unknown"), _result(usage="unknown"))
    assert source._refinable(
        _finding("sign"), _result(usage="sign", usage_refinable=True)
    )
    assert not source._refinable(_finding("sign"), _result(usage="sign"))
    assert not source._refinable(_finding("verify"), _result(usage="verify"))


def test_a_malformed_refinable_flag_is_a_contract_error() -> None:
    with pytest.raises(source.RulePackContractError):
        source._refinable(
            _finding("sign"), _result(usage="sign", usage_refinable="yes")
        )


def test_exactly_the_getinstance_signature_rules_declare_a_refinable_default() -> None:
    """The flag must not spread: each rule carrying it is one whose usage is a
    guess from the call's CONTEXT, and every such Java rule carries it."""
    rules = yaml.safe_load(SIGNATURE_RULES.read_text(encoding="utf-8"))["rules"]
    refinable = {r["id"] for r in rules if r["metadata"].get("usage_refinable") is True}
    at_getinstance = {
        r["id"]
        for r in rules
        if "Signature.getInstance" in yaml.safe_dump(r)
        and r["metadata"].get("usage") == "sign"
    }

    assert refinable == REFINABLE
    assert at_getinstance == REFINABLE


# ---------------------------------------------------------------------------
# What it is for: the verifier-first advice can find a Java verifier
# ---------------------------------------------------------------------------


def test_a_java_verifier_reaches_the_cbom_as_a_verifier_with_its_advice(
    findings: list[Finding],
) -> None:
    (verifier,) = in_fixture(findings, VERIFIER, "java-signature-rsa")
    target = Target(
        kind="repo",
        ref=str(JAVA_ROOT),
        system="java",
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )

    _, cbom = normalise([verifier], target)
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

    (component,) = json.loads(scored)["components"]
    properties = component["properties"]
    usage = [p["value"] for p in properties if p["name"] == "ecdat:usage"]
    actions = " ".join(p["value"] for p in properties if p["name"] == "ecdat:actions")
    assert usage == ["verify"]
    assert "ML-DSA" in actions and "ML-KEM" not in actions, actions
    assert "Migrate the VERIFIERS first" in actions


def test_the_refinement_is_deterministic(
    findings: list[Finding], context: ScanContext
) -> None:
    def verdicts(items: list[Finding]) -> list[tuple[str, str, str]]:
        return sorted(
            (relative_path_of(f, JAVA_ROOT), rule_id_of(f), f.usage) for f in items
        )

    assert verdicts(_scan(JAVA_ROOT, context)) == verdicts(findings)
