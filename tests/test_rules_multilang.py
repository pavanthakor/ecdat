"""Both packs at once: one repo, three languages, one CBOM (ADR-0023).

Part A and Part B are scored separately on purpose. This file asserts the two
things that only make sense *together*:

* a repo carrying Go **and** JS **and** Python produces one schema-valid CBOM
  with findings from all of them, all in the `declared` view — the packs are
  additive, not alternatives;
* QuantumBank's Go gateway, which ADR-0004 recorded as a KNOWN GAP and the KPI
  harness excluded from its denominator, is now genuinely detected.

That second one is the point of the slice. A known gap that closes has to move
out of the exclusion list and into the scored set, or the number goes up without
anything having been found.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from core.normalise import normalise, validate_cbom_json
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import rule_id_of

QUANTUMBANK = Path("testdata/quantumbank")
GATEWAY = "services/gateway/sign.go"
KNOWLEDGE_DIR = Path("knowledge")


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("ml-scratch")
    )


# ---------------------------------------------------------------------------
# One repo, three languages, one CBOM
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mixed_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A repo carrying Go, JavaScript, TypeScript and Python side by side."""
    root = tmp_path_factory.mktemp("mixed-repo")
    (root / "sign.go").write_text(
        "package main\n\n"
        'import (\n\t"crypto/rand"\n\t"crypto/rsa"\n)\n\n'
        "func Key() (*rsa.PrivateKey, error) {\n"
        "\treturn rsa.GenerateKey(rand.Reader, 2048)\n}\n",
        encoding="utf-8",
    )
    (root / "hash.js").write_text(
        'const crypto = require("crypto");\n'
        'function f(d) { return crypto.createHash("md5").update(d).digest("hex"); }\n'
        "module.exports = { f };\n",
        encoding="utf-8",
    )
    (root / "keys.ts").write_text(
        'import * as crypto from "crypto";\n'
        "export function k(cb: (e: Error | null) => void): void {\n"
        '  crypto.generateKeyPair("ec", { namedCurve: "P-256" }, cb);\n}\n',
        encoding="utf-8",
    )
    (root / "legacy.py").write_text(
        "import hashlib\n\n\ndef digest(data: bytes) -> str:\n"
        "    return hashlib.sha1(data).hexdigest()\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture(scope="module")
def mixed_findings(mixed_repo: Path, context: ScanContext) -> list[Finding]:
    target = Target(kind="repo", ref=str(mixed_repo), system="mixed")
    return list(SourceScanner().scan(target, context))


def test_one_repo_yields_findings_from_go_js_ts_and_python(
    mixed_findings: list[Finding],
) -> None:
    by_extension = {
        Path(f.evidence.occurrences[0].locator.rpartition(":")[0]).suffix
        for f in mixed_findings
    }
    assert {".go", ".js", ".ts", ".py"} <= by_extension, (
        f"a language produced nothing; saw {sorted(by_extension)}"
    )


def test_the_mixed_repo_produces_a_schema_valid_cbom(
    mixed_repo: Path, mixed_findings: list[Finding]
) -> None:
    target = Target(kind="repo", ref=str(mixed_repo), system="mixed")
    _, cbom_json = normalise(mixed_findings, target)
    validate_cbom_json(cbom_json)

    document = json.loads(cbom_json)
    names = {component["name"] for component in document["components"]}
    # One from each language, so the CBOM proves the packs are additive.
    assert "RSA-2048" in names, sorted(names)
    assert "MD5" in names, sorted(names)
    assert "SHA-1" in names, sorted(names)
    # The normaliser names an EC component by its curve, so the TypeScript
    # keypair lands as `ECDSA-P-256` -- the captured curve reaching the CBOM.
    assert "ECDSA-P-256" in names, sorted(names)


def test_every_multilang_finding_is_in_the_declared_view(
    mixed_findings: list[Finding],
) -> None:
    assert mixed_findings
    for finding in mixed_findings:
        assert finding.view == "declared"
        for occurrence in finding.evidence.occurrences:
            assert occurrence.view == "declared"


# ---------------------------------------------------------------------------
# The QuantumBank Go gap, closed
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def quantumbank_findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="repo", ref=str(QUANTUMBANK), system="quantumbank")
    return list(SourceScanner().scan(target, context))


def _gateway(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if GATEWAY in f.evidence.occurrences[0].locator]


def test_the_quantumbank_go_gateway_is_no_longer_invisible(
    quantumbank_findings: list[Finding],
) -> None:
    """ADR-0004's known gap: real crypto in a real service that ECDAT could not see."""
    hits = _gateway(quantumbank_findings)
    assert hits, f"{GATEWAY} still produces no findings; the Go gap is not closed"


def test_the_gateway_ecdsa_p256_key_is_detected(
    quantumbank_findings: list[Finding],
) -> None:
    ecdsa = [f for f in _gateway(quantumbank_findings) if f.algorithm == "ECDSA"]
    assert ecdsa, "the gateway's ECDSA P-256 signing key was not detected"
    assert any(f.params.get("curve") == "P256" for f in ecdsa), [
        f.params for f in ecdsa
    ]
    assert all(f.primitive == "signature" for f in ecdsa)


def test_the_gateway_embedded_certificate_is_detected_and_redacted(
    quantumbank_findings: list[Finding],
) -> None:
    certs = [f for f in _gateway(quantumbank_findings) if f.asset_type == "certificate"]
    assert certs, "the gateway's embedded PEM certificate was not detected"
    for finding in certs:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == "<redacted key material>"


def test_no_quantumbank_secret_reaches_a_finding(
    quantumbank_findings: list[Finding],
) -> None:
    """The Go gateway's PEM body carries NOTAREALCERT."""
    blob = json.dumps([f.model_dump() for f in quantumbank_findings], default=str)
    for sentinel in ("NOTAREALCERT", "NOTAREALKEY", "SECRETSENTINEL"):
        assert sentinel not in blob, f"{sentinel!r} escaped into a QuantumBank finding"


def test_the_answer_key_no_longer_marks_the_go_gateway_as_a_known_gap() -> None:
    """The exclusion has to be REMOVED, not merely satisfied.

    A gap that closes but stays in the exclusion list means the KPI denominator
    never grows, and the score improves without anything having been found.
    """
    with (QUANTUMBANK / "answer_key.yaml").open(encoding="utf-8") as handle:
        key: dict[str, Any] = yaml.safe_load(handle)

    gateway_entries = [
        entry
        for entry in key["findings"]
        if GATEWAY in str(entry.get("locator_contains", ""))
    ]
    assert gateway_entries, "the gateway entries vanished from the answer key"
    for entry in gateway_entries:
        assert not entry.get("known_gap", False), (
            f"{entry['id']} is still marked known_gap; the Go rules detect it now, "
            "so it belongs in the scored denominator"
        )


def test_go_rules_do_not_disturb_the_python_quantumbank_findings(
    quantumbank_findings: list[Finding],
) -> None:
    """Adding a language must not change what the Python pack already reported."""
    python_hits = [
        f
        for f in quantumbank_findings
        if f.evidence.occurrences[0].locator.rpartition(":")[0].endswith(".py")
    ]
    assert python_hits, "the Python findings disappeared when Go rules were added"
    assert all(rule_id_of(f).startswith("py-") for f in python_hits)
