"""ADR-0034 -- a hard-coded-key finding needs CORROBORATION, in all four packs.

Scanning OWASP Juice Shop exposed a real false-positive class. The
`*-hardcoded-key` rules were NAME-scoped: any key-ish identifier holding a
string literal of eight characters or more was reported as hard-coded key
material, at full confidence. On real front-end code that meant five Angular
storage, cookie and config strings, and the same imprecision sat in the Go, JS
and Java packs (Python never had a name-scoped rule; its key rule was already
anchored at the cipher).

A key-ish name is not evidence. The corroboration model:

    shape: a PEM block or a DER blob  -> fires, confidence 1.0
    the literal reaches a key, IV,    -> fires, confidence 1.0
      HMAC or signing parameter
      (intra-procedural taint)
    a key-ish name + a high-entropy   -> fires, confidence 0.5, `candidate`
      32+ character literal, and
      nothing else
    a bare key-ish string             -> does NOT fire

These tests pin each branch in each language, the Juice Shop false positives
closed and its PEM kept, redaction, determinism, the scanner mechanics the model
needs (a rule-declared confidence, the holder link, candidate folding) and the
pack-wide invariants ADR-0034's STEP 0 measured.
"""

from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

import scanners.source as source
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import REDACTED, RulePackContractError, SourceScanner
from tests.rulepack import (
    PackAnswers,
    load_answers,
    relative_path_of,
    rule_id_of,
    score,
)

KNOWLEDGE_DIR = Path("knowledge")
RULES_DIR = KNOWLEDGE_DIR / "rules"

#: What every candidate rule declares. Below every binary-scanner technique
#: (the weakest, `constant`, is 0.6): a name and a shape are less evidence than
#: a byte table.
CANDIDATE_CONFIDENCE = 0.5

#: A holder is the IDENTIFIER that held a literal -- never the literal.
IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*")


@dataclass(frozen=True)
class Pack:
    """One language pack's ADR-0034 fixtures, and what each must produce."""

    language: str
    prefix: str
    root: Path
    #: The rule ids of the SINK branch. Python's AES rule keeps its id and its
    #: `algorithm: AES`; its sibling covers every other key parameter.
    sink_rules: frozenset[str]
    sink_fixture: str
    #: The holder each sink finding in `sink_fixture` records. `None` is the
    #: literal written inline at the sink, which no variable holds.
    sink_holders: frozenset[str | None]
    #: The high-entropy holder that ALSO matches the candidate rule, and the
    #: line it is declared on: its candidate must be folded, not doubled.
    folded_holder: str
    folded_line: int
    der_fixture: str
    pem_rule: str
    pem_fixture: str
    candidate_fixture: str
    plain_fixture: str
    near_miss_fixture: str
    #: A KDF salt and an assembled key that reach a cipher without being the key.
    derived_fixture: str
    #: The pre-ADR-0034 key-to-cipher fixture, which must not regress.
    existing_fixture: str
    existing_rule: str
    existing_count: int
    #: Planted in this slice's fixtures; each must be listed in the answer key.
    sentinels: tuple[str, ...]

    @property
    def der_rule(self) -> str:
        return f"{self.prefix}-hardcoded-key-der"

    @property
    def candidate_rule(self) -> str:
        return f"{self.prefix}-hardcoded-key-candidate"

    @property
    def key_family(self) -> re.Pattern[str]:
        """Every rule in this pack that matches key material and must redact."""
        return re.compile(rf"{self.prefix}-(?:hardcoded-|pem-|assembled-key)")


PACKS = (
    Pack(
        language="python",
        prefix="py",
        root=Path("testdata/python_fixtures"),
        sink_rules=frozenset({"py-hardcoded-key", "py-hardcoded-cipher-key"}),
        sink_fixture="must_fire/py_key_reaches_sink.py",
        sink_holders=frozenset({"WEBHOOK_KEY", None, "fernet_key"}),
        folded_holder="WEBHOOK_KEY",
        folded_line=14,
        der_fixture="must_fire/py_der_key.py",
        pem_rule="py-pem-private-key",
        pem_fixture="must_fire/py_pem_private_key.py",
        candidate_fixture="must_fire/py_key_candidate.py",
        plain_fixture="must_not_fire/py_plain_key_strings.py",
        near_miss_fixture="must_not_fire/py_key_near_misses.py",
        derived_fixture="must_fire/py_key_derived_not_hardcoded.py",
        existing_fixture="must_fire/py_hardcoded_cipher_key.py",
        existing_rule="py-hardcoded-cipher-key",
        existing_count=1,
        sentinels=(
            "PYSINKSENTINEL",
            "PYDERSENTINEL",
            "955e9a9751dca0fd",
            "5311553b827b1eb7",
            "d1747741165638f9",
        ),
    ),
    Pack(
        language="go",
        prefix="go",
        root=Path("testdata/go_fixtures"),
        sink_rules=frozenset({"go-hardcoded-key"}),
        sink_fixture="must_fire/go_key_reaches_sink.go",
        sink_holders=frozenset({"webhookKey", None, "signingSecret"}),
        folded_holder="webhookKey",
        folded_line=16,
        der_fixture="must_fire/go_der_key.go",
        pem_rule="go-pem-block",
        pem_fixture="must_fire/go_pem_private_key.go",
        candidate_fixture="must_fire/go_key_candidate.go",
        plain_fixture="must_not_fire/go_plain_key_strings.go",
        near_miss_fixture="must_not_fire/go_key_near_misses.go",
        derived_fixture="must_not_fire/go_key_near_misses.go",
        existing_fixture="must_fire/go_hardcoded_key.go",
        existing_rule="go-hardcoded-key",
        existing_count=2,
        sentinels=(
            "GOSINKSENTINEL",
            "GODERSENTINEL",
            "954649cdbbb849fa",
            "01ee996b12ef5fc9",
            "c68f7163878626ee",
        ),
    ),
    Pack(
        language="javascript",
        prefix="js",
        root=Path("testdata/js_fixtures"),
        sink_rules=frozenset({"js-hardcoded-key"}),
        sink_fixture="must_fire/js_key_reaches_sink.js",
        sink_holders=frozenset({"webhookKey", None, "rawKey"}),
        folded_holder="webhookKey",
        folded_line=11,
        der_fixture="must_fire/js_der_key.js",
        pem_rule="js-pem-block",
        pem_fixture="must_fire/js_pem_private_key.js",
        candidate_fixture="must_fire/js_key_candidate.js",
        plain_fixture="must_not_fire/ts_plain_key_strings.ts",
        near_miss_fixture="must_not_fire/js_key_near_misses.js",
        derived_fixture="must_fire/js_key_derived_not_hardcoded.js",
        existing_fixture="must_fire/js_hardcoded_key.js",
        existing_rule="js-hardcoded-key",
        existing_count=2,
        sentinels=(
            "JSSINKSENTINEL",
            "TSSINKSENTINEL",
            "JSDERSENTINEL",
            "e624c0021fe5c931",
            "e551cb2cae989987",
            "6949b268dc2426f5",
        ),
    ),
    Pack(
        language="java",
        prefix="java",
        root=Path("testdata/java_fixtures"),
        sink_rules=frozenset({"java-hardcoded-key"}),
        sink_fixture="must_fire/JavaKeyReachesSink.java",
        sink_holders=frozenset({"WEBHOOK_KEY", None, "keyBytes"}),
        folded_holder="WEBHOOK_KEY",
        folded_line=13,
        der_fixture="must_fire/JavaDerKey.java",
        pem_rule="java-pem-block",
        pem_fixture="must_fire/JavaPemPrivateKey.java",
        candidate_fixture="must_fire/JavaKeyCandidate.java",
        plain_fixture="must_not_fire/JavaPlainKeyStrings.java",
        near_miss_fixture="must_not_fire/JavaKeyNearMisses.java",
        derived_fixture="must_not_fire/JavaKeyNearMisses.java",
        existing_fixture="must_fire/JavaHardcodedKey.java",
        existing_rule="java-hardcoded-key",
        existing_count=2,
        sentinels=(
            "JAVASINKSENTINEL",
            "JAVADERSENTINEL",
            "f7ef507df605238c",
            "f729627e7d795964",
            "a1c20c2b1b7f5b48",
        ),
    ),
)
PACK_IDS = [pack.language for pack in PACKS]
BY_LANGUAGE = {pack.language: pack for pack in PACKS}


def _scan(root: Path, scratch: Path, knowledge: Path = KNOWLEDGE_DIR) -> list[Finding]:
    context = ScanContext(knowledge_dir=knowledge, scratch_dir=scratch)
    target = Target(kind="directory", ref=str(root), system=f"adr34-{root.name}")
    return list(SourceScanner().scan(target, context))


@pytest.fixture(scope="module")
def scans(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[Finding]]:
    scratch = tmp_path_factory.mktemp("adr34-packs")
    return {pack.language: _scan(pack.root, scratch) for pack in PACKS}


def _in(scans: dict[str, list[Finding]], pack: Pack, fixture: str) -> list[Finding]:
    return [
        f for f in scans[pack.language] if relative_path_of(f, pack.root) == fixture
    ]


def _line(locator: str) -> int:
    return int(locator.rpartition(":")[2])


# ---------------------------------------------------------------------------
# Branch 1 -- the literal reaches a key parameter: confidence 1.0
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_literal_that_reaches_a_key_parameter_fires_at_full_confidence(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """A module constant, an inline literal and a wrapped local -- one each."""
    hits = [
        f
        for f in _in(scans, pack, pack.sink_fixture)
        if rule_id_of(f) in pack.sink_rules
    ]
    assert len(hits) == 3, [(rule_id_of(f), f.raw.get("holder")) for f in hits]
    for finding in hits:
        assert finding.confidence == 1.0
        assert finding.params.get("flagged") is True
        assert "candidate" not in finding.params
        assert finding.asset_type == "key"
    assert {f.raw.get("holder") for f in hits} == pack.sink_holders


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_the_pre_adr_0034_key_to_cipher_fixture_still_fires(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """No regression: the key (and IV) literals feeding a cipher still fire."""
    hits = [
        f
        for f in _in(scans, pack, pack.existing_fixture)
        if rule_id_of(f) == pack.existing_rule
    ]
    assert len(hits) == pack.existing_count
    assert all(f.confidence == 1.0 for f in hits)


def test_an_angular_class_field_that_reaches_a_key_parameter_still_fires(
    scans: dict[str, list[Finding]],
) -> None:
    """The Juice Shop declaration SHAPE, with a sink: this one is key material."""
    js = BY_LANGUAGE["javascript"]
    hits = [
        f
        for f in _in(scans, js, "must_fire/ts_key_reaches_sink.ts")
        if rule_id_of(f) == "js-hardcoded-key"
    ]
    assert len(hits) == 1
    assert hits[0].raw.get("holder") == "signingKey"
    assert hits[0].confidence == 1.0


# ---------------------------------------------------------------------------
# Branch 2 -- PEM / DER shape: confidence 1.0
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_der_shaped_literal_fires_at_full_confidence_and_only_once(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    in_file = _in(scans, pack, pack.der_fixture)
    der = [f for f in in_file if rule_id_of(f) == pack.der_rule]
    assert len(der) == 1
    assert der[0].confidence == 1.0
    assert der[0].params.get("flagged") is True
    # The DER literal reaches a key parameter as well. The shape rule owns a
    # shaped literal, so neither the sink rule nor the candidate may report it.
    others = [rule_id_of(f) for f in in_file if f not in der]
    assert others == [], others


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_pem_block_still_fires_at_full_confidence(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    pem = [
        f for f in _in(scans, pack, pack.pem_fixture) if rule_id_of(f) == pack.pem_rule
    ]
    assert len(pem) == 1
    assert pem[0].confidence == 1.0


# ---------------------------------------------------------------------------
# Branch 3 -- entropy + length only: confidence 0.5, marked a candidate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_an_entropy_only_literal_is_a_low_confidence_candidate(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """A 32- and a 64-character hex literal, key-ish names, no sink."""
    in_file = _in(scans, pack, pack.candidate_fixture)
    assert {rule_id_of(f) for f in in_file} == {pack.candidate_rule}
    assert len(in_file) == 2
    for finding in in_file:
        assert finding.confidence == CANDIDATE_CONFIDENCE
        # Marked, so an analyst reads it as a candidate, not an assertion.
        assert finding.params.get("candidate") is True
        assert finding.params.get("flagged") is not True
        assert finding.asset_type == "key"
        for occurrence in finding.evidence.occurrences:
            assert occurrence.detail == f"rule={pack.candidate_rule}"
            assert occurrence.snippet == REDACTED


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_candidate_that_reaches_a_sink_is_folded_not_doubled(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """High entropy AND a sink: one finding at 1.0, carrying the declaration.

    The candidate rule really does match the declaration -- the folded
    occurrence it leaves on the sink finding is the proof -- and the scanner
    folds it because both name the same holder in the same file.
    """
    in_file = _in(scans, pack, pack.sink_fixture)
    assert [f for f in in_file if rule_id_of(f) == pack.candidate_rule] == []
    owners = [f for f in in_file if f.raw.get("holder") == pack.folded_holder]
    assert len(owners) == 1
    folded = [
        o
        for o in owners[0].evidence.occurrences
        if o.detail == f"rule={pack.candidate_rule}"
    ]
    assert len(folded) == 1, owners[0].evidence.occurrences
    assert _line(folded[0].locator) == pack.folded_line
    assert folded[0].snippet == REDACTED
    assert owners[0].confidence == 1.0


# ---------------------------------------------------------------------------
# Branch 4 -- a bare key-ish string: nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_plain_key_ish_string_produces_zero_findings(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """The Juice Shop class: storage keys, cookie names, headers, config."""
    hits = [
        (rule_id_of(f), f.evidence.occurrences[0].locator)
        for f in _in(scans, pack, pack.plain_fixture)
    ]
    assert hits == []


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_near_misses_produce_zero_findings(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """Each fails exactly one gate: name, length or entropy."""
    hits = [
        (rule_id_of(f), f.evidence.occurrences[0].locator)
        for f in _in(scans, pack, pack.near_miss_fixture)
    ]
    assert hits == []


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_derived_or_assembled_key_is_not_a_hardcoded_key(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    """A KDF salt and a constant prefix reach a cipher; neither IS the key."""
    hits = [
        rule_id_of(f)
        for f in _in(scans, pack, pack.derived_fixture)
        if rule_id_of(f) in pack.sink_rules | {pack.der_rule, pack.candidate_rule}
    ]
    assert hits == []


# ---------------------------------------------------------------------------
# Redaction -- a fired key never carries its bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_every_key_finding_is_redacted_and_no_sentinel_escapes(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    findings = scans[pack.language]
    material = [f for f in findings if pack.key_family.match(rule_id_of(f))]
    assert {rule_id_of(f) for f in material} >= {pack.der_rule, pack.candidate_rule}
    for finding in material:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == REDACTED, (rule_id_of(finding), occurrence)

    answers = load_answers(pack.root)
    assert set(pack.sentinels) <= set(answers.sentinels), (
        "the answer key must list this slice's sentinels, or the check below "
        "proves nothing about them"
    )
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in answers.sentinels:
        assert sentinel not in blob, (
            f"{sentinel!r} escaped into a {pack.language} Finding"
        )


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_a_holder_is_an_identifier_and_never_a_param(
    pack: Pack, scans: dict[str, list[Finding]]
) -> None:
    holders = [f.raw["holder"] for f in scans[pack.language] if f.raw.get("holder")]
    assert holders, "no finding recorded a holder"
    for holder in holders:
        assert IDENTIFIER.fullmatch(holder), holder
    for finding in scans[pack.language]:
        assert "holder" not in finding.params


# ---------------------------------------------------------------------------
# THE JUICE SHOP ACCEPTANCE TEST
# ---------------------------------------------------------------------------

MIRROR = Path("testdata/juiceshop_mirror")
MIRROR_ANSWERS: PackAnswers = load_answers(MIRROR)
JUICE_SHOP: dict[str, Any] = MIRROR_ANSWERS.raw["juice_shop"]

#: The js-hardcoded-key rule as it shipped before ADR-0034, verbatim but for
#: this comment. Vendored so the mirror's FIDELITY is a test: run over the
#: mirror, it must reproduce the real scan's findings site for site.
PRE_ADR_0034_JS_RULE = """
rules:
  - id: js-hardcoded-key
    languages: [javascript, typescript]
    severity: ERROR
    message: "ecdat|"
    metadata:
      algorithm: unknown
      primitive: unknown
      usage: unknown
      asset_type: key
      redact: true
      quantum_note: >-
        A key or IV written as a literal in source (CWE-321; NIST SP 800-57
        Part 1 Rev.5 s5.3). Vendored pre-ADR-0034 rule, for the fidelity test.
      flags: [key-material, critical]
    patterns:
      - pattern-either:
          - pattern: const $NAME = $LITERAL;
          - pattern: let $NAME = $LITERAL;
          - pattern: var $NAME = $LITERAL;
      - metavariable-regex:
          metavariable: $NAME
          regex: (?i).*(key|secret|iv|nonce|salt|passphrase|password|credential).*
      - metavariable-regex:
          metavariable: $LITERAL
          regex: ^["'][^"']{8,}["']$
"""


def _site(finding: Finding) -> tuple[str, int]:
    return (
        relative_path_of(finding, MIRROR),
        _line(finding.evidence.occurrences[0].locator),
    )


def _as_site(spelled: str) -> tuple[str, int]:
    path, _, line = spelled.rpartition(":")
    return (path, int(line))


@pytest.fixture(scope="module")
def mirror_findings(tmp_path_factory: pytest.TempPathFactory) -> list[Finding]:
    return _scan(MIRROR, tmp_path_factory.mktemp("adr34-mirror"))


def test_the_mirror_reproduces_the_real_scan_under_the_old_rule(
    tmp_path: Path,
) -> None:
    """Fidelity first: the pre-ADR-0034 rule fires on exactly what it did."""
    pack = tmp_path / "rules" / "javascript"
    pack.mkdir(parents=True)
    (pack / "keymaterial.yaml").write_text(PRE_ADR_0034_JS_RULE, encoding="utf-8")
    old = _scan(MIRROR, tmp_path, knowledge=tmp_path)

    expected = {_as_site(s) for s in JUICE_SHOP["false_positives"]}
    expected.add(_as_site(JUICE_SHOP["pem_true_positive"]))  # its double report
    assert len(expected) == 6
    assert sorted(_site(f) for f in old) == sorted(expected)


def test_the_five_juice_shop_false_positives_now_produce_zero_findings(
    mirror_findings: list[Finding],
) -> None:
    fp_files = {_as_site(s)[0] for s in JUICE_SHOP["false_positives"]}
    assert len(fp_files) == 5
    hits = [
        (_site(f), rule_id_of(f))
        for f in mirror_findings
        if relative_path_of(f, MIRROR) in fp_files
    ]
    assert hits == []


def test_the_juice_shop_pem_still_fires_and_is_reported_once(
    mirror_findings: list[Finding],
) -> None:
    """The true positive kept; the double report dropped.

    The PEM reaches jwt.sign and createHmac as well. The shape rule owns a
    shaped literal, so neither use produces a second, sink-rule finding.
    """
    pem_site = _as_site(JUICE_SHOP["pem_true_positive"])
    pem = [f for f in mirror_findings if _site(f) == pem_site]
    assert [rule_id_of(f) for f in pem] == ["js-pem-block"]
    assert pem[0].confidence == 1.0
    assert all(o.snippet == REDACTED for o in pem[0].evidence.occurrences)

    inline_site = _as_site(JUICE_SHOP["inline_key_true_positive"])
    key_sites = [
        _site(f)
        for f in mirror_findings
        if rule_id_of(f).startswith("js-hardcoded-key")
    ]
    assert key_sites == [inline_site]


def test_the_inline_hmac_key_the_old_rule_never_saw_is_found(
    mirror_findings: list[Finding],
) -> None:
    inline_site = _as_site(JUICE_SHOP["inline_key_true_positive"])
    hits = [f for f in mirror_findings if _site(f) == inline_site]
    assert [rule_id_of(f) for f in hits] == ["js-hardcoded-key"]
    assert hits[0].confidence == 1.0
    assert hits[0].raw.get("holder") is None  # no variable holds it


def test_the_mirror_scores_exactly_against_its_answer_key(
    mirror_findings: list[Finding], capsys: Any
) -> None:
    result = score(mirror_findings, MIRROR_ANSWERS)
    with capsys.disabled():
        print(result.report("JUICE SHOP MIRROR (ADR-0034)"))
    assert result.recall == 1.0, result.missed
    assert result.precision == 1.0, result.spurious

    for fixture, expectation in MIRROR_ANSWERS.cases:
        matched = [
            f
            for f in mirror_findings
            if relative_path_of(f, MIRROR) == fixture
            and rule_id_of(f) == expectation["rule_id"]
        ]
        for finding in matched:
            assert finding.algorithm == expectation["algorithm"]
            assert finding.primitive == expectation["primitive"]
            assert finding.usage == expectation["usage"]
            assert finding.asset_type == expectation["asset_type"]

    blob = json.dumps([f.model_dump() for f in mirror_findings], default=str)
    for sentinel in MIRROR_ANSWERS.sentinels:
        assert sentinel not in blob


# ---------------------------------------------------------------------------
# No regression -- QuantumBank's genuine key still fires
# ---------------------------------------------------------------------------


def test_quantumbank_genuine_hardcoded_key_still_fires(tmp_path: Path) -> None:
    """`FIELD_KEY = b"..."` feeding `AES.new` -- the real key-to-cipher case."""
    findings = _scan(Path("testdata/quantumbank/services/auth"), tmp_path)
    keys = [f for f in findings if rule_id_of(f) == "py-hardcoded-cipher-key"]
    assert len(keys) == 1
    key = keys[0]
    assert key.evidence.occurrences[0].locator.endswith("services/auth/vault.py:9")
    assert key.algorithm == "AES"
    assert key.confidence == 1.0
    assert key.params.get("flagged") is True
    assert all(o.snippet == REDACTED for o in key.evidence.occurrences)
    assert [f for f in findings if rule_id_of(f).endswith("-candidate")] == []


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_the_corroboration_model_is_deterministic(
    tmp_path: Path,
    scans: dict[str, list[Finding]],
    mirror_findings: list[Finding],
) -> None:
    """Same input + same packs -> the same findings, folds included."""
    js = BY_LANGUAGE["javascript"]
    again = _scan(js.root, tmp_path)
    assert [f.model_dump() for f in again] == [
        f.model_dump() for f in scans["javascript"]
    ]
    mirror_again = _scan(MIRROR, tmp_path)
    assert [f.model_dump() for f in mirror_again] == [
        f.model_dump() for f in mirror_findings
    ]


# ---------------------------------------------------------------------------
# The scanner mechanics the model needs (synthetic semgrep results)
# ---------------------------------------------------------------------------


def _result(
    rule_id: str,
    message: str,
    metadata: dict[str, Any],
    *,
    path: str = "app/keys.js",
    line: int = 3,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "algorithm": "unknown",
        "primitive": "unknown",
        "usage": "unknown",
        "asset_type": "key",
        "quantum_note": "synthetic rule (ADR-0034; CWE-321)",
        "redact": True,
    }
    base.update(metadata)
    return {
        "check_id": rule_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "extra": {"message": message, "metadata": base},
    }


def _finding(result: dict[str, Any]) -> Finding:
    return source._finding(result, {}, "source")


CANDIDATE_META: dict[str, Any] = {
    "holder_metavar": "$N",
    "confidence": "0.5",
    "flags": ["key-material", "candidate"],
}
SINK_META: dict[str, Any] = {
    "holder_metavar": "$HOLDER",
    "flags": ["key-material", "critical"],
}


def test_a_declared_confidence_caps_the_finding() -> None:
    finding = _finding(_result("x-rule", "ecdat|", {"confidence": "0.5"}))
    assert finding.confidence == 0.5


def test_without_a_declared_confidence_a_resolved_finding_stays_certain() -> None:
    assert _finding(_result("x-rule", "ecdat|", {})).confidence == 1.0


def test_a_declared_confidence_never_raises_a_heuristic_one() -> None:
    """A ceiling, not a setting: an unresolved capture (0.6) stays at 0.6."""
    finding = _finding(
        _result(
            "x-rule",
            "ecdat|key_size=configured_size",
            {"confidence": "0.9", "capture": {"key_size": "$SIZE"}},
        )
    )
    assert finding.confidence == 0.6


@pytest.mark.parametrize(
    "declared",
    ["high", "1.5", "0", "-0.2", "nan", "inf", "", 0.5, 1, True],
    ids=repr,
)
def test_an_invalid_declared_confidence_is_a_contract_error(declared: Any) -> None:
    """A string in (0, 1] -- semgrep 1.176.1 refuses a YAML float in a rule."""
    with pytest.raises(RulePackContractError):
        _finding(_result("x-rule", "ecdat|", {"confidence": declared}))


@pytest.mark.parametrize("declared", [None, "1.0", "1"])
def test_a_candidate_rule_must_declare_a_confidence_below_one(
    declared: str | None,
) -> None:
    """A rule may not call its finding a candidate and then claim certainty."""
    metadata: dict[str, Any] = {"flags": ["key-material", "candidate"]}
    if declared is not None:
        metadata["confidence"] = declared
    with pytest.raises(RulePackContractError):
        _finding(_result("x-candidate", "ecdat|", metadata))


def test_a_candidate_is_marked_and_not_flagged() -> None:
    finding = _finding(_result("x-candidate", "ecdat|holder=apiKey", CANDIDATE_META))
    assert finding.params == {"candidate": True}
    assert finding.confidence == 0.5


def test_the_holder_is_recorded_in_raw_and_never_in_params() -> None:
    finding = _finding(_result("x-sink", "ecdat|holder=moduleKey", SINK_META))
    assert finding.raw["holder"] == "moduleKey"
    assert "holder" not in finding.params
    assert "holder" not in finding.raw["captures"]


def test_an_unbound_holder_is_recorded_as_none() -> None:
    """The inline literal: semgrep leaves `$HOLDER` in the message verbatim."""
    finding = _finding(_result("x-sink", "ecdat|holder=$HOLDER", SINK_META))
    assert finding.raw["holder"] is None


@pytest.mark.parametrize(
    "captured",
    [
        '"SECRETSENTINEL0123456789"',
        "'SECRETSENTINEL'",
        "a b",
        "k+SECRETSENTINEL",
        "x=1",
    ],
)
def test_a_holder_that_is_not_an_identifier_is_discarded_and_stored_nowhere(
    captured: str,
) -> None:
    """Defence in depth against a binding that is not a name.

    STEP 0 measured semgrep substituting a BOUND metavariable into the message
    wherever its name prefixes an UNBOUND one (`$H` into `$HOLDER`). The packs
    are tested against that shape; this is the scanner refusing to keep
    anything that is not an identifier, should one ever arrive.
    """
    finding = _finding(_result("x-sink", f"ecdat|holder={captured}", SINK_META))
    assert finding.raw["holder"] is None
    blob = json.dumps(finding.model_dump(), default=str)
    assert "SECRETSENTINEL" not in blob
    assert captured not in blob


def test_a_declared_holder_the_message_does_not_carry_is_a_contract_error() -> None:
    with pytest.raises(RulePackContractError):
        _finding(_result("x-sink", "ecdat|", SINK_META))


def _fold(findings: list[Finding]) -> list[Finding]:
    fold = source._fold_superseded_candidates
    result: list[Finding] = fold(findings)
    return result


def test_a_candidate_is_folded_into_the_confirmed_finding_with_its_holder() -> None:
    candidate = _finding(
        _result("x-candidate", "ecdat|holder=apiKey", CANDIDATE_META, line=3)
    )
    confirmed = _finding(_result("x-sink", "ecdat|holder=apiKey", SINK_META, line=9))
    folded = _fold([candidate, confirmed])
    assert len(folded) == 1
    kept = folded[0]
    assert kept.raw["rule_id"] == "x-sink"
    assert kept.confidence == 1.0
    assert "candidate" not in kept.params
    assert [o.locator for o in kept.evidence.occurrences] == [
        "app/keys.js:9",
        "app/keys.js:3",
    ]
    assert kept.evidence.occurrences[1].detail == "rule=x-candidate"


def test_a_candidate_is_folded_into_every_confirmed_finding_with_its_holder() -> None:
    """One key reaching two sinks: both findings carry the declaration."""
    candidate = _finding(
        _result("x-candidate", "ecdat|holder=apiKey", CANDIDATE_META, line=3)
    )
    first = _finding(_result("x-sink", "ecdat|holder=apiKey", SINK_META, line=9))
    second = _finding(_result("x-sink", "ecdat|holder=apiKey", SINK_META, line=14))
    folded = _fold([candidate, first, second])
    assert [f.raw["rule_id"] for f in folded] == ["x-sink", "x-sink"]
    for finding in folded:
        assert "app/keys.js:3" in [o.locator for o in finding.evidence.occurrences]


@pytest.mark.parametrize(
    ("candidate_message", "candidate_path", "confirmed_message"),
    [
        ("ecdat|holder=apiKey", "app/keys.js", "ecdat|holder=otherKey"),
        ("ecdat|holder=apiKey", "app/other.js", "ecdat|holder=apiKey"),
        ("ecdat|holder=apiKey", "app/keys.js", "ecdat|holder=$HOLDER"),
        ("ecdat|holder=$N", "app/keys.js", "ecdat|holder=$HOLDER"),
    ],
    ids=["different-holder", "different-file", "inline-sink", "no-holder-either"],
)
def test_a_candidate_nothing_confirms_is_kept(
    candidate_message: str, candidate_path: str, confirmed_message: str
) -> None:
    candidate = _finding(
        _result("x-candidate", candidate_message, CANDIDATE_META, path=candidate_path)
    )
    confirmed = _finding(_result("x-sink", confirmed_message, SINK_META, line=9))
    folded = _fold([candidate, confirmed])
    assert [f.raw["rule_id"] for f in folded] == ["x-candidate", "x-sink"]
    assert folded[0].confidence == 0.5


def test_folding_is_order_independent() -> None:
    findings = [
        _finding(_result("x-candidate", "ecdat|holder=apiKey", CANDIDATE_META, line=3)),
        _finding(_result("x-candidate", "ecdat|holder=lonely", CANDIDATE_META, line=4)),
        _finding(_result("x-sink", "ecdat|holder=apiKey", SINK_META, line=9)),
        _finding(_result("x-sink", "ecdat|holder=$HOLDER", SINK_META, line=11)),
    ]
    expected = [f.model_dump() for f in _fold(findings)]
    for order in itertools.permutations(findings):
        assert sorted(
            (f.model_dump() for f in _fold(list(order))), key=json.dumps
        ) == sorted(expected, key=json.dumps)


# ---------------------------------------------------------------------------
# Pack-wide invariants STEP 0 measured
# ---------------------------------------------------------------------------


def _rules_of(language: str) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for path in sorted((RULES_DIR / language).glob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            rules[str(rule["id"])] = rule
    return rules


def _flatten(node: Any) -> list[Any]:
    found: list[Any] = [node]
    if isinstance(node, dict):
        for value in node.values():
            found.extend(_flatten(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_flatten(value))
    return found


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_every_pack_carries_the_whole_corroboration_model(pack: Pack) -> None:
    ids = set(_rules_of(pack.language))
    assert pack.sink_rules <= ids
    assert {pack.der_rule, pack.candidate_rule, pack.pem_rule} <= ids


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_every_sink_rule_is_configured_for_precision(pack: Pack) -> None:
    """Each setting is a STEP 0 measurement, pinned so it cannot drift.

    * `taint_assume_safe_functions` -- without it a KDF salt, or the "AES"
      passed to KeyGenerator, flowed through the call into the key parameter.
    * `constant_propagation: false` -- with it, every constant-backed sink
      produced a second, holder-less result.
    * a concatenation sanitizer -- an assembled key's literal is a part, not
      the key, and Java's `+`-joined PEM would otherwise leak through.
    """
    rules = _rules_of(pack.language)
    for rule_id in pack.sink_rules:
        rule = rules[rule_id]
        assert rule["mode"] == "taint"
        assert rule["options"]["taint_assume_safe_functions"] is True
        assert rule["options"]["constant_propagation"] is False
        sanitizers = [str(s.get("pattern", "")) for s in rule["pattern-sanitizers"]]
        assert any(re.fullmatch(r"\$[A-Z_]+ \+ \$[A-Z_]+", s) for s in sanitizers)
        metadata = rule["metadata"]
        assert metadata["redact"] is True
        assert "critical" in metadata["flags"]
        assert "candidate" not in metadata["flags"]
        assert "confidence" not in metadata
        assert f"holder={metadata['holder_metavar']}" in rule["message"]


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_every_candidate_rule_is_marked_uncertain(pack: Pack) -> None:
    rule = _rules_of(pack.language)[pack.candidate_rule]
    metadata = rule["metadata"]
    assert metadata["confidence"] == str(CANDIDATE_CONFIDENCE)
    assert "candidate" in metadata["flags"]
    assert "critical" not in metadata["flags"]
    assert metadata["redact"] is True
    assert f"holder={metadata['holder_metavar']}" in rule["message"]
    analyzers = [
        node["metavariable-analysis"]["analyzer"]
        for node in _flatten(rule)
        if isinstance(node, dict) and "metavariable-analysis" in node
    ]
    assert analyzers == ["entropy"]


@pytest.mark.parametrize("pack", PACKS, ids=PACK_IDS)
def test_every_der_rule_is_shape_only_and_certain(pack: Pack) -> None:
    rule = _rules_of(pack.language)[pack.der_rule]
    assert rule["options"]["constant_propagation"] is False
    assert rule["metadata"]["redact"] is True
    assert "critical" in rule["metadata"]["flags"]
    assert rule["message"] == "ecdat|"


def test_no_metavariable_is_a_prefix_of_one_its_message_interpolates() -> None:
    """STEP 0's redaction hazard, over every rule in every pack.

    semgrep substitutes a bound metavariable wherever its NAME appears in the
    message -- including as the prefix of a longer, UNBOUND one. With
    `hmac.New($H, ...)` bound and `$HOLDER` unbound, the message read
    `holder=sha256.NewOLDER`. Had the key argument's metavariable been the
    prefix, the key bytes would have been interpolated into the Finding.
    """
    metavariable = re.compile(r"\$[A-Z_][A-Z0-9_]*")
    exposed: list[tuple[str, str, str]] = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            in_message = set(metavariable.findall(str(rule.get("message", ""))))
            bound = {
                name
                for node in _flatten({k: v for k, v in rule.items() if k != "message"})
                if isinstance(node, str)
                for name in metavariable.findall(node)
            }
            for name in in_message:
                for other in bound:
                    if other != name and name.startswith(other):
                        exposed.append((str(rule["id"]), name, other))
    assert exposed == []
