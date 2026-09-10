"""Const-prop reach for Go, JS/TS and Java, and the cross-language contract.

ADR-0027 closed a quiet recall bug for Python: `metavariable-regex` tests the
SOURCE TEXT bound to a metavariable, so a value assigned earlier binds the
variable's NAME and the classification silently fails while the
literal-at-call-site form is reported normally. Three packs still had it.

**The one that matters most is an authentication bypass.**
`const alg = "none"; jwt.sign(payload, key, {algorithm: alg})` produced NO
finding in the JavaScript pack. RFC 8725 s3.1 requires `alg: none` to be
rejected outright, and a service selecting its signing algorithm from config
was reported as having no JWT signing at all.

Each part is scored SEPARATELY and each gate is `== 1.0`, never a floor —
ADR-0027's own regression was a rewrite that dropped two detections and sailed
through a `>= 0.9` check.

What STEP 0 measured, per language, before any rule was touched:

============  =============================  ==============================
language      string literal via a variable  attribute/enum ref via variable
============  =============================  ==============================
Python        yes (ADR-0027)                 **no**
Go            (API has no string-classified  **no**
              algorithms at all)
JS/TS         yes                            **no**
Java          yes                            **no**
============  =============================  ==============================

So Go gets no conversion — there is no string to propagate — and Java's JWT
rules cannot be fixed either, because jjwt and auth0 both spell their
algorithms as enum members. Both limits are PINNED by tests here rather than
argued about in prose.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import load_answers, relative_path_of, rule_id_of, score

KNOWLEDGE_DIR = Path("knowledge")
GO_ROOT = Path("testdata/go_fixtures")
JS_ROOT = Path("testdata/js_fixtures")
JAVA_ROOT = Path("testdata/java_fixtures")


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("ml-scratch")
    )


def _scan(root: Path, context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(root), system=root.name)
    return list(SourceScanner().scan(target, context))


@pytest.fixture(scope="module")
def go_findings(context: ScanContext) -> list[Finding]:
    return _scan(GO_ROOT, context)


@pytest.fixture(scope="module")
def js_findings(context: ScanContext) -> list[Finding]:
    return _scan(JS_ROOT, context)


@pytest.fixture(scope="module")
def java_findings(context: ScanContext) -> list[Finding]:
    return _scan(JAVA_ROOT, context)


def _for(findings: list[Finding], root: Path, fixture: str) -> list[Finding]:
    return [f for f in findings if relative_path_of(f, root) == fixture]


# ---------------------------------------------------------------------------
# PART B — JS/TS. The auth bypass, and the reason this slice exists.
# ---------------------------------------------------------------------------


def test_the_jwt_none_auth_bypass_is_caught_behind_a_variable(
    js_findings: list[Finding],
) -> None:
    """`const alg = "none"` then `jwt.sign(..., {algorithm: alg})`.

    RFC 8725 s3.1: `alg: none` disables verification entirely, so anyone can
    mint a token the service accepts. Before ADR-0028 this produced NOTHING --
    not a lower-confidence finding, not an unknown algorithm: the file looked
    like it had no JWT signing in it.
    """
    hits = [
        f
        for f in _for(js_findings, JS_ROOT, "must_fire/js_jwt_propagated.js")
        if rule_id_of(f) == "js-jwt-none"
    ]
    assert hits, "the alg=none auth bypass is still invisible behind a variable"
    assert hits[0].algorithm == "none"
    assert hits[0].params.get("flagged") is True


def test_every_jwt_family_is_caught_behind_a_variable(
    js_findings: list[Finding],
) -> None:
    """None, RSA, ECDSA and HMAC — one fixture, four rules, all propagated."""
    rules = {
        rule_id_of(f)
        for f in _for(js_findings, JS_ROOT, "must_fire/js_jwt_propagated.js")
    }
    assert rules == {"js-jwt-none", "js-jwt-rsa", "js-jwt-ecdsa", "js-jwt-hmac"}


def test_the_ts_propagated_case_is_scanned(js_findings: list[Finding]) -> None:
    """`.ts` on the PROPAGATED path, not only the literal one.

    A rule declaring `languages: [javascript, typescript]` that stopped
    matching `.ts` would pass every `.js` assertion above.
    """
    ts = _for(js_findings, JS_ROOT, "must_fire/ts_jwt_propagated.ts")
    assert [rule_id_of(f) for f in ts] == ["js-jwt-none"]

    cipher = _for(js_findings, JS_ROOT, "must_fire/ts_cipher_propagated.ts")
    assert len(cipher) == 2
    assert {f.algorithm for f in cipher} == {"AES"}

    # The PARAMETER is the variable's name, not the resolved suite.
    # `metavariable-pattern` constrains a binding without rewriting it, so the
    # CLASSIFICATION is correct -- these are AES cipher findings, which is what
    # the CBOM and the policy engine read -- while `cipher_suite` reports what
    # the source literally says. Asserted rather than glossed: it is the same
    # degradation ADR-0027 recorded for Python's `params.alg`, and pretending
    # the value resolves would make the limit invisible.
    assert {f.params.get("cipher_suite") for f in cipher} == {
        "suite",
        "CONFIGURED_SUITE",
    }
    # ...and the scanner says so on its own: an unresolved lower-case name
    # drops the confidence rather than reporting a suite nobody wrote.
    local = next(f for f in cipher if f.params.get("cipher_suite") == "suite")
    assert local.confidence < 1.0


def test_js_literals_still_fire(js_findings: list[Finding]) -> None:
    """The branch that already worked must not be traded for the new one."""
    literal = _for(js_findings, JS_ROOT, "must_fire/js_jwt_none.js")
    assert [rule_id_of(f) for f in literal] == ["js-jwt-none"]


def test_js_decoys_stay_silent(js_findings: list[Finding]) -> None:
    """Algorithm-shaped NAMES holding non-crypto strings, and an unlisted alg."""
    for decoy in ("must_not_fire/decoys.js", "must_not_fire/decoys.ts"):
        hits = [(rule_id_of(f), f.algorithm) for f in _for(js_findings, JS_ROOT, decoy)]
        assert hits == [], f"{decoy} produced findings: {hits}"


def test_js_recall_and_precision(js_findings: list[Finding], capsys: Any) -> None:
    result = score(js_findings, load_answers(JS_ROOT))
    with capsys.disabled():
        print(result.report("JS/TS (ADR-0028)"))
    # EXACT. A floor is what let ADR-0027's rewrite drop two detections.
    assert result.recall == 1.0, (
        f"JS recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, f"JS spurious: {result.spurious}"


# ---------------------------------------------------------------------------
# PART C — Java. The transformation string is where the mode lives.
# ---------------------------------------------------------------------------


def test_the_java_cipher_mode_is_parsed_from_a_propagated_transform(
    java_findings: list[Finding],
) -> None:
    """`String t = "AES/ECB/PKCS5Padding"` then `Cipher.getInstance(t)`.

    Java packs algorithm, mode and padding into ONE token, so missing the
    propagated form loses all three — including the ECB verdict, which is the
    highest-value finding in the Java pack.
    """
    hits = _for(java_findings, JAVA_ROOT, "must_fire/JavaCipherPropagated.java")
    modes = {f.params.get("mode") for f in hits if f.algorithm == "AES"}
    assert modes == {"ECB", "GCM"}, [f.params for f in hits]

    ecb = [f for f in hits if f.params.get("mode") == "ECB"]
    gcm = [f for f in hits if f.params.get("mode") == "GCM"]
    assert ecb[0].params.get("flagged") is True
    assert gcm[0].params.get("flagged") is not True


def test_java_digest_and_signature_are_caught_behind_a_variable(
    java_findings: list[Finding],
) -> None:
    digest = _for(java_findings, JAVA_ROOT, "must_fire/JavaDigestPropagated.java")
    assert [rule_id_of(f) for f in digest] == ["java-digest-md5"]

    signature = _for(java_findings, JAVA_ROOT, "must_fire/JavaSignaturePropagated.java")
    assert [rule_id_of(f) for f in signature] == ["java-signature-weak-hash"]
    assert signature[0].params.get("flagged") is True


def test_java_literals_still_fire(java_findings: list[Finding]) -> None:
    literal = _for(java_findings, JAVA_ROOT, "must_fire/JavaCipherAesEcb.java")
    assert [rule_id_of(f) for f in literal] == ["java-cipher-aes-ecb"]


def test_java_decoys_stay_silent(java_findings: list[Finding]) -> None:
    hits = [
        (rule_id_of(f), f.algorithm)
        for f in _for(java_findings, JAVA_ROOT, "must_not_fire/Decoys.java")
    ]
    assert hits == [], f"Java decoys produced findings: {hits}"


def test_the_java_enum_reference_limit_is_pinned(
    java_findings: list[Finding],
) -> None:
    """The JWT auth-bypass close is NOT achievable for Java, and this says so.

    jjwt and auth0 java-jwt both spell their algorithms as ENUM members
    (`SignatureAlgorithm.RS256`), and OSS const-prop follows strings only. If a
    semgrep upgrade starts catching it this test fails, the fixture graduates
    to must_fire, and ADR-0028 gets corrected — which is the point of pinning
    it rather than writing it down.
    """
    limits = load_answers(JAVA_ROOT).raw["known_limits"]
    assert any("EnumRefLimit" in limit["fixture"] for limit in limits)
    hits = _for(java_findings, JAVA_ROOT, "must_not_fire/EnumRefLimit.java")
    assert hits == [], (
        "const-prop now follows a Java enum reference — good news. Move the "
        f"fixture to must_fire and correct ADR-0028. Saw: {hits}"
    )


def test_java_recall_and_precision(java_findings: list[Finding], capsys: Any) -> None:
    result = score(java_findings, load_answers(JAVA_ROOT))
    with capsys.disabled():
        print(result.report("JAVA (ADR-0028)"))
    assert result.recall == 1.0, (
        f"Java recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, f"Java spurious: {result.spurious}"


# ---------------------------------------------------------------------------
# PART A — Go. Measured, and the answer is "nothing to convert".
# ---------------------------------------------------------------------------


def test_the_go_limit_is_a_degraded_parameter_not_a_missed_finding(
    go_findings: list[Finding],
) -> None:
    """The Go limit, measured — and it is not the limit that was assumed.

    `elliptic.P384()` and `tls.VersionTLS10` are attribute/function references
    and OSS const-prop does not follow them. The consequence is NOT that the
    call sites are invisible: the Go rules capture without a regex constraint,
    so they still FIRE. What is lost is the PARAMETER — `curve: "curve"`
    instead of `curve: "P384"`.

    So Go needs no conversion. There is no classification to fix, only a
    parameter that cannot be resolved, and the scanner already marks that
    honestly: a lower-case bare name reads as unresolved, so these findings
    carry confidence 0.6 and `configurable=True` rather than claiming a value
    nobody wrote.
    """
    limits = load_answers(GO_ROOT).raw["known_limits"]
    assert any("go_propagated_params" in limit["fixture"] for limit in limits)

    hits = _for(go_findings, GO_ROOT, "must_fire/go_propagated_params.go")
    by_rule = {rule_id_of(f): f for f in hits}
    assert set(by_rule) == {"go-ecdsa-keygen", "go-tls-minversion"}

    ecdsa = by_rule["go-ecdsa-keygen"]
    assert ecdsa.algorithm == "ECDSA"  # classification survives
    assert ecdsa.params.get("curve") == "curve"  # the parameter does not
    assert ecdsa.confidence < 1.0  # and the scanner says so
    assert ecdsa.configurable is True


def test_go_decoys_stay_silent(go_findings: list[Finding]) -> None:
    hits = [
        (rule_id_of(f), f.algorithm)
        for f in _for(go_findings, GO_ROOT, "must_not_fire/decoys.go")
    ]
    assert hits == [], f"Go decoys produced findings: {hits}"


def test_go_recall_and_precision(go_findings: list[Finding], capsys: Any) -> None:
    result = score(go_findings, load_answers(GO_ROOT))
    with capsys.disabled():
        print(result.report("GO (ADR-0028)"))
    assert result.recall == 1.0, (
        f"Go recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, f"Go spurious: {result.spurious}"


# ---------------------------------------------------------------------------
# THE CROSS-LANGUAGE CONTRACT TEST
# ---------------------------------------------------------------------------

PACKS = ("python", "go", "javascript", "java")

#: Rules exempt BY ID, each for a stated reason that is not about propagation.
#:
#: Two kinds only. A rule whose regex tests a variable NAME is asking about the
#: name. A rule whose regex tests the SHAPE of a literal (is this long enough
#: to be a key?) is asking about the literal it already matched -- and a value
#: behind a constant is caught by that rule's own `const $NAME = $LITERAL`
#: branch.
#:
#: ADR-0034 moved the `*-hardcoded-key` rules to taint, so they left this list:
#: they no longer regex a bound value at all. The entropy-only CANDIDATE rules
#: that replaced their name-scoped half test both kinds at once -- a key-ish
#: NAME and the SHAPE of the literal declared under it -- and joined it.
#:
#: Listed rather than pattern-matched so adding one is a deliberate act.
EXEMPT_BY_ID = {
    "py-weak-random-secret": "regex tests a variable NAME",
    "go-weak-random": "regex tests a variable NAME",
    "js-math-random": "regex tests a variable NAME",
    "java-weak-random": "regex tests a variable NAME",
    "py-hardcoded-key-candidate": "regex tests a NAME and the SHAPE of its literal",
    "go-hardcoded-key-candidate": "regex tests a NAME and the SHAPE of its literal",
    "js-hardcoded-key-candidate": "regex tests a NAME and the SHAPE of its literal",
    "java-hardcoded-key-candidate": "regex tests a NAME and the SHAPE of its literal",
    "js-forge-rsa-keygen": "regex tests that $BITS is NUMERIC, not which algorithm",
}

#: `$VAR` in an argument position: after `(`, `[`, `,`, `=` or `:`.
#:
#: The colon is load-bearing and was missing from ADR-0027's version. JS and TS
#: object literals spell an argument `{algorithm: $ALG}`, so without it the
#: contract test walked straight past the four `js-jwt-*` rules -- including
#: the `alg: none` auth bypass. The test that was supposed to make this class
#: of bug unrepeatable could not see the worst instance of it.
ARGUMENT_POSITION = re.compile(r"[(\[,=:]\s*\$[A-Z_][A-Z0-9_]*")

_PATTERN_KEYS = {"pattern", "pattern-inside", "pattern-not", "pattern-not-inside"}


def _flatten(node: Any) -> list[Any]:
    found: list[Any] = []
    if isinstance(node, dict):
        found.append(node)
        for value in node.values():
            found.extend(_flatten(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_flatten(value))
    return found


def _pattern_strings(rule: Any) -> list[str]:
    return [
        str(value)
        for node in _flatten(rule)
        if isinstance(node, dict)
        for key, value in node.items()
        if key in _PATTERN_KEYS and isinstance(value, str)
    ]


def offenders_in(rule: dict[str, Any]) -> list[tuple[str, str]]:
    """`(metavariable, pattern)` for each classification that ignores propagation."""
    rule_id = str(rule["id"])
    if rule_id in EXEMPT_BY_ID:
        return []
    nodes = _flatten(rule)
    regexed = {
        str(n["metavariable-regex"]["metavariable"])
        for n in nodes
        if isinstance(n, dict) and "metavariable-regex" in n
    }
    if not regexed:
        return []
    aware = {
        str(n["metavariable-pattern"]["metavariable"])
        for n in nodes
        if isinstance(n, dict) and "metavariable-pattern" in n
    }
    found: list[tuple[str, str]] = []
    for pattern in _pattern_strings(rule):
        for match in ARGUMENT_POSITION.finditer(pattern):
            metavar = match.group(0).lstrip("([,=: \t")
            if metavar in regexed and metavar not in aware:
                found.append((metavar, pattern.strip()))
    return found


def test_no_rule_in_any_pack_classifies_a_passed_value_with_regex_alone() -> None:
    """ADR-0027's contract, now over all four packs.

    A metavariable bound to a value PASSED to a call and constrained only by
    `metavariable-regex` silently misses every propagated constant. The fix is
    a `metavariable-pattern` constraint on the same metavariable, which is
    evaluated against the propagated value.
    """
    offending: dict[str, list[tuple[str, str]]] = {}
    for pack in PACKS:
        for path in sorted(Path("knowledge/rules") / pack for pack in [pack]):
            for rule_file in sorted(path.glob("*.yaml")):
                document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
                for rule in document["rules"]:
                    hits = offenders_in(rule)
                    if hits:
                        offending[str(rule["id"])] = hits

    assert offending == {}, (
        "these rules classify a value PASSED to a call using metavariable-regex "
        "alone, so a propagated constant is silently missed (ADR-0028). Add a "
        "metavariable-pattern constraint on the same metavariable: "
        f"{sorted(offending)}"
    )


@pytest.mark.parametrize(
    ("language", "broken"),
    [
        (
            "go",
            {
                "id": "go-broken-probe",
                "languages": ["go"],
                "patterns": [
                    {"pattern": "cipher.NewCBCEncrypter($MODE, $IV)"},
                    {
                        "metavariable-regex": {
                            "metavariable": "$MODE",
                            "regex": "^CBC$",
                        }
                    },
                ],
            },
        ),
        (
            "javascript",
            {
                "id": "js-broken-probe",
                "languages": ["javascript"],
                "patterns": [
                    {"pattern": "jwt.sign($P, $K, {..., algorithm: $ALG, ...})"},
                    {
                        "metavariable-regex": {
                            "metavariable": "$ALG",
                            "regex": '^"none"$',
                        }
                    },
                ],
            },
        ),
        (
            "java",
            {
                "id": "java-broken-probe",
                "languages": ["java"],
                "patterns": [
                    {"pattern": "Cipher.getInstance($T, ...)"},
                    {
                        "metavariable-regex": {
                            "metavariable": "$T",
                            "regex": '^"AES/ECB/',
                        }
                    },
                ],
            },
        ),
    ],
)
def test_the_contract_test_bites_in_every_language(
    language: str, broken: dict[str, Any]
) -> None:
    """A guard nobody has watched fail is a guard nobody should trust.

    Each of these is the exact mistake the real rules used to make, in that
    language's own syntax. The JavaScript one is the important case: its
    metavariable sits in an object literal (`{algorithm: $ALG}`), which
    ADR-0027's argument-position regex did not recognise — so the contract
    test would have passed while the `alg: none` auth bypass stayed open.
    """
    assert offenders_in(broken), (
        f"the contract test does NOT bite on a deliberately broken {language} "
        "rule, so it would not have caught the bug it exists to catch"
    )


def test_the_exemption_list_names_only_rules_that_exist() -> None:
    """An exemption for a deleted rule is a hole nobody is watching."""
    known: set[str] = set()
    for pack in PACKS:
        for rule_file in sorted((Path("knowledge/rules") / pack).glob("*.yaml")):
            document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            known.update(str(rule["id"]) for rule in document["rules"])

    stale = sorted(set(EXEMPT_BY_ID) - known)
    assert stale == [], f"exemptions for rules that no longer exist: {stale}"
