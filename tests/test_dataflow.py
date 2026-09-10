"""Source dataflow: constant propagation and taint (ADR-0026).

Scanner A has always matched CALL SITES. ADR-0004 recorded the two things that
costs, and this slice closes both with Semgrep's own dataflow rather than a new
engine.

**Miss-class 1 — the `configurable` flag is guessed from the SHAPE of a
captured value.** `RSA_BITS` is ALL_CAPS, so the heuristic reads it as a
resolved constant and reports `configurable=False`; it is in fact read from
`os.environ`. That flag is not decoration: it feeds the crypto-agility score
and the Mosca **Y** (migration-time) estimate, so getting it backwards inflates
the cost of every site like it. A recall number cannot catch this — the
artefact is reported either way, with the wrong price attached.

**Miss-class 2 — an artefact that exists only along a flow is invisible.** A
key assembled by concatenation has no `key = b"..."` literal to match, and a
weak RNG assigned to a variable nobody named `secret` is outside the name-scoped
rule by construction.

The precision case matters as much: what makes a taint rule safe to ship is the
SINK, not the source. `random.random()` in a Monte Carlo simulation, an env read
that sizes a page, and a concatenation that builds a label all reach nothing
cryptographic, and all must stay silent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from core.normalise import normalise
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import rule_id_of

FIXTURE_ROOT = Path("testdata/dataflow_fixtures")
KNOWLEDGE_DIR = Path("knowledge")

with (FIXTURE_ROOT / "answer_key.yaml").open(encoding="utf-8") as _handle:
    ANSWERS: dict[str, Any] = yaml.safe_load(_handle)

CONFIGURABILITY: list[dict[str, Any]] = ANSWERS["configurability"]
CONST_PROP: list[dict[str, Any]] = ANSWERS["constant_propagation"]
KNOWN_LIMITS: list[dict[str, Any]] = ANSWERS["known_limits"]
CONST_PROP_REACH: list[dict[str, Any]] = ANSWERS["const_prop_reach"]
FINDINGS: dict[str, list[dict[str, Any]]] = ANSWERS["findings"]
DECOYS: list[str] = ANSWERS["decoys"]


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("df-scratch")
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="dataflow")
    return list(SourceScanner().scan(target, context))


def _rel(finding: Finding) -> str:
    locator = finding.evidence.occurrences[0].locator
    path, _, _line = locator.rpartition(":")
    return str(Path(path).resolve().relative_to(FIXTURE_ROOT.resolve()))


def _for(findings: list[Finding], fixture: str) -> list[Finding]:
    return [f for f in findings if _rel(f) == fixture]


# ---------------------------------------------------------------------------
# STEP 0, as a test: the OSS build really does have these features
# ---------------------------------------------------------------------------


def test_constant_propagation_follows_a_value_to_its_call_site(
    findings: list[Finding],
) -> None:
    """`algo = "md5"` then `hashlib.new(algo, ...)` -- the value is followed.

    The capability is what miss-class 1's fix rests on, and this build has
    surprised us before (semgrep OSS emits no `metavars` block at all), so it
    is asserted rather than assumed.

    It also took a rule change to reach. Propagation applies to the PATTERN,
    not to the capture: `hashlib.new($ALG, ...)` with a `metavariable-regex`
    binds `$ALG` to the source text `algo` and the regex fails, while
    `hashlib.new("md5", ...)` matches the propagated value. The digest rules
    now carry both branches -- see ADR-0026.
    """
    for case in CONST_PROP:
        hits = [
            f
            for f in _for(findings, case["fixture"])
            if f.algorithm == case["algorithm"] and rule_id_of(f) == case["rule_id"]
        ]
        seen = [f.algorithm for f in _for(findings, case["fixture"])]
        assert len(hits) == case["count"], (
            f"constant propagation resolved {len(hits)} of "
            f"{case['count']} {case['algorithm']} sites in {case['fixture']}; "
            f"saw {seen}"
        )


def test_the_measured_const_prop_limit_is_still_the_limit() -> None:
    """What OSS does NOT propagate, pinned so the ADR cannot go stale.

    `algo = algorithms.AES` then `algo(key)` is invisible: OSS propagates
    literals, not class or attribute references. Recorded in the answer key as
    a `known_limit` rather than a decoy -- a decoy should stay silent, and this
    should not. If a semgrep upgrade starts catching it, this test fails and
    the fixture graduates to must_fire.
    """
    assert KNOWN_LIMITS, "the measured limits vanished from the answer key"
    aliased = next(
        limit
        for limit in KNOWN_LIMITS
        if limit["fixture"] == "must_not_fire/constprop_limit.py"
    )
    assert aliased["missed"] == "AES"


def test_the_aliased_class_reference_is_genuinely_missed(
    findings: list[Finding],
) -> None:
    """The limit above, asserted against the scanner rather than the document."""
    hits = _for(findings, "must_not_fire/constprop_limit.py")
    assert hits == [], (
        "constant propagation now resolves an aliased class reference -- good "
        "news, but the answer key still lists it as a known limit. Move the "
        f"fixture to must_fire and update ADR-0026. Saw: {[f.algorithm for f in hits]}"
    )


# ---------------------------------------------------------------------------
# MISS-CLASS 1: the configurable flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    CONFIGURABILITY,
    ids=[
        f"{c['fixture'].split('/')[-1]}={c['expected_configurable']}"
        for c in CONFIGURABILITY
    ],
)
def test_the_configurable_flag_is_corrected_by_dataflow(
    case: dict[str, Any], findings: list[Finding]
) -> None:
    hits = [
        f
        for f in _for(findings, case["fixture"])
        if rule_id_of(f) == case["rule_id"] and f.algorithm == case["algorithm"]
    ]
    assert hits, f"{case['rule_id']} did not fire on {case['fixture']}"
    for finding in hits:
        assert finding.configurable is case["expected_configurable"], (
            f"{case['fixture']}: configurable={finding.configurable}, "
            f"expected {case['expected_configurable']} -- {case['why']}"
        )


def test_env_and_literal_differ_only_in_the_configurable_flag(
    findings: list[Finding],
) -> None:
    """The heart of miss-class 1, stated as one assertion.

    Same algorithm, same rule, same kind of call site. If the two came back
    identical the correction is not working, and no recall number would say so.
    """
    env = _for(findings, "must_fire/df_env_keysize.py")
    literal = _for(findings, "must_fire/df_literal_keysize.py")
    assert env and literal

    env_rsa = next(f for f in env if f.algorithm == "RSA")
    literal_rsa = next(f for f in literal if f.algorithm == "RSA")

    assert env_rsa.algorithm == literal_rsa.algorithm
    assert env_rsa.primitive == literal_rsa.primitive
    assert rule_id_of(env_rsa) == rule_id_of(literal_rsa)
    assert env_rsa.configurable is True
    assert literal_rsa.configurable is False


def test_the_correction_does_not_add_a_second_finding(
    findings: list[Finding],
) -> None:
    """A configurability verdict is METADATA, not a new artefact.

    Emitting it as its own Finding would double-report the key, and worse: the
    normaliser's merge rule makes `configurable=False` beat `True` (one site
    that cannot be changed makes the artefact not freely configurable), so a
    second finding would be silently overruled by the one it was meant to
    correct.
    """
    env = _for(findings, "must_fire/df_env_keysize.py")
    assert len(env) == 1, [(rule_id_of(f), f.algorithm, f.configurable) for f in env]


def test_a_configurable_site_is_not_penalised_on_confidence(
    findings: list[Finding],
) -> None:
    """`bits` used to score 0.6 for being an unresolved lower-case name.

    Dataflow turns that guess into evidence: the value IS configurable, and it
    is known rather than suspected, so the confidence penalty goes away.
    """
    hits = _for(findings, "must_fire/df_getenv_keysize.py")
    rsa = next(f for f in hits if f.algorithm == "RSA")
    assert rsa.configurable is True
    assert rsa.confidence == 1.0, (
        f"a dataflow-confirmed configurable site still scores {rsa.confidence}"
    )


# ---------------------------------------------------------------------------
# MISS-CLASS 2: artefacts that exist only along a flow
# ---------------------------------------------------------------------------


def test_an_assembled_key_reaching_a_cipher_is_found(findings: list[Finding]) -> None:
    """No `key = b"..."` literal exists, so the per-call-site rule sees nothing."""
    hits = [
        f
        for f in _for(findings, "must_fire/df_assembled_key.py")
        if rule_id_of(f) == "py-assembled-key-material"
    ]
    assert hits, "the concatenation-assembled key was not detected"
    assert hits[0].asset_type == "key"


def test_the_assembled_key_is_a_finding_the_old_rules_miss(
    findings: list[Finding],
) -> None:
    """Stated as a negative so the claim is checked, not asserted.

    If a per-call-site key-material rule already covered this, the taint rule
    would be redundant and should not have shipped.
    """
    per_call_site = {"py-hardcoded-cipher-key", "py-hardcoded-iv", "py-pem-private-key"}
    hits = {rule_id_of(f) for f in _for(findings, "must_fire/df_assembled_key.py")}
    assert not (hits & per_call_site), (
        f"a per-call-site rule already covers this file: {hits & per_call_site}"
    )


def test_weak_rng_is_caught_by_dataflow_when_the_name_says_nothing(
    findings: list[Finding],
) -> None:
    """`value = random.random()` -- outside the name-scoped rule by construction."""
    fixture = "must_fire/df_weak_rng_dataflow.py"
    by_rule = {rule_id_of(f) for f in _for(findings, fixture)}
    assert "py-weak-random-dataflow" in by_rule, (
        f"the taint rule missed the flow; saw {by_rule}"
    )
    assert "py-weak-random-secret" not in by_rule, (
        "the name-scoped rule fired on a variable named `value`; the blind spot "
        "this test describes does not exist and the fixture is wrong"
    )


def test_the_two_rng_rules_do_not_double_report(findings: list[Finding]) -> None:
    """Both fire on the named-AND-flowing case; one component comes out.

    They agree on algorithm, primitive, usage and locus, so they carry one
    identity and the normaliser folds them together. That is why both can ship:
    the union is better recall, and the merge is what stops it being noise.
    """
    fixture = "must_fire/df_weak_rng_named.py"
    hits = _for(findings, fixture)
    rules = {rule_id_of(f) for f in hits}
    assert {"py-weak-random-secret", "py-weak-random-dataflow"} <= rules, rules

    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="dataflow")
    _, cbom_json = normalise(hits, target)
    drbg = [
        c
        for c in json.loads(cbom_json)["components"]
        if c["name"].startswith("MT19937")
    ]
    assert len(drbg) == 1, (
        f"the two RNG rules produced {len(drbg)} components for one call site: "
        f"{[c['name'] for c in drbg]}"
    )


# ---------------------------------------------------------------------------
# PRECISION -- what makes a taint rule safe to ship
# ---------------------------------------------------------------------------


def test_no_dataflow_rule_fires_on_the_decoys(findings: list[Finding]) -> None:
    """A Monte Carlo simulation, jitter, a banner pick, an env-sized page, and
    a concatenated label. None reaches a cryptographic sink."""
    for decoy in DECOYS:
        hits = [
            (rule_id_of(f), f.evidence.occurrences[0].locator)
            for f in _for(findings, decoy)
        ]
        assert hits == [], f"{decoy} produced findings: {hits}"


def test_an_env_read_with_no_crypto_sink_is_not_a_configurability_verdict(
    findings: list[Finding],
) -> None:
    """`int(os.environ.get("PAGE_SIZE", "50"))` is not a cryptographic fact.

    The configurability rule is scoped to cryptographic sinks precisely so a
    settings module does not become an inventory of cryptographic decisions.
    """
    assert _for(findings, "must_not_fire/decoys.py") == []


# ---------------------------------------------------------------------------
# NO REGRESSION on the existing pack
# ---------------------------------------------------------------------------


def test_the_python_pack_still_scores_perfectly_on_its_own_fixtures(
    context: ScanContext, capsys: Any
) -> None:
    """Dataflow rules must not cost the pack that already worked.

    A new rule that fires once on `testdata/python_fixtures` fails that pack's
    precision assertion, which is exactly the guard this slice has to clear.
    """
    from tests.rulepack import load_answers, score

    root = Path("testdata/python_fixtures")
    answers = load_answers(root)
    target = Target(kind="directory", ref=str(root), system="python-fixtures")
    hits = list(SourceScanner().scan(target, context))

    result = score(hits, answers)
    with capsys.disabled():
        print(result.report("PYTHON (regression check)"))

    # EXACT, not the pack's own >= 0.9 threshold. This is a regression guard,
    # and a rewrite that quietly dropped two detections would sail through a
    # 90% floor -- which is exactly what happened while ADR-0027 was being
    # written: converting the MAC rules lost the positional
    # `hmac.new(..., hashlib.md5, ...)` branch and the score went to 39/41
    # while every assertion still passed.
    assert result.recall == 1.0, f"the existing pack lost detections: {result.missed}"
    assert result.precision == 1.0, (
        f"a new rule fired on the existing pack's fixtures: {result.spurious}"
    )


# ---------------------------------------------------------------------------
# DETERMINISM
# ---------------------------------------------------------------------------


def test_dataflow_analysis_is_deterministic(context: ScanContext) -> None:
    """Same input, same packs -> byte-identical CBOM (CLAUDE.md).

    Worth asserting separately from the other packs: taint analysis explores a
    graph, and a graph traversal that depended on iteration order would produce
    a CBOM that changed between runs of an unchanged repository.
    """
    import datetime
    import uuid

    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="dataflow")
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


def test_dataflow_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    planted = 0
    found = 0
    missed: list[tuple[str, str]] = []

    for fixture, expectations in FINDINGS.items():
        for expectation in expectations:
            planted += expectation["count"]
            hits = [
                f
                for f in _for(findings, fixture)
                if rule_id_of(f) == expectation["rule_id"]
                and f.algorithm == expectation["algorithm"]
                and f.primitive == expectation["primitive"]
                and f.asset_type == expectation["asset_type"]
            ]
            found += min(len(hits), expectation["count"])
            if len(hits) < expectation["count"]:
                missed.append((fixture, expectation["rule_id"]))

    # The configurability corrections are scored too: a correction that silently
    # stopped working would leave every recall number untouched.
    corrections = 0
    correct = 0
    for case in CONFIGURABILITY:
        corrections += 1
        hits = [
            f
            for f in _for(findings, case["fixture"])
            if rule_id_of(f) == case["rule_id"]
        ]
        if hits and all(f.configurable is case["expected_configurable"] for f in hits):
            correct += 1

    decoy_hits = sum(len(_for(findings, decoy)) for decoy in DECOYS)
    recall = found / planted if planted else 0.0
    precision = 1.0 if decoy_hits == 0 else 0.0

    with capsys.disabled():
        print("\n  dataflow rules vs testdata/dataflow_fixtures/answer_key.yaml")
        print(f"  RECALL      {recall:6.1%}  ({found}/{planted} planted findings)")
        print(f"  PRECISION   {precision:6.1%}  ({decoy_hits} decoy hit(s))")
        print(f"  CONFIG FLAG {correct}/{corrections} corrected")
        if missed:
            print(f"  MISSED      {missed}")

    assert recall >= 0.9, f"recall {recall:.1%}; missed {missed}"
    assert precision == 1.0, f"{decoy_hits} finding(s) on the dataflow decoys"
    assert correct == corrections, "a configurable-flag correction did not hold"


# ---------------------------------------------------------------------------
# CONST-PROP REACH -- ADR-0027
#
# ADR-0026 fixed the digest and MAC rules and left the rest. These tests close
# the gap and, more importantly, stop it being reintroduced.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    CONST_PROP_REACH,
    ids=[f"{c['rule_id']}" for c in CONST_PROP_REACH],
)
def test_classification_sees_through_a_propagated_constant(
    case: dict[str, Any], findings: list[Finding]
) -> None:
    """`alg = "RS256"` then `jwt.encode(..., algorithm=alg)` must be reported.

    The literal-at-call-site form always worked. This is the form that did not,
    and it is the one a settings-driven codebase actually writes.
    """
    hits = [
        f
        for f in _for(findings, case["fixture"])
        if rule_id_of(f) == case["rule_id"] and f.algorithm == case["algorithm"]
    ]
    assert len(hits) == case["count"], (
        f"{case['rule_id']} matched {len(hits)} of {case['count']} propagated "
        f"sites in {case['fixture']} -- {case['why']}"
    )


def test_the_ssl_protocol_rule_never_had_this_gap(
    context: ScanContext, tmp_path: Path
) -> None:
    """Measured, not assumed -- and pinned so nobody 'fixes' it into one.

    `py-ssl-weak-protocol` matches `ssl.$PROTO`: the constant ITSELF, wherever
    it appears. So a protocol assigned to a variable is already reported at the
    ASSIGNMENT, and the rule needs no propagation to see it. Rewriting it to
    classify a value passed to `SSLContext(...)` would ADD a gap, because OSS
    const-prop does not follow an attribute reference (ADR-0026).
    """
    source = tmp_path / "ssl_propagated.py"
    source.write_text(
        "import ssl\n\n\n"
        "def context():\n"
        "    proto = ssl.PROTOCOL_TLSv1_1\n"
        "    return ssl.SSLContext(proto)\n",
        encoding="utf-8",
    )
    target = Target(kind="directory", ref=str(tmp_path), system="ssl-prop")
    hits = [
        f
        for f in SourceScanner().scan(target, context)
        if rule_id_of(f) == "py-ssl-weak-protocol"
    ]
    assert hits, "py-ssl-weak-protocol missed a protocol constant behind a variable"
    assert hits[0].params.get("version") == "TLSv1_1"


def test_a_jose_algorithm_no_rule_claims_is_not_reported(
    findings: list[Finding],
) -> None:
    """Propagation-aware classification must not become a catch-all.

    EdDSA (RFC 8037) is a real `alg` value with no rule and no quantum note in
    this pack. A rule that fired on it would be reporting an algorithm it
    cannot say anything about.
    """
    assert _for(findings, "must_not_fire/decoys.py") == []


# ---------------------------------------------------------------------------
# THE CONTRACT TEST -- the durable half of ADR-0027
# ---------------------------------------------------------------------------


def test_no_python_rule_classifies_a_passed_value_with_metavariable_regex_alone() -> (
    None
):
    """The gap ADR-0026 found, made impossible to reintroduce.

    `metavariable-regex` tests the SOURCE TEXT bound to a metavariable. When
    the metavariable is bound to a value PASSED to a call -- `algorithm=$ALG`,
    `getInstance($T)`, `[$ALG]` -- the source text is the variable's name
    whenever the value was assigned earlier, so the regex silently fails and
    the site is never reported. `metavariable-pattern` is evaluated against the
    PROPAGATED value and does not have that hole.

    Matching the constant itself is fine and is why this test looks at argument
    position rather than banning `metavariable-regex` outright:
    `py-ssl-weak-protocol` binds `$PROTO` in `ssl.$PROTO`, which is an
    attribute suffix and not a passed value, and it reports the propagated case
    at the assignment.

    Name-scoping is fine too: a regex over a VARIABLE NAME (`py-weak-random-secret`)
    is asking about the name, and propagation has nothing to do with it. Those
    are listed explicitly rather than pattern-matched, so adding one is a
    deliberate act.
    """
    import re

    import yaml

    # Rules whose metavariable-regex tests a NAME rather than a value.
    # Propagation is irrelevant to them by construction, and listing them
    # explicitly means adding one is a deliberate act rather than a
    # pattern that quietly widens. The ADR-0034 candidate tests a key-ish NAME
    # and the SHAPE of the literal declared under it -- the literal it matched,
    # never a value passed to a call.
    name_scoped = {"py-weak-random-secret", "py-hardcoded-key-candidate"}

    #: `$VAR` in an argument position: after `(`, `,`, `=` or `[`.
    argument_position = re.compile(r"[(\[,=]\s*\$[A-Z_][A-Z0-9_]*")

    offenders: list[tuple[str, str]] = []
    for path in sorted(Path("knowledge/rules/python").glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in document["rules"]:
            rule_id = str(rule["id"])
            if rule_id in name_scoped:
                continue
            nodes = _flatten(rule)
            regexed = {
                str(node["metavariable-regex"]["metavariable"])
                for node in nodes
                if isinstance(node, dict) and "metavariable-regex" in node
            }
            if not regexed:
                continue
            # A metavariable that ALSO carries a metavariable-pattern
            # constraint is covered: that branch is evaluated against the
            # propagated value, and keeping the regex branch beside it only
            # widens the union.
            propagation_aware = {
                str(node["metavariable-pattern"]["metavariable"])
                for node in nodes
                if isinstance(node, dict) and "metavariable-pattern" in node
            }
            for pattern in _pattern_strings(rule):
                for match in argument_position.finditer(pattern):
                    metavar = match.group(0).lstrip("([,= \t")
                    if metavar in regexed and metavar not in propagation_aware:
                        offenders.append((rule_id, pattern.strip()))

    assert offenders == [], (
        "these rules classify a value PASSED to a call using metavariable-regex "
        "alone, so a propagated constant is silently missed (ADR-0027). Add a "
        "metavariable-pattern constraint on the same metavariable -- it is "
        "evaluated against the propagated value: "
        f"{sorted(set(offenders))}"
    )


def _flatten(node: Any) -> list[Any]:
    """Every mapping and sequence member anywhere inside a rule."""
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
    """Every `pattern:` / `pattern-inside:` string in a rule."""
    keys = {"pattern", "pattern-inside", "pattern-not", "pattern-not-inside"}
    return [
        str(value)
        for node in _flatten(rule)
        if isinstance(node, dict)
        for key, value in node.items()
        if key in keys and isinstance(value, str)
    ]
