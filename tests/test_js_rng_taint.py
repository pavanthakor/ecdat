"""PART B — the JS weak-RNG taint sibling, owed from ADR-0028.

ADR-0026 shipped this for Python and made the argument for shipping BOTH rules:
the name-scoped one and the dataflow one cover different halves and neither is
a superset. ADR-0028 generalised constant propagation to the other packs and
explicitly did not do this, because the identity-merge argument had to be
re-made for JavaScript sinks rather than translated. This is that.

* `js-math-random` fires on a variable NAMED key/token/secret, and catches the
  case with no visible sink in the same function -- taint is intra-procedural,
  so a value returned to a caller is invisible to the taint rule.
* `js-math-random-dataflow` fires on a value that FLOWS to a key sink, and
  catches the case the name says nothing about.

Where both fire they must produce ONE component, not two. That is what makes
shipping both safe rather than noisy, and it is asserted here rather than
trusted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.normalise import normalise
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.source import SourceScanner
from tests.rulepack import relative_path_of, rule_id_of

JS_ROOT = Path("testdata/js_fixtures")
KNOWLEDGE_DIR = Path("knowledge")


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("jsrng-scratch")
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(JS_ROOT), system="js-fixtures")
    return list(SourceScanner().scan(target, context))


def _for(findings: list[Finding], fixture: str) -> list[Finding]:
    return [f for f in findings if relative_path_of(f, JS_ROOT) == fixture]


# ---------------------------------------------------------------------------
# The blind spot, closed
# ---------------------------------------------------------------------------


def test_a_badly_named_weak_rng_reaching_a_key_sink_is_found(
    findings: list[Finding],
) -> None:
    """`material` is not key-named, so the name-scoped rule cannot see it."""
    fixture = "must_fire/js_rng_dataflow.js"
    by_rule = {rule_id_of(f) for f in _for(findings, fixture)}

    assert "js-math-random-dataflow" in by_rule, by_rule
    assert "js-math-random" not in by_rule, (
        "the name-scoped rule fired on a variable called `material`; the blind "
        "spot this test describes does not exist and the fixture is wrong"
    )


def test_the_dataflow_finding_is_a_weak_drbg(findings: list[Finding]) -> None:
    hits = [
        f
        for f in _for(findings, "must_fire/js_rng_dataflow.js")
        if rule_id_of(f) == "js-math-random-dataflow"
    ]
    assert hits
    assert hits[0].primitive == "drbg"
    assert hits[0].algorithm == "Math.random"
    assert hits[0].params.get("flagged") is True


# ---------------------------------------------------------------------------
# BOTH rules ship, and do not double-report
# ---------------------------------------------------------------------------


def test_both_rules_fire_where_the_name_and_the_flow_agree(
    findings: list[Finding],
) -> None:
    fixture = "must_fire/js_rng_named_and_flowing.js"
    by_rule = {rule_id_of(f) for f in _for(findings, fixture)}
    assert {"js-math-random", "js-math-random-dataflow"} <= by_rule, by_rule


def test_the_two_rules_produce_one_component_not_two(
    findings: list[Finding],
) -> None:
    """The ADR-0026 identity-merge pattern, re-made for JavaScript.

    They agree on algorithm, primitive, usage and params, so they carry one
    identity and the normaliser folds them. `flags` must stay equal between the
    two rules for that to hold -- `critical` sets `params.flagged`, and a params
    mismatch would split the identity and double-report the same weak key.
    """
    fixture = "must_fire/js_rng_named_and_flowing.js"
    hits = _for(findings, fixture)
    target = Target(kind="directory", ref=str(JS_ROOT), system="js-fixtures")
    _, cbom = normalise(hits, target)

    drbg = [
        c for c in json.loads(cbom)["components"] if c["name"].startswith("Math.random")
    ]
    assert len(drbg) == 1, (
        f"the two RNG rules produced {len(drbg)} components for one call site: "
        f"{[c['name'] for c in drbg]}"
    )


def test_the_name_scoped_rule_still_catches_its_own_case(
    findings: list[Finding],
) -> None:
    """It is not a subset of the taint rule and must not be retired.

    `js_math_random.js` assigns to `token` and returns it -- no sink in the same
    function, so intra-procedural taint sees nothing. The name is the only
    signal there is.
    """
    fixture = "must_fire/js_math_random.js"
    by_rule = {rule_id_of(f) for f in _for(findings, fixture)}
    assert "js-math-random" in by_rule, by_rule
    assert "js-math-random-dataflow" not in by_rule, (
        "the taint rule reached a case with no sink; the fixture no longer "
        "demonstrates why both rules ship"
    )


# ---------------------------------------------------------------------------
# PRECISION
# ---------------------------------------------------------------------------


def test_a_non_crypto_math_random_stays_silent(findings: list[Finding]) -> None:
    """An animation ease, a shuffle, jitter and a Monte Carlo trial.

    What makes a taint rule safe to ship is the SINK, not the source. A rule
    that fired on every `Math.random()` would be noise an operator learns to
    ignore, and would take the real finding with it.
    """
    for decoy in ("must_not_fire/decoys.js", "must_not_fire/decoys.ts"):
        hits = [
            (rule_id_of(f), f.evidence.occurrences[0].locator)
            for f in _for(findings, decoy)
        ]
        assert hits == [], f"{decoy} produced findings: {hits}"
