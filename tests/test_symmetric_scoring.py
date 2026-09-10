"""PART B — symmetric key size scored against DATA LIFETIME (ADR-0029).

The engine has always scored the asymmetric family properly: RSA and ECC are
Shor-broken at any key size, and Mosca's inequality turns "broken eventually"
into "urgent here". Symmetric ciphers got a flat number — AES-128 scored 20
whether it protected a session cookie or a citizen's health record for fifty
years.

That is the wrong shape for a conditional fact. NIST SP 800-131A Rev.2 keeps
AES-128 ACCEPTABLE, and NIST IR 8547 says Grover halves it to roughly 64 bits
of quantum strength. Both are true, and which one governs depends entirely on
how long the data must stay secret — the same x that Mosca's inequality already
uses for the asymmetric case.

So this pack scores AES-128 the way the asymmetric side is scored: **same
algorithm, different context, different number.** A short-lived secret with
AES-128 is a note; a fifty-year secret with AES-128 is a finding.

It reads the TYPED `key_size` from Part A. `key_size: {max: 128}` is a numeric
comparison and cannot work against `"128"`, which is why Part A comes first —
`test_the_rule_needs_the_typed_key_size` asserts that dependency rather than
leaving it as a claim in an ADR.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.normalise import normalise
from core.scanner import Target
from core.schema import Evidence, Finding, Occurrence
from policy.apply import ScoreInputs, apply_policy
from policy.engine import default_packs

KNOWLEDGE_DIR = Path("knowledge")

#: Data classes and the lifetimes they carry, from knowledge/data_classes.yaml.
SHORT_LIVED = "Internal"  # x_years = 3
LONG_LIVED = "Sovereign"  # x_years = 50


def cipher_finding(algorithm: str, **params: Any) -> Finding:
    return Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="block-cipher",
        algorithm=algorithm,
        params=dict(params),
        usage="encrypt",
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view="declared",
                    locator="app/crypto.py:20",
                    detail="rule=py-aes-cipher",
                )
            ]
        ),
    )


def score_in(finding: Finding, data_class: str) -> dict[str, Any]:
    """Score one finding in one data-lifetime context; return its properties."""
    target = Target(
        kind="repo",
        ref="/srv/app",
        system="paymentsvc",
        data_class=data_class,
        sector="bfsi",
        exposure="internet",
    )
    _, cbom_json = normalise([finding], target)
    scored = apply_policy(
        cbom_json,
        default_packs(),
        inputs=ScoreInputs(
            data_class=data_class,
            sector="bfsi",
            exposure="internet",
            knowledge_dir=KNOWLEDGE_DIR,
        ),
    )
    components = json.loads(scored)["components"]
    assert len(components) == 1
    return {p["name"]: p["value"] for p in components[0]["properties"]}


def total(properties: dict[str, Any]) -> int:
    return int(properties["ecdat:score"])


def rules(properties: dict[str, Any]) -> set[str]:
    return set(str(properties.get("ecdat:fired_rules", "")).split(","))


# ---------------------------------------------------------------------------
# SAME ALGORITHM, DIFFERENT CONTEXT
# ---------------------------------------------------------------------------


def test_aes_128_scores_higher_for_long_lived_data_than_short_lived() -> None:
    """The whole point of Part B, as one assertion.

    Identical finding, identical algorithm, identical key size. The only thing
    that changes is how long the data has to stay secret — and that is exactly
    what decides whether Grover halving matters.
    """
    short = score_in(cipher_finding("AES", key_size=128), SHORT_LIVED)
    long_lived = score_in(cipher_finding("AES", key_size=128), LONG_LIVED)

    assert total(long_lived) > total(short), (
        f"AES-128 scored {total(short)} for 3-year data and "
        f"{total(long_lived)} for 50-year data; the lifetime is not being read"
    )
    # ...and it is THIS pack that moved, not just mosca underneath it.
    assert symmetric_score(long_lived) > symmetric_score(short), (
        f"symmetric contribution was {symmetric_score(short)} vs "
        f"{symmetric_score(long_lived)}; the total moved for another reason"
    )


def test_the_symmetric_rule_fires_only_for_long_lived_data() -> None:
    short = score_in(cipher_finding("AES", key_size=128), SHORT_LIVED)
    long_lived = score_in(cipher_finding("AES", key_size=128), LONG_LIVED)

    assert any(r.startswith("symmetric-") for r in rules(long_lived)), rules(long_lived)
    fired_short = {r for r in rules(short) if r.startswith("symmetric-")}
    assert fired_short <= {"symmetric-adequate-for-short-lived-data"}, fired_short


def symmetric_score(properties: dict[str, Any]) -> int:
    """This pack's contribution alone, out of `ecdat:category_score`."""
    parts = dict(
        part.split("=", 1)
        for part in str(properties.get("ecdat:category_score", "")).split(",")
        if "=" in part
    )
    return int(parts.get("symmetric", 0))


def test_aes_256_is_adequate_in_every_context() -> None:
    """256 bits leaves 128 after Grover, which is the target either way.

    Asserted on THIS PACK's contribution rather than on the total, because the
    total legitimately moves: the mosca pack scores urgency by data lifetime
    for every finding, and that is its job. What must not move is the symmetric
    verdict.
    """
    short = score_in(cipher_finding("AES", key_size=256), SHORT_LIVED)
    long_lived = score_in(cipher_finding("AES", key_size=256), LONG_LIVED)

    assert symmetric_score(short) == 0
    assert symmetric_score(long_lived) == 0
    weakness = {r for r in rules(long_lived) if "grover-weakened" in r}
    assert weakness == set(), weakness


def test_aes_256_scores_below_aes_128_for_long_lived_data() -> None:
    """The comparison an operator actually makes when choosing a key size."""
    weak = score_in(cipher_finding("AES", key_size=128), LONG_LIVED)
    strong = score_in(cipher_finding("AES", key_size=256), LONG_LIVED)
    assert total(strong) < total(weak)


def test_3des_is_weakened_regardless_of_lifetime() -> None:
    """Not a Grover question: SP 800-131A Rev.2 disallowed 3DES after 2023.

    Sweet32 (CVE-2016-2183) exploits the 64-bit block, and a short data
    lifetime does not make a 64-bit block bigger. So unlike AES-128, this one
    must NOT scale away to nothing.
    """
    short = score_in(cipher_finding("3DES"), SHORT_LIVED)
    assert total(short) > 0
    assert any("3des" in r or "legacy" in r for r in rules(short)), rules(short)


# ---------------------------------------------------------------------------
# THE CONNECTION TO PART A
# ---------------------------------------------------------------------------


def test_the_rule_needs_the_typed_key_size() -> None:
    """`key_size: {max: 128}` is a NUMERIC comparison.

    This is the dependency between the two halves of ADR-0029, asserted rather
    than asserted-in-prose: a finding whose key size arrives as the string
    "128" must score identically to one carrying the int 128, because Part A
    canonicalises it before the policy engine ever sees it. Without Part A this
    test fails and the symmetric rule silently never fires on half the estate.
    """
    typed = score_in(cipher_finding("AES", key_size=128), LONG_LIVED)
    stringy = score_in(cipher_finding("AES", key_size="128"), LONG_LIVED)

    assert total(stringy) == total(typed), (
        f"a string key_size scored {total(stringy)} where the int scored "
        f"{total(typed)}: Part A's canonicalisation is not reaching the engine"
    )
    assert rules(stringy) == rules(typed)


# ---------------------------------------------------------------------------
# THE VERIFIED-FACT GATE (ADR-0017)
# ---------------------------------------------------------------------------


def test_every_symmetric_rule_is_verified_and_cited() -> None:
    """These facts are well documented, so they must score, not be demoted.

    ADR-0017 demotes an unverified pack fact to a labelled note. SP 800-131A
    Rev.2 and the Grover halving in IR 8547 are published documents, so the
    rules carry `verified: true` with their citation and score legitimately.
    A rule that scored WITHOUT that flag would be exactly what ADR-0017 exists
    to prevent.
    """
    packs = [p for p in default_packs() if p.name == "symmetric"]
    assert packs, "the symmetric pack is not loaded"
    for rule in packs[0].rules:
        assert rule.citation.strip(), f"{rule.id} has no citation"
        assert rule.verified is True, f"{rule.id} is not verified"
        assert (rule.source or "").strip(), f"{rule.id} names no source"


def test_the_symmetric_pack_declares_a_cap() -> None:
    """A category with no ceiling can crowd out every other dimension."""
    packs = [p for p in default_packs() if p.name == "symmetric"]
    assert packs[0].caps.get("symmetric")


# ---------------------------------------------------------------------------
# NO REGRESSION on the asymmetric side
# ---------------------------------------------------------------------------


def test_the_same_rsa_still_scores_critical_here_and_lower_there() -> None:
    """The guard the asymmetric side has always had, unchanged.

    Adding a symmetric category must not disturb it: RSA-2048 is Shor-broken
    whatever the data lifetime, and Mosca is what makes one context worse than
    the other.
    """
    rsa = Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="pke",
        algorithm="RSA",
        params={"key_size": 2048},
        usage="key-transport",
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view="declared", locator="app/keys.py:9", detail="rule=py-rsa"
                )
            ]
        ),
    )
    short = score_in(rsa, SHORT_LIVED)
    long_lived = score_in(rsa, LONG_LIVED)

    assert total(long_lived) > total(short)
    assert short["ecdat:band"] != "Critical"
    assert long_lived["ecdat:band"] == "Critical"


def test_a_symmetric_finding_does_not_reach_critical_on_its_own() -> None:
    """Grover halving is a weakening, not a break, and the score must say so.

    An AES-128 finding that reached Critical would put "use a longer key" in
    the same band as "this is broken by Shor", and an operator who saw that
    once would stop believing the bands.
    """
    long_lived = score_in(cipher_finding("AES", key_size=128), LONG_LIVED)
    assert long_lived["ecdat:band"] != "Critical", long_lived["ecdat:score"]


@pytest.mark.parametrize("data_class", [SHORT_LIVED, LONG_LIVED])
def test_scoring_is_deterministic(data_class: str) -> None:
    first = score_in(cipher_finding("AES", key_size=128), data_class)
    second = score_in(cipher_finding("AES", key_size=128), data_class)
    assert first == second
