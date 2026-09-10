"""PART A — canonical param types, applied before identity (ADR-0029).

`Finding.params` is an untyped dict, and params are IDENTIFYING: they go into
the blake2b digest that becomes the CycloneDX `bom-ref`. So `key_size: 2048`
and `key_size: "2048"` — the same RSA-2048, reported by two scanners that
happened to disagree about a type — hash to TWO components, and the inventory
shows two artefacts where there is one.

The split is not hypothetical. The source scanner runs `ast.literal_eval` and
gets an int; the container and binary scanners read a version or a size out of
text and get a str; a YAML pack gives whatever the YAML parser decided. Nothing
made them agree, and nothing noticed.

The fix is a canonicalisation pass at the normaliser boundary, before
`finding_identity` is computed. Two rules:

* a KNOWN param is coerced to its canonical type, listed once in
  `core/params.py` with the reason;
* an UNKNOWN param passes through UNCHANGED. Guessing a type for a param no
  pack has declared would invent facts, and would make adding a param to a rule
  a change to core.

This is Part A because Part B's symmetric rule does a NUMERIC comparison on
`key_size` — `key_size: {max: 128}` cannot work against `"128"`.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from core.cbom import dedup
from core.identity import finding_identity
from core.normalise import normalise, validate_cbom_json
from core.params import CANONICAL_TYPES, canonicalise_params
from core.scanner import Target
from core.schema import Evidence, Finding, Occurrence

TARGET = Target(kind="repo", ref="/srv/app", system="paymentsvc")


def finding(**params: Any) -> Finding:
    """One RSA finding whose params are whatever the caller says."""
    return Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="pke",
        algorithm="RSA",
        params=dict(params),
        usage="unknown",
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view="declared", locator="app/keys.py:12", detail="rule=py-rsa"
                )
            ]
        ),
    )


# ---------------------------------------------------------------------------
# THE HASH SPLIT, closed
# ---------------------------------------------------------------------------


def test_an_int_and_a_string_key_size_are_one_artefact() -> None:
    """The bug, stated as one assertion.

    Two scanners, one RSA-2048, two spellings of the same number. Before
    ADR-0029 this produced two bom-refs and an inventory that double-counted
    every key whose size two detectors disagreed about the type of.
    """
    typed = finding(key_size=2048)
    stringy = finding(key_size="2048")

    assert finding_identity(typed, TARGET) == finding_identity(stringy, TARGET)


def test_the_two_spellings_collapse_to_one_component() -> None:
    """End to end, through the normaliser rather than through the hash."""
    components = dedup([finding(key_size=2048), finding(key_size="2048")], TARGET)
    assert len(components) == 1, [f.params for _, f in components]
    (_identity, merged) = components[0]
    assert merged.params["key_size"] == 2048
    assert isinstance(merged.params["key_size"], int)


def test_the_cbom_carries_the_canonical_type() -> None:
    _, cbom_json = normalise([finding(key_size="2048")], TARGET)
    validate_cbom_json(cbom_json)
    document = json.loads(cbom_json)
    assert len(document["components"]) == 1
    values = {
        p["name"]: p["value"] for p in document["components"][0].get("properties", [])
    }
    assert values.get("ecdat:param:key_size") == "2048"


# ---------------------------------------------------------------------------
# The canonical type per known key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("param", "given", "expected"),
    [
        ("key_size", "2048", 2048),
        ("key_size", 2048, 2048),
        ("key_size", " 4096 ", 4096),
        ("mode", "gcm", "GCM"),
        ("mode", "GCM", "GCM"),
        ("mode", "cbc", "CBC"),
        ("curve", "secp256r1", "P-256"),
        ("curve", "prime256v1", "P-256"),
        ("curve", "P-256", "P-256"),
        ("curve", "P256", "P-256"),
        ("version", "tlsv1.2", "TLSv1.2"),
        ("version", "TLSv1.2", "TLSv1.2"),
        ("hybrid", "true", True),
        ("hybrid", True, True),
        ("hybrid", "false", False),
        ("valid_to", "2027-04-05", dt.date(2027, 4, 5)),
        ("valid_to", dt.date(2027, 4, 5), dt.date(2027, 4, 5)),
    ],
)
def test_a_known_param_is_coerced_to_its_canonical_type(
    param: str, given: Any, expected: Any
) -> None:
    assert canonicalise_params({param: given})[param] == expected


def test_an_unknown_param_passes_through_untouched() -> None:
    """Not over-constrained on purpose.

    A param no pack has declared has no canonical type to coerce to. Guessing
    one would invent a fact, and would make adding a param to a rule a change
    to `core/`.
    """
    original: dict[str, Any] = {
        "iteration_count": "600000",
        "provider": "SunJCE",
        "weird": [1, 2, 3],
    }
    assert canonicalise_params(original) == original


def test_a_value_that_will_not_coerce_is_left_alone_rather_than_dropped() -> None:
    """`key_size: "unknown"` is a real thing a scanner reports.

    Coercion that failed silently to `None`, or that raised, would either lose
    the fact or end a scan over somebody else's malformed input. The value
    survives as written, and the identity hash simply keeps distinguishing it.
    """
    assert canonicalise_params({"key_size": "unknown"})["key_size"] == "unknown"
    assert canonicalise_params({"valid_to": "never"})["valid_to"] == "never"


def test_every_canonical_type_has_a_documented_reason() -> None:
    """The table is the one place the types live, so it must say why."""
    assert CANONICAL_TYPES
    for name, entry in CANONICAL_TYPES.items():
        assert entry.why.strip(), f"{name} has no reason recorded"
        assert entry.coerce is not None


def test_canonicalisation_is_idempotent() -> None:
    """Applying it twice must not move a value — the CBOM is re-normalised."""
    once = canonicalise_params(
        {"key_size": "2048", "mode": "gcm", "curve": "secp256r1", "hybrid": "true"}
    )
    assert canonicalise_params(once) == once


# ---------------------------------------------------------------------------
# What must NOT change
# ---------------------------------------------------------------------------


def test_findings_that_already_agreed_keep_their_identity() -> None:
    """Two int key sizes were always one artefact and must stay one."""
    a, b = finding(key_size=2048), finding(key_size=2048)
    assert finding_identity(a, TARGET) == finding_identity(b, TARGET)


def test_different_key_sizes_are_still_different_artefacts() -> None:
    """Canonicalising must not collapse things that genuinely differ."""
    assert finding_identity(finding(key_size=2048), TARGET) != finding_identity(
        finding(key_size=4096), TARGET
    )


def test_normalisation_is_deterministic() -> None:
    first = normalise([finding(key_size="2048")], TARGET)[1]
    second = normalise([finding(key_size="2048")], TARGET)[1]
    assert first == second
