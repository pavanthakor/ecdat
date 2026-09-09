"""The post-policy correlation pass: write drift onto the stored CBOM.

Runs after policy scoring and before the store, so a stored CBOM already
carries both its verdicts and its drift. Like ``policy.apply``, it is
byte-stable and idempotent: the same document and the same rules produce the
same bytes, and re-running replaces the drift rather than accumulating it.

**Why drift raises the score.** A drifted component is floored to High and its
score multiplied, because **an inventory error is worse than a known
weakness.** A system with a documented RSA-2048 is a system you can plan a
migration for; a system that says it negotiates ML-KEM and does not is a system
whose entire inventory is now suspect -- you cannot plan around a description
that is wrong, and you do not know what else is wrong.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from correlate.drift import Drift, detect
from correlate.identity import group_components
from policy.engine import BANDS, band_for

__all__ = [
    "DRIFT_FLOOR_BAND",
    "DRIFT_PROPERTIES",
    "DRIFT_RISK_MULTIPLIER",
    "apply_drift",
    "correlate_document",
]

#: Every property this module owns, so stripping before a rewrite and writing
#: after cannot drift apart.
DRIFT_PROPERTIES = (
    "ecdat:drift:kind",
    "ecdat:drift:declared",
    "ecdat:drift:observed",
    "ecdat:drift:cause",
    "ecdat:drift:evidence",
    "ecdat:drift:peer",
    "ecdat:drift:confidence",
    "ecdat:drift:pre_drift_score",
    "ecdat:coverage:views",
    "ecdat:coverage:missing",
)

#: Drift multiplies the component's existing risk rather than adding a fixed
#: amount, so a serious artefact that also drifts outranks a trivial one that
#: does. 1.25 is deliberately modest: drift is a reason to look, and the floor
#: below is what guarantees it gets looked at.
DRIFT_RISK_MULTIPLIER = 1.25

#: No drifted component may sit below this band, whatever it scored before.
#: This is the load-bearing half: the multiplier alone would leave a Low
#: component Low, and a wrong description of a low-risk asset is still a wrong
#: description.
DRIFT_FLOOR_BAND = "High"

_INDENT = 2

_BAND_SEVERITY = {band: index for index, (_score, band) in enumerate(BANDS)}


def _floor_score() -> int:
    """The lowest score that lands in DRIFT_FLOOR_BAND."""
    return next(score for score, band in BANDS if band == DRIFT_FLOOR_BAND)


def _system_of(document: dict[str, Any]) -> str:
    metadata = document.get("metadata", {}).get("component", {})
    return str(metadata.get("name", "")) or "system"


def _properties(component: dict[str, Any], name: str) -> list[str]:
    return [
        p["value"] for p in component.get("properties", []) if p.get("name") == name
    ]


def _without_owned(properties: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [p for p in properties if p.get("name") not in DRIFT_PROPERTIES]


def correlate_document(document: dict[str, Any]) -> dict[str, list[Drift]]:
    """``bom-ref -> drifts``, deterministic in component order."""
    system = _system_of(document)
    by_ref: dict[str, list[Drift]] = {}
    for group in group_components(document.get("components", []), system):
        for drift in detect(group):
            by_ref.setdefault(drift.affected, []).append(drift)
    for drifts in by_ref.values():
        drifts.sort(key=lambda d: (d.kind, d.declared, d.observed))
    return by_ref


def _drift_properties(drifts: Sequence[Drift], previous: int) -> list[dict[str, str]]:
    properties: list[dict[str, str]] = [
        {"name": "ecdat:drift:pre_drift_score", "value": str(previous)}
    ]
    for drift in drifts:
        properties.append({"name": "ecdat:drift:kind", "value": drift.kind})
        properties.append({"name": "ecdat:drift:declared", "value": drift.declared})
        properties.append({"name": "ecdat:drift:observed", "value": drift.observed})
        properties.append({"name": "ecdat:drift:cause", "value": drift.cause})
        properties.append(
            {"name": "ecdat:drift:confidence", "value": str(drift.confidence)}
        )
        # Each contributing view is cited. A drift claim that cannot show a
        # sighting from both sides is not a claim.
        properties.extend(
            {"name": "ecdat:drift:evidence", "value": f"{view}|{locator}"}
            for view, locator in drift.evidence
        )
        # Peer attribution comes from the occurrence detail, because ADR-0002
        # folds a client and a server on one host into one component.
        properties.extend(
            {"name": "ecdat:drift:peer", "value": peer} for peer in drift.peers
        )
    return properties


def _apply_effect(component: dict[str, Any], previous: int) -> None:
    """Raise the score and floor the band. See the module docstring."""
    raised = min(100, int(previous * DRIFT_RISK_MULTIPLIER + 0.5))
    raised = max(raised, _floor_score())

    band = band_for(raised)
    if _BAND_SEVERITY[band] > _BAND_SEVERITY[DRIFT_FLOOR_BAND]:
        band = DRIFT_FLOOR_BAND

    properties = [
        p
        for p in component["properties"]
        if p.get("name") not in ("ecdat:score", "ecdat:band")
    ]
    properties.append({"name": "ecdat:score", "value": str(raised)})
    properties.append({"name": "ecdat:band", "value": band})
    component["properties"] = properties


def apply_drift(cbom_json: str) -> str:
    """Correlate a stored CBOM and write drift onto the affected components."""
    document = json.loads(cbom_json)
    system = _system_of(document)

    # Remember each component's score from BEFORE any previous drift pass, then
    # strip, so re-running replaces the previous pass rather than compounding
    # its multiplier on top of itself.
    original: dict[str, int] = {}
    for component in document.get("components", []):
        ref = str(component.get("bom-ref", ""))
        carried = _properties(component, "ecdat:drift:pre_drift_score")
        current = _properties(component, "ecdat:score")
        original[ref] = int((carried or current or ["0"])[0])
        component["properties"] = _without_owned(component.get("properties", []))

    by_ref = correlate_document(document)
    coverage = {
        ref: group
        for group in group_components(document.get("components", []), system)
        for ref in [str(c.get("bom-ref", "")) for c in group.declared]
    }

    for component in document.get("components", []):
        ref = str(component.get("bom-ref", ""))
        properties = list(component["properties"])

        group = coverage.get(ref)
        if group is not None:
            # Coverage is reported whether or not anything drifted: "we did not
            # look" and "they agree" are different answers.
            properties.append(
                {
                    "name": "ecdat:coverage:views",
                    "value": ",".join(sorted(group.views)),
                }
            )
            if group.missing_views:
                properties.append(
                    {
                        "name": "ecdat:coverage:missing",
                        "value": ",".join(sorted(group.missing_views)),
                    }
                )

        drifts = by_ref.get(ref)
        if drifts:
            previous = original.get(ref, 0)
            properties.extend(_drift_properties(drifts, previous))
            component["properties"] = properties
            _apply_effect(component, previous)
        else:
            component["properties"] = properties

        # Stable sort by name: repeated names (evidence, peer) keep their
        # meaningful order, everything else lands where a reader expects it.
        component["properties"] = sorted(
            component["properties"], key=lambda p: p["name"]
        )

    # Components are emitted in bom-ref order. The normaliser already orders
    # them by identity (which IS the bom-ref), so this preserves its ordering
    # while making the correlator's output independent of the order components
    # happened to arrive in -- `sort_keys` sorts dict keys, not list elements.
    document["components"] = sorted(
        document.get("components", []),
        key=lambda c: str(c.get("bom-ref", c.get("name", ""))),
    )

    return (
        json.dumps(document, indent=_INDENT, sort_keys=True, ensure_ascii=False) + "\n"
    )
