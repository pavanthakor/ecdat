"""Write policy verdicts onto a CBOM as ``ecdat:`` component properties.

Separate from the engine on purpose: :mod:`policy.engine` decides what a
component is worth and knows nothing about CycloneDX, while this module knows
where a verdict goes in the document and nothing about how it was reached.

Byte-stability is the contract, same as the normaliser's (ADR-0002): the same
CBOM and the same packs must produce byte-identical output, because a scored
document is stored and diffed. Two things secure that -- serialisation is
canonical (sorted keys, fixed indent), and the verdict itself is deterministic.

Applying policy twice is a no-op rather than a duplication: existing ``ecdat:``
verdict properties are stripped before the new ones are written, so re-scoring
a stored document with an updated pack replaces the old verdict instead of
accumulating a second one beside it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from policy.engine import Pack, Verdict, evaluate

__all__ = ["VERDICT_PROPERTIES", "apply_policy", "verdict_properties"]

#: Every property this module owns. Listed once so that stripping before a
#: rewrite and writing after cannot drift apart.
VERDICT_PROPERTIES = (
    "ecdat:score",
    "ecdat:band",
    "ecdat:labels",
    "ecdat:deadline",
    "ecdat:actions",
    "ecdat:fired_rules",
    "ecdat:quantum_status",
    "ecdat:category_score",
)

_INDENT = 2


def verdict_properties(verdict: Verdict) -> list[dict[str, str]]:
    """A verdict as CycloneDX properties, in the order they will be written.

    ``ecdat:actions`` repeats -- one property per action, in the verdict's
    (deadline, rule id) order -- the same convention the normaliser already
    uses for ``ecdat:occurrence``. Actions are prose and may contain commas, so
    joining them into one value would not survive a reader splitting it.
    """
    properties: list[dict[str, str]] = [
        {"name": "ecdat:score", "value": str(verdict.score)},
        {"name": "ecdat:band", "value": verdict.band},
    ]
    if verdict.labels:
        properties.append({"name": "ecdat:labels", "value": ",".join(verdict.labels)})
    if verdict.deadline is not None:
        properties.append(
            {"name": "ecdat:deadline", "value": verdict.deadline.isoformat()}
        )
    if verdict.quantum_status is not None:
        properties.append(
            {"name": "ecdat:quantum_status", "value": verdict.quantum_status}
        )
    if verdict.fired_rules:
        properties.append(
            {"name": "ecdat:fired_rules", "value": ",".join(verdict.fired_rules)}
        )
    properties.extend(
        {"name": "ecdat:category_score", "value": f"{category}={score}"}
        for category, score in sorted(verdict.categories.items())
    )
    properties.extend(
        {"name": "ecdat:actions", "value": action} for action in verdict.actions
    )
    return properties


def _without_verdict(properties: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [p for p in properties if p.get("name") not in VERDICT_PROPERTIES]


def apply_policy(cbom_json: str, packs: Sequence[Pack]) -> str:
    """Score every component in ``cbom_json`` and return the scored document.

    Property ordering: the merged list is sorted by name with a STABLE sort, so
    existing name-sorted properties keep their places and repeated names --
    ``ecdat:actions``, ``ecdat:occurrence`` -- keep their meaningful internal
    order rather than being shuffled into value order.
    """
    document = json.loads(cbom_json)

    for component in document.get("components", []):
        verdict = evaluate(component, packs)
        properties = _without_verdict(component.get("properties", []))
        properties.extend(verdict_properties(verdict))
        component["properties"] = sorted(properties, key=lambda p: p["name"])

    return (
        json.dumps(
            document,
            indent=_INDENT,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )
