"""Write policy verdicts onto a CBOM as ``ecdat:`` component properties.

Verdicts carry their own honesty markers since ADR-0017: ``ecdat:provisional``
and the repeated ``ecdat:provisional_rule`` say that some of what is displayed
came from a rule nobody has checked against its source, and
``ecdat:deadline_provisional`` says the reported deadline is one of them. None
of them are written when nothing is provisional, so their ABSENCE is the clean
signal that every contributing fact was verified.

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
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml

from policy.engine import (
    Y_YEARS_BASE,
    Y_YEARS_HARDCODED_PENALTY,
    Pack,
    Verdict,
    evaluate,
)

__all__ = [
    "DEFAULT_Z_YEARS",
    "SCORE_INPUT_PROPERTIES",
    "VERDICT_PROPERTIES",
    "Exposure",
    "ScoreInputs",
    "Sector",
    "apply_policy",
    "score_input_properties",
    "verdict_properties",
]

Sector = Literal["defence", "power", "telecom", "bfsi", "other"]
Exposure = Literal["internet", "internal", "build", "unknown"]

#: Z -- years until a cryptographically relevant quantum computer.
#:
#: AN ESTIMATE, AND A CONTESTED ONE. There is no measurement here and there
#: cannot be; expert surveys put a CRQC somewhere in the 2030s with wide
#: disagreement. 11 years (to ~2037) sits inside that range and is deliberately
#: a single global PARAMETER rather than a per-component fact, so an analyst can
#: move it and watch the whole estate re-prioritise. That is the honest way to
#: use a number nobody knows: expose the assumption, do not bury it.
DEFAULT_Z_YEARS = 11

ENV_KNOWLEDGE_DIR = "ECDAT_KNOWLEDGE_DIR"
DEFAULT_KNOWLEDGE_DIR = Path("knowledge")
DATA_CLASS_PACK = Path("data_classes.yaml")

#: Every property this module owns. Listed once so that stripping before a
#: rewrite and writing after cannot drift apart.
SCORE_INPUT_PROPERTIES = (
    "ecdat:data_class",
    "ecdat:x_years",
    "ecdat:x_years_basis",
    "ecdat:y_years",
    "ecdat:y_years_basis",
    "ecdat:z_years",
    "ecdat:z_years_basis",
    "ecdat:sector",
    "ecdat:exposure",
)

VERDICT_PROPERTIES = (
    "ecdat:score",
    "ecdat:band",
    "ecdat:labels",
    "ecdat:deadline",
    "ecdat:actions",
    "ecdat:fired_rules",
    "ecdat:quantum_status",
    "ecdat:category_score",
    "ecdat:provisional",
    "ecdat:provisional_rule",
    "ecdat:deadline_provisional",
)

_INDENT = 2


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """The organisational context a verdict depends on.

    None of this comes from a scan: it is what the operator knows about the
    system being scanned. It is the whole reason the same RSA-2048 can be
    Critical in one place and Medium in another.
    """

    #: Free text matched against knowledge/data_classes.yaml. Unrecognised or
    #: absent yields NO x_years -- never a default of zero. See `_x_years`.
    data_class: str | None = None
    sector: Sector = "other"
    exposure: Exposure = "unknown"
    #: The CRQC horizon. Global, not per-component; the dashboard slider.
    z_years: int = DEFAULT_Z_YEARS
    #: Where knowledge/data_classes.yaml lives. Defaults to the env var or
    #: ``knowledge/``.
    knowledge_dir: Path | None = None


@lru_cache(maxsize=8)
def _data_class_table(knowledge_dir: Path) -> dict[str, tuple[str, int]]:
    """``alias -> (canonical name, x_years)``, lower-cased for matching."""
    path = knowledge_dir / DATA_CLASS_PACK
    if not path.is_file():
        return {}

    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    table: dict[str, tuple[str, int]] = {}
    for entry in document.get("data_classes", []):
        name = str(entry["name"])
        years = int(entry["x_years"])
        table[name.lower()] = (name, years)
        for alias in entry.get("aliases") or ():
            table[str(alias).lower()] = (name, years)
    return table


def _x_years(inputs: ScoreInputs) -> tuple[str, int] | None:
    """The data lifetime, or None when it is genuinely unknown.

    Unknown is not zero. A system nobody has classified is a system nobody has
    assessed, and scoring it as "nothing to protect" would quietly clear the
    exact estate a migration programme exists to find.
    """
    if not inputs.data_class:
        return None
    knowledge = inputs.knowledge_dir or Path(
        os.environ.get(ENV_KNOWLEDGE_DIR, DEFAULT_KNOWLEDGE_DIR)
    )
    return _data_class_table(knowledge).get(inputs.data_class.strip().lower())


def _y_years(component: Mapping[str, Any]) -> int:
    """Migration time in years. An ESTIMATE -- see Y_YEARS_BASE.

    A hard-coded algorithm needs a code change, a review and a redeploy; a
    configured one may need only a config change. Unknown configurability is
    treated as configurable, so the estimate does not inflate on ignorance.
    """
    configurable = next(
        (
            p["value"]
            for p in component.get("properties", [])
            if p.get("name") == "ecdat:configurable"
        ),
        None,
    )
    if configurable == "false":
        return Y_YEARS_BASE + Y_YEARS_HARDCODED_PENALTY
    return Y_YEARS_BASE


def score_input_properties(
    component: Mapping[str, Any], inputs: ScoreInputs
) -> list[dict[str, str]]:
    """The ``ecdat:`` score inputs, written BEFORE any rule evaluates.

    Every estimated term carries a ``_basis`` property saying so in words. A
    number a reader cannot tell apart from a measurement is a number they will
    treat as one.
    """
    properties: list[dict[str, str]] = [
        {"name": "ecdat:sector", "value": inputs.sector},
        {"name": "ecdat:exposure", "value": inputs.exposure},
        {"name": "ecdat:z_years", "value": str(inputs.z_years)},
        {
            "name": "ecdat:z_years_basis",
            "value": (
                "ESTIMATE (global parameter): years until a cryptographically "
                "relevant quantum computer. Contested and adjustable; not a "
                "measurement."
            ),
        },
    ]

    y_years = _y_years(component)
    properties.append({"name": "ecdat:y_years", "value": str(y_years)})
    properties.append(
        {
            "name": "ecdat:y_years_basis",
            "value": (
                f"ESTIMATE (heuristic): base {Y_YEARS_BASE}y"
                + (
                    f" + {Y_YEARS_HARDCODED_PENALTY}y hard-coded penalty"
                    if y_years > Y_YEARS_BASE
                    else ""
                )
                + ". Modelled from configurability, not measured."
            ),
        }
    )

    resolved = _x_years(inputs)
    if resolved is not None:
        canonical, x_years = resolved
        properties.append({"name": "ecdat:data_class", "value": canonical})
        properties.append({"name": "ecdat:x_years", "value": str(x_years)})
        properties.append(
            {
                "name": "ecdat:x_years_basis",
                "value": (
                    f"data_class={canonical} (knowledge/data_classes.yaml); "
                    "a policy default, not a statutory retention period"
                ),
            }
        )
    # No else: an unknown data class writes NO x_years at all, and the mosca
    # pack has a rule that fires on exactly that absence.

    return properties


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

    # Provisional reporting (ADR-0017). Written only when something IS
    # provisional, so a component carrying none of these is one whose every
    # contributing fact was checked -- absence is the clean signal.
    if verdict.provisional_rules:
        properties.append({"name": "ecdat:provisional", "value": "true"})
        properties.extend(
            {"name": "ecdat:provisional_rule", "value": rule_id}
            for rule_id in verdict.provisional_rules
        )
    if verdict.deadline_provisional:
        properties.append({"name": "ecdat:deadline_provisional", "value": "true"})
    return properties


_OWNED_PROPERTIES = frozenset(SCORE_INPUT_PROPERTIES) | frozenset(VERDICT_PROPERTIES)


def _without_owned(properties: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop everything this module writes, so re-applying replaces rather than
    duplicates -- inputs included, since the context may have changed too."""
    return [p for p in properties if p.get("name") not in _OWNED_PROPERTIES]


def apply_policy(
    cbom_json: str,
    packs: Sequence[Pack],
    *,
    inputs: ScoreInputs | None = None,
) -> str:
    """Score every component in ``cbom_json`` and return the scored document.

    Property ordering: the merged list is sorted by name with a STABLE sort, so
    existing name-sorted properties keep their places and repeated names --
    ``ecdat:actions``, ``ecdat:occurrence`` -- keep their meaningful internal
    order rather than being shuffled into value order.
    """
    document = json.loads(cbom_json)
    resolved_inputs = inputs or ScoreInputs()

    for component in document.get("components", []):
        # Order matters: the score inputs are attached FIRST, so a pack's
        # `when` clause can select on sector, exposure and the Mosca terms.
        properties = _without_owned(component.get("properties", []))
        properties.extend(score_input_properties(component, resolved_inputs))
        component["properties"] = properties

        verdict = evaluate(component, packs)
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
