"""The policy engine: signed, cited packs of data rules over CBOM components.

Policy-as-code, with the emphasis on *data* (ADR-0007). A pack is YAML: a
selector that is compared, an effect that is arithmetic, and a citation. There
is no expression language, no callable, and nothing that reaches an
interpreter, because a scoring engine is exactly the place an attacker would
want one:

* **A `when` clause is DATA.** Operators are a closed, dispatched set. A value
  that looks like Python is compared as a string. An unknown operator raises at
  load rather than silently never matching -- a typo'd operator that quietly
  fails to fire is a rule that has been removed without anyone deciding to.
* **A pack must be signed and cited.** An unsigned or tampered pack does not
  load. A rule without a citation does not load. Per CLAUDE.md there are no
  uncited crypto facts, and a score nobody can trace is a number nobody should
  act on.
* **Merging is deterministic.** Scores add within a per-category cap, labels
  union and sort, the deadline is the earliest, actions order by (deadline,
  rule id). Pack load order cannot change a verdict.

Scoring deliberately does NOT live in the normaliser. The CBOM is the record of
what was found; a verdict is an opinion about it, and opinions change when NIST
publishes. Keeping them apart means re-scoring an estate is re-running this
over stored documents, not re-scanning it.
"""

from __future__ import annotations

import datetime as dt
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from core.logs import get_logger
from policy import sign

__all__ = [
    "BANDS",
    "CATEGORY_CAP_DEFAULT",
    "DERIVED_FACTS",
    "EFFECT_TYPES",
    "MOSCA_GAP_CEILING",
    "Y_YEARS_BASE",
    "Y_YEARS_HARDCODED_PENALTY",
    "Pack",
    "PackSignatureError",
    "PackValidationError",
    "PolicyError",
    "Rule",
    "Verdict",
    "band_for",
    "component_facts",
    "default_packs",
    "evaluate",
    "load_packs",
    "matches",
    "mosca_contribution",
    "mosca_gap",
]

_log = get_logger("policy")

ENV_POLICY_DIR = "ECDAT_POLICY_DIR"
ENV_POLICY_DEV = "ECDAT_POLICY_DEV"
DEFAULT_PACK_DIR = Path("policy/packs")
DEFAULT_PUBLIC_KEY = Path("policy/keys/dev/pack-signing.pub")

#: Score -> band. Ordered high to low; the first threshold met wins.
BANDS: tuple[tuple[int, str], ...] = (
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (0, "Low"),
)

#: Cap applied to a category no pack declares a cap for. A category with no
#: ceiling lets one pack's rules drown out every other pack's, so there is
#: always a ceiling; packs narrow it, nothing widens it.
CATEGORY_CAP_DEFAULT = 40

#: Most severe first. When several rules set `quantum_status`, the worst wins,
#: so adding a reassuring rule can never mask a damning one.
_QUANTUM_STATUS_SEVERITY = ("broken", "weakened", "adequate", "pqc")

# ---------------------------------------------------------------------------
# Mosca's inequality
#
# x + y > z  --  if the time data must stay secret (x) plus the time migration
# takes (y) exceeds the time until a cryptographically relevant quantum
# computer (z), then data encrypted TODAY is already lost. The gap is how many
# years late you already are.
#
# This is the ONLY arithmetic in the policy system that is not a plain sum of
# rule scores, and it lives here -- one named, tested function -- specifically
# so the selector grammar never needs an expression language to express it.
# A pack asks for it by name (`effect: {type: mosca_urgency}`); it cannot
# describe a different calculation. See ADR-0008.
# ---------------------------------------------------------------------------

#: Gap in years at which Mosca urgency reaches the category cap. Below this the
#: contribution scales linearly. 20 years is a full migration-planning horizon:
#: being two decades late is as urgent as this dimension can express, and
#: everything worse is already maximally urgent.
MOSCA_GAP_CEILING = 20

#: Y -- migration time in years, for a component that is configurable.
#:
#: AN ESTIMATE, NOT A MEASUREMENT. Mosca's y is meant to be measured for a
#: specific organisation; ECDAT cannot measure it from a scan, so it models it.
#: The base is the low end of published enterprise crypto-migration experience;
#: the penalty reflects that a hard-coded algorithm needs a code change, review
#: and redeploy where a configured one may need only a config change. Every
#: emitted y_years carries a basis string saying it is an estimate.
Y_YEARS_BASE = 3

#: Added to Y when the finding is hard-coded (``configurable == False``).
Y_YEARS_HARDCODED_PENALTY = 2

#: Effect types a rule may name. Closed, like the selector vocabulary: an
#: unknown type is refused at load rather than silently scoring zero.
EFFECT_TYPES = frozenset({"mosca_urgency"})

#: Facts that are produced by evaluation rather than read off the component.
#: A rule selecting on one of these runs in the second pass; see `evaluate`.
DERIVED_FACTS = frozenset({"quantum_status"})


def mosca_gap(x_years: int | None, y_years: int, z_years: int) -> int | None:
    """``(x + y) - z``, or ``None`` when the data lifetime is unknown.

    ``None`` is not zero and must never be treated as zero. An unclassified
    system is one nobody has assessed, not one that is safe; scoring it as safe
    is the exact failure this returns ``None`` to prevent.
    """
    if x_years is None:
        return None
    return int(x_years) + int(y_years) - int(z_years)


def mosca_contribution(gap: int | None, cap: int) -> int:
    """Scale a Mosca gap onto ``[0, cap]``.

    Integer arithmetic throughout: a float here would make the score depend on
    binary rounding, and the determinism guarantee is about bytes.
    """
    if gap is None or gap <= 0:
        return 0
    return min(cap, (cap * gap) // MOSCA_GAP_CEILING)


class PolicyError(Exception):
    """Base class for policy problems."""


class PackValidationError(PolicyError, ValueError):
    """A pack is malformed, uncited, or uses an operator that does not exist."""


class PackSignatureError(PolicyError, ValueError):
    """A pack is unsigned, or its signature does not verify."""


# ---------------------------------------------------------------------------
# The selector -- data only
# ---------------------------------------------------------------------------

#: The complete operator vocabulary. Anything else is an error, by design.
_OPERATORS = frozenset({"eq", "in", "not_in", "min", "max", "present", "contains"})

_MISSING = object()


def _compare(operators: Mapping[str, Any], value: Any) -> bool:
    """Apply one field's operator mapping. Every operator must hold."""
    unsupported = sorted(set(operators) - _OPERATORS)
    if unsupported:
        raise PackValidationError(
            f"unsupported selector operator(s) {unsupported}; "
            f"the vocabulary is {sorted(_OPERATORS)}"
        )

    for operator, operand in operators.items():
        if operator == "present":
            if bool(operand) is not (value is not _MISSING):
                return False
            continue

        if value is _MISSING:
            # Absent never satisfies a value comparison. Reading absence as a
            # match would make every unqualified rule fire on everything.
            return False

        if operator == "eq" and value != operand:
            return False
        if operator == "in" and value not in operand:
            return False
        if operator == "not_in" and value in operand:
            return False
        if operator == "contains" and (
            not isinstance(value, list | tuple | set) or operand not in value
        ):
            return False
        if operator in ("min", "max"):
            number = _as_number(value)
            if number is None:
                return False
            if operator == "min" and number < operand:
                return False
            if operator == "max" and number > operand:
                return False
    return True


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def matches(when: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Whether a `when` clause matches a component's facts.

    Keys are ANDed. A bare scalar is equality; a mapping is an operator set.

    Everything here is comparison. ``when`` values are never parsed, formatted,
    interpolated or evaluated -- a value of ``"__import__('os').system('rm')"``
    is a string that equals some component names and not others, and nothing
    else happens to it. See ADR-0007.
    """
    for field_name, expected in when.items():
        value = facts.get(field_name, _MISSING)
        if isinstance(expected, Mapping):
            if not _compare(expected, value):
                return False
        elif value is _MISSING or value != expected:
            return False
    return True


# ---------------------------------------------------------------------------
# The projection a selector sees
# ---------------------------------------------------------------------------


def _algorithm_from(name: str, params: Mapping[str, str], asset_type: str) -> str:
    """Recover the canonical algorithm from a component name.

    The exact inverse of ``core.cbom._component_name``, driven by the params
    rather than by the shape of the string -- which is why ``SHA-1`` keeps its
    ``-1`` while ``RSA-2048`` loses its ``-2048``. A regex could not tell those
    apart. ``test_the_projection_matches_real_normaliser_output`` pins this
    against real normaliser output so a change there fails loudly.
    """
    if asset_type == "protocol":
        version = params.get("version")
        if version and name.endswith(f" {version}"):
            return name[: -len(version) - 1]
        return name

    for key in ("key_size", "curve"):
        suffix = params.get(key)
        if suffix and name.endswith(f"-{suffix}"):
            return name[: -len(suffix) - 1]
    return name


#: ``ecdat:`` properties that are SCORE INPUTS rather than verdict outputs,
#: mapped to the fact name a selector addresses. Written onto the component by
#: policy.apply before any rule runs, so a pack can match on organisational
#: context (sector, exposure) and on the Mosca terms. A closed allowlist, so
#: adding a new input is a deliberate edit here and not an accident of naming.
SCORE_INPUT_FACTS = {
    "ecdat:x_years": "x_years",
    "ecdat:y_years": "y_years",
    "ecdat:z_years": "z_years",
    "ecdat:sector": "sector",
    "ecdat:exposure": "exposure",
    "ecdat:data_class": "data_class",
    "ecdat:configurable": "configurable",
}


def component_facts(component: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten a CBOM component into the fields a selector may address.

    Documented surface, in precedence order (structured fields win over params
    of the same name):

    ``name``, ``algorithm``, ``component_type``, ``asset_type``, ``primitive``,
    ``usage``, ``views`` (list), ``nist_quantum_security_level``,
    ``classical_security_level``, plus every ``ecdat:param:X`` as ``X``
    (``key_size``, ``curve``, ``mode``, ``version``, ``pqc_capable``, ...),
    plus the score inputs in :data:`SCORE_INPUT_FACTS` (``x_years``,
    ``y_years``, ``z_years``, ``sector``, ``exposure``, ``data_class``,
    ``configurable``) when policy.apply has attached them.

    One fact is NOT read from the component: ``quantum_status`` is produced by
    evaluation, and rules selecting on it run in a second pass -- see
    :func:`evaluate`.

    Numeric-looking params are converted to numbers so range operators work
    without every pack having to quote them.
    """
    facts: dict[str, Any] = {}
    params: dict[str, str] = {}
    views: list[str] = []

    for prop in component.get("properties", []):
        prop_name = prop.get("name", "")
        value = prop.get("value", "")
        if prop_name.startswith("ecdat:param:"):
            params[prop_name.removeprefix("ecdat:param:")] = value
        elif prop_name == "ecdat:view":
            views.append(value)
        elif prop_name == "ecdat:usage":
            facts["usage"] = value
        elif prop_name == "ecdat:asset_type":
            facts["asset_type"] = value
        elif prop_name in SCORE_INPUT_FACTS:
            facts[SCORE_INPUT_FACTS[prop_name]] = _coerce(value)

    for key, raw in params.items():
        facts[key] = _coerce(raw)

    crypto = component.get("cryptoProperties", {})
    algorithm_properties = crypto.get("algorithmProperties", {})
    if "assetType" in crypto:
        facts["asset_type"] = crypto["assetType"]
    if "primitive" in algorithm_properties:
        facts["primitive"] = algorithm_properties["primitive"]
    if "nistQuantumSecurityLevel" in algorithm_properties:
        facts["nist_quantum_security_level"] = algorithm_properties[
            "nistQuantumSecurityLevel"
        ]
    if "classicalSecurityLevel" in algorithm_properties:
        facts["classical_security_level"] = algorithm_properties[
            "classicalSecurityLevel"
        ]

    name = str(component.get("name", ""))
    facts["name"] = name
    facts["component_type"] = component.get("type")
    facts["views"] = sorted(views)
    facts["algorithm"] = _algorithm_from(
        name, params, str(facts.get("asset_type", "algorithm"))
    )
    return facts


def _coerce(raw: str) -> Any:
    if raw in ("true", "True"):
        return True
    if raw in ("false", "False"):
        return False
    try:
        return int(raw)
    except ValueError:
        return raw


# ---------------------------------------------------------------------------
# Packs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rule:
    """One scoring rule: a data selector, an effect, and a citation."""

    id: str
    pack: str
    when: Mapping[str, Any]
    effect: Mapping[str, Any]
    citation: str


@dataclass(frozen=True, slots=True)
class Pack:
    """A versioned, signed, cited collection of rules."""

    name: str
    version: int
    citation: str
    #: Per-category score ceilings this pack declares. The cap table lives in
    #: the pack header so the rules that create a category and the ceiling on
    #: that category version together. See ADR-0007.
    caps: Mapping[str, int]
    rules: Sequence[Rule]


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the packs say about one component."""

    score: int
    band: str
    labels: tuple[str, ...] = ()
    deadline: dt.date | None = None
    actions: tuple[str, ...] = ()
    fired_rules: tuple[str, ...] = ()
    quantum_status: str | None = None
    #: Per-category subtotals after capping. Diagnostic, not part of equality
    #: for scoring purposes -- but included so a reviewer can see the split.
    categories: Mapping[str, int] = field(default_factory=dict)


def band_for(score: int) -> str:
    """Map a total score onto its band. >=80 Critical, 60 High, 40 Medium."""
    for threshold, band in BANDS:
        if score >= threshold:
            return band
    return BANDS[-1][1]  # pragma: no cover - the 0 threshold always matches


_REQUIRED_EFFECT_KEYS = ("score", "category")
_ALLOWED_EFFECT_KEYS = frozenset(
    {
        "score",
        "category",
        "label",
        "labels",
        "deadline",
        "action",
        "actions",
        "quantum_status",
        "type",
    }
)


def _parse_rule(raw: Mapping[str, Any], pack_name: str, source: Path) -> Rule:
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PackValidationError(f"{source}: a rule has no id")

    citation = raw.get("citation")
    if not isinstance(citation, str) or not citation.strip():
        raise PackValidationError(
            f"{source}: rule {rule_id!r} has no citation. Every rule must cite "
            "its source (FIPS number, NIST SP/IR section, RFC); an unciteable "
            "score is one nobody can act on."
        )

    when = raw.get("when")
    if not isinstance(when, Mapping) or not when:
        raise PackValidationError(f"{source}: rule {rule_id!r} has no `when` clause")

    effect = raw.get("effect")
    if not isinstance(effect, Mapping):
        raise PackValidationError(f"{source}: rule {rule_id!r} has no `effect`")
    required = ("category",) if "type" in effect else _REQUIRED_EFFECT_KEYS
    for key in required:
        if key not in effect:
            raise PackValidationError(
                f"{source}: rule {rule_id!r} effect is missing {key!r}"
            )
    unknown = sorted(set(effect) - _ALLOWED_EFFECT_KEYS)
    if unknown:
        raise PackValidationError(
            f"{source}: rule {rule_id!r} effect has unknown key(s) {unknown}"
        )
    effect_type = effect.get("type")
    if effect_type is not None:
        if effect_type not in EFFECT_TYPES:
            raise PackValidationError(
                f"{source}: rule {rule_id!r} effect type {effect_type!r} is not "
                f"one of {sorted(EFFECT_TYPES)}. Effect types are a closed "
                "vocabulary: a pack names a computation, it cannot describe one."
            )
        if "score" in effect:
            raise PackValidationError(
                f"{source}: rule {rule_id!r} sets both `type` and `score`; a "
                "computed effect must not also carry a literal score"
            )
    elif not isinstance(effect["score"], int) or isinstance(effect["score"], bool):
        raise PackValidationError(
            f"{source}: rule {rule_id!r} score must be an integer"
        )

    # Validate the selector now rather than at first evaluation, so a typo is a
    # load failure and not a rule that silently never fires.
    for expected in when.values():
        if isinstance(expected, Mapping):
            unsupported = sorted(set(expected) - _OPERATORS)
            if unsupported:
                raise PackValidationError(
                    f"{source}: rule {rule_id!r} uses unsupported selector "
                    f"operator(s) {unsupported}; the vocabulary is "
                    f"{sorted(_OPERATORS)}"
                )

    return Rule(
        id=rule_id,
        pack=pack_name,
        when=dict(when),
        effect=dict(effect),
        citation=citation,
    )


def _parse_pack(path: Path, body: bytes) -> Pack:
    document = yaml.safe_load(body.decode("utf-8"))
    if not isinstance(document, Mapping):
        raise PackValidationError(f"{path}: not a mapping")

    name = document.get("pack")
    if not isinstance(name, str) or not name.strip():
        raise PackValidationError(f"{path}: missing `pack` name")

    citation = document.get("citation")
    if not isinstance(citation, str) or not citation.strip():
        raise PackValidationError(f"{path}: pack {name!r} has no citation")

    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PackValidationError(f"{path}: pack {name!r} has no rules")

    caps = document.get("caps") or {}
    if not isinstance(caps, Mapping):
        raise PackValidationError(f"{path}: pack {name!r} `caps` must be a mapping")

    return Pack(
        name=name,
        version=int(document.get("version", 1)),
        citation=citation,
        caps={str(k): int(v) for k, v in caps.items()},
        rules=[_parse_rule(r, name, path) for r in raw_rules],
    )


def load_packs(
    directory: Path | str,
    *,
    dev: bool = False,
    public_key_path: Path | str | None = None,
) -> list[Pack]:
    """Load, verify and validate every ``*.yaml`` pack in ``directory``.

    Packs are returned sorted by name so the caller cannot depend on filesystem
    ordering.

    ``dev=True`` skips SIGNATURE verification only, and logs loudly each time.
    Every other gate -- citations, schema, operator vocabulary, duplicate rule
    ids -- still applies, because those catch mistakes rather than attacks and
    a developer needs them most.
    """
    root = Path(directory)
    public_key = Path(public_key_path) if public_key_path else DEFAULT_PUBLIC_KEY

    packs: list[Pack] = []
    for path in sorted(root.glob("*.yaml")):
        body = path.read_bytes()

        if dev:
            _log.warning(
                "pack_signature_skipped",
                extra={
                    "event": "pack_signature_skipped",
                    "pack_path": str(path),
                    "detail": (
                        "dev mode: pack signature verification was SKIPPED. "
                        "Never run a scan anyone will act on in this mode."
                    ),
                },
            )
        else:
            sign.verify_file(path, public_key)

        packs.append(_parse_pack(path, body))

    seen: dict[str, str] = {}
    for pack in packs:
        for rule in pack.rules:
            if rule.id in seen:
                raise PackValidationError(
                    f"duplicate rule id {rule.id!r} in packs {seen[rule.id]!r} "
                    f"and {pack.name!r}; rule ids appear in fired_rules and "
                    "must identify exactly one rule"
                )
            seen[rule.id] = pack.name

    return sorted(packs, key=lambda p: p.name)


def default_packs() -> list[Pack]:
    """The packs a scan uses. Signed unless ECDAT_POLICY_DEV=1 says otherwise."""
    directory = Path(os.environ.get(ENV_POLICY_DIR, DEFAULT_PACK_DIR))
    return load_packs(directory, dev=os.environ.get(ENV_POLICY_DEV) == "1")


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _as_date(value: Any) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _listed(effect: Mapping[str, Any], singular: str, plural: str) -> list[str]:
    values: list[str] = []
    one = effect.get(singular)
    if isinstance(one, str):
        values.append(one)
    many = effect.get(plural)
    if isinstance(many, list):
        values.extend(str(v) for v in many)
    return values


def _is_derived_rule(rule: Rule) -> bool:
    """Whether a rule selects on a fact that evaluation itself produces."""
    return any(key in DERIVED_FACTS for key in rule.when)


def evaluate(component: Mapping[str, Any], packs: Iterable[Pack]) -> Verdict:
    """Score one CBOM component against every rule in every pack.

    Merge semantics, all deterministic and all pinned by tests:

    * **score** -- contributions ADD within a category, then each category is
      CAPPED, then the capped subtotals sum. Capping per category rather than
      globally stops one dimension of risk from crowding out the others: ten
      quantum rules on one component cannot bury a single critical hygiene
      finding, and it is what lets Criticality mean "bad along several axes"
      rather than "many rules fired".
    * **labels** -- union, sorted.
    * **deadline** -- the EARLIEST any rule demands. A later deadline never
      relaxes an earlier one.
    * **actions** -- ordered by (deadline, rule id), soonest first, deduped.
    * **fired_rules** -- sorted.
    * **quantum_status** -- most severe wins.

    **Two passes.** A rule may select on ``quantum_status``, which is a verdict
    output rather than a property of the component -- "if this is Shor-broken
    AND it is in a critical sector" is a rule the India DST pack genuinely
    needs. Pass one runs every rule that does not, producing the derived facts;
    pass two runs the rules that do, against those facts. Exactly two passes,
    so a pass-two rule cannot feed another pass-two rule and there is no
    fixpoint to reason about. Contributions from both passes merge identically.
    """
    facts = dict(component_facts(component))

    caps: dict[str, int] = {}
    for pack in packs:
        for category, cap in pack.caps.items():
            # Narrowest cap wins: a pack may tighten a ceiling, never widen it.
            caps[category] = min(caps.get(category, cap), cap)

    subtotals: dict[str, int] = {}
    labels: set[str] = set()
    fired: list[str] = []
    deadlines: list[dt.date] = []
    actions: list[tuple[dt.date, str, str]] = []
    statuses: set[str] = set()

    def run(rules: Iterable[Rule]) -> None:
        for rule in rules:
            if not matches(rule.when, facts):
                continue

            fired.append(rule.id)
            effect = rule.effect
            category = str(effect["category"])

            if effect.get("type") == "mosca_urgency":
                contribution = mosca_contribution(
                    mosca_gap(
                        facts.get("x_years"),
                        int(facts.get("y_years", Y_YEARS_BASE)),
                        int(facts.get("z_years", 0)),
                    ),
                    caps.get(category, CATEGORY_CAP_DEFAULT),
                )
            else:
                contribution = int(effect["score"])

            subtotals[category] = subtotals.get(category, 0) + contribution
            labels.update(_listed(effect, "label", "labels"))

            status = effect.get("quantum_status")
            if isinstance(status, str):
                statuses.add(status)

            deadline = _as_date(effect.get("deadline"))
            if deadline is not None:
                deadlines.append(deadline)

            # A rule with no deadline sorts after every dated one.
            sort_date = deadline or dt.date.max
            for action in _listed(effect, "action", "actions"):
                actions.append((sort_date, rule.id, action))

    all_rules = [rule for pack in packs for rule in pack.rules]
    run(r for r in all_rules if not _is_derived_rule(r))

    quantum_status = next((s for s in _QUANTUM_STATUS_SEVERITY if s in statuses), None)
    if quantum_status is not None:
        facts["quantum_status"] = quantum_status
    run(r for r in all_rules if _is_derived_rule(r))

    # Recomputed: a second-pass rule may itself assert a status.
    quantum_status = next((s for s in _QUANTUM_STATUS_SEVERITY if s in statuses), None)

    capped = {
        category: min(total, caps.get(category, CATEGORY_CAP_DEFAULT))
        for category, total in sorted(subtotals.items())
    }
    score = sum(capped.values())

    ordered_actions: list[str] = []
    for _date, _rule_id, action in sorted(actions):
        if action not in ordered_actions:
            ordered_actions.append(action)

    return Verdict(
        score=score,
        band=band_for(score),
        labels=tuple(sorted(labels)),
        deadline=min(deadlines) if deadlines else None,
        actions=tuple(ordered_actions),
        fired_rules=tuple(sorted(fired)),
        quantum_status=quantum_status,
        categories=capped,
    )


#: Re-exported so callers can annotate without importing dataclasses.
QuantumStatus = Literal["broken", "weakened", "adequate", "pqc"]
