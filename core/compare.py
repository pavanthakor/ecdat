"""Compare two stored CBOMs: what appeared, what went, what moved (ADR-0031).

The join is the content-addressed bom-ref (ADR-0002), so every bucket is exact:

* **new**       -- a bom-ref only the head document carries
* **resolved**  -- a bom-ref only the base document carries
* **changed**   -- the same bom-ref with a different verdict or different
  evidence, reported with BOTH sides so a reader sees the move, not a delta
* **drift introduced / resolved** -- a drift record present on one side only

The join is also the stated limit. A bom-ref hashes the scope plus the set of
PLACES an artefact was seen, with positions dropped; so a moved line keeps its
bom-ref and reports as changed evidence, while an artefact that gained or lost
a whole sighting place reports as resolved + new. That is the identity telling
the truth about what it can join, and this module does not paper over it with
a fuzzy match -- a guessed pairing would be a diff nobody could audit.

Pure over two parsed documents: nothing is re-scored, re-scanned or stored.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "Change",
    "Comparison",
    "DriftEntry",
    "Entry",
    "Verdict",
    "compare_documents",
]

#: The verdict fields a change reports on, in the order they are listed.
#: `usage`, `algorithm` and params are not here because they are IDENTIFYING
#: (ADR-0029/0030): a different usage is a different bom-ref, so it can only
#: ever show up as resolved + new.
_VERDICT_FIELDS = ("band", "score", "deadline", "quantum_status")


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the policy engine said about one artefact on one side."""

    band: str | None
    score: int | None
    deadline: str | None
    quantum_status: str | None


@dataclass(frozen=True, slots=True)
class Entry:
    """An artefact present on one side only."""

    bom_ref: str
    name: str
    band: str | None
    score: int | None
    deadline: str | None


@dataclass(frozen=True, slots=True)
class Change:
    """The same artefact, judged or evidenced differently."""

    bom_ref: str
    name: str
    fields: list[str]
    before: Verdict
    after: Verdict
    evidence_added: list[str]
    evidence_removed: list[str]


@dataclass(frozen=True, slots=True)
class DriftEntry:
    """One drift record that exists on one side and not the other."""

    bom_ref: str
    name: str
    kind: str
    declared: str
    observed: str
    cause: str


@dataclass(frozen=True, slots=True)
class Comparison:
    new: list[Entry]
    resolved: list[Entry]
    changed: list[Change]
    drift_introduced: list[DriftEntry]
    drift_resolved: list[DriftEntry]
    #: Artefacts on both sides with nothing different. A count, not a list: the
    #: reader needs to know how much did NOT move, not to read it.
    unchanged: int


Component = Mapping[str, Any]


def _values(component: Component, name: str) -> list[str]:
    return [
        str(p.get("value", ""))
        for p in component.get("properties", [])
        if p.get("name") == name
    ]


def _one(component: Component, name: str) -> str | None:
    values = _values(component, name)
    return values[0] if values else None


def _integer(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _verdict(component: Component) -> Verdict:
    return Verdict(
        band=_one(component, "ecdat:band"),
        score=_integer(_one(component, "ecdat:score")),
        deadline=_one(component, "ecdat:deadline"),
        quantum_status=_one(component, "ecdat:quantum_status"),
    )


def _entry(ref: str, component: Component) -> Entry:
    verdict = _verdict(component)
    return Entry(
        bom_ref=ref,
        name=str(component.get("name", "")),
        band=verdict.band,
        score=verdict.score,
        deadline=verdict.deadline,
    )


def _drifts(component: Component) -> dict[tuple[str, str, str], str]:
    """Drift records keyed by (kind, declared, observed), cause as the value.

    The correlator writes one record per PEER (ADR-0012), so the same
    disagreement seen from two processes arrives twice. A diff counts the
    disagreement, not the witnesses; the first cause is kept.
    """
    kinds = _values(component, "ecdat:drift:kind")
    declared = _values(component, "ecdat:drift:declared")
    observed = _values(component, "ecdat:drift:observed")
    causes = _values(component, "ecdat:drift:cause")
    records: dict[tuple[str, str, str], str] = {}
    for index, kind in enumerate(kinds):
        key = (
            kind,
            declared[index] if index < len(declared) else "",
            observed[index] if index < len(observed) else "",
        )
        records.setdefault(key, causes[index] if index < len(causes) else "")
    return records


def _by_ref(document: Mapping[str, Any]) -> dict[str, Component]:
    """Components keyed by bom-ref. The first wins if a document repeats one."""
    indexed: dict[str, Component] = {}
    for component in document.get("components", []):
        ref = str(component.get("bom-ref", ""))
        indexed.setdefault(ref, component)
    return indexed


def _drift_entries(
    refs: Iterable[str],
    components: Mapping[str, Component],
    keep: set[tuple[str, str, str, str]],
) -> list[DriftEntry]:
    entries: list[DriftEntry] = []
    for ref in refs:
        component = components[ref]
        for (kind, declared, observed), cause in _drifts(component).items():
            if (ref, kind, declared, observed) in keep:
                entries.append(
                    DriftEntry(
                        bom_ref=ref,
                        name=str(component.get("name", "")),
                        kind=kind,
                        declared=declared,
                        observed=observed,
                        cause=cause,
                    )
                )
    return sorted(entries, key=lambda d: (d.name, d.bom_ref, d.kind, d.declared))


def _drift_keys(components: Mapping[str, Component]) -> set[tuple[str, str, str, str]]:
    return {
        (ref, kind, declared, observed)
        for ref, component in components.items()
        for (kind, declared, observed) in _drifts(component)
    }


def compare_documents(base: Mapping[str, Any], head: Mapping[str, Any]) -> Comparison:
    """Diff two CBOMs by bom-ref. Deterministic under component order."""
    before = _by_ref(base)
    after = _by_ref(head)

    def order(entry: Entry) -> tuple[str, str]:
        return (entry.name, entry.bom_ref)

    new = sorted((_entry(r, after[r]) for r in after.keys() - before.keys()), key=order)
    resolved = sorted(
        (_entry(r, before[r]) for r in before.keys() - after.keys()), key=order
    )

    changed: list[Change] = []
    unchanged = 0
    for ref in after.keys() & before.keys():
        was, now = _verdict(before[ref]), _verdict(after[ref])
        fields = [f for f in _VERDICT_FIELDS if getattr(was, f) != getattr(now, f)]
        old_evidence = set(_values(before[ref], "ecdat:occurrence"))
        new_evidence = set(_values(after[ref], "ecdat:occurrence"))
        if old_evidence != new_evidence:
            fields.append("evidence")
        if not fields:
            unchanged += 1
            continue
        changed.append(
            Change(
                bom_ref=ref,
                name=str(after[ref].get("name", "")),
                fields=fields,
                before=was,
                after=now,
                evidence_added=sorted(new_evidence - old_evidence),
                evidence_removed=sorted(old_evidence - new_evidence),
            )
        )
    changed.sort(key=lambda c: (c.name, c.bom_ref))

    head_drift = _drift_keys(after)
    base_drift = _drift_keys(before)
    return Comparison(
        new=new,
        resolved=resolved,
        changed=changed,
        drift_introduced=_drift_entries(after, after, head_drift - base_drift),
        drift_resolved=_drift_entries(before, before, base_drift - head_drift),
        unchanged=unchanged,
    )
