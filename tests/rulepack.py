"""Shared harness for scoring a language rule pack against its answer key.

The Python pack's tests grew this scoring logic first
(``tests/test_scanner_source.py``); Go and JS/TS are scored the same way and
must be scored *separately*, so it lives here rather than being copied twice.

"Separately" is the point of ADR-0023's paired-slice process. One combined
number lets a strong pack carry a weak one: Go at 100% and JS at 60% averages
to something that looks shippable. Two independent scores cannot do that, and
either failing fails the build.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from core.schema import Finding

__all__ = [
    "PackAnswers",
    "load_answers",
    "relative_path_of",
    "rule_id_of",
    "score",
]


class PackAnswers:
    """One language's ``answer_key.yaml``, with its fixture root."""

    def __init__(self, root: Path) -> None:
        self.root = root
        with (root / "answer_key.yaml").open(encoding="utf-8") as handle:
            document: dict[str, Any] = yaml.safe_load(handle)
        self.expected: dict[str, list[dict[str, Any]]] = document["expected"]
        self.sentinels: list[str] = document["secret_sentinels"]

    @property
    def cases(self) -> list[tuple[str, dict[str, Any]]]:
        """``(fixture, expectation)`` for every declared detection."""
        return [
            (fixture, expectation)
            for fixture, expectations in self.expected.items()
            for expectation in expectations
        ]

    @property
    def counts(self) -> Counter[tuple[str, str]]:
        return Counter(
            {
                (fixture, expectation["rule_id"]): expectation["count"]
                for fixture, expectations in self.expected.items()
                for expectation in expectations
            }
        )


def load_answers(root: Path) -> PackAnswers:
    return PackAnswers(root)


def rule_id_of(finding: Finding) -> str:
    rule = finding.raw.get("rule_id")
    assert isinstance(rule, str), f"finding carries no rule_id: {finding!r}"
    return rule


def relative_path_of(finding: Finding, root: Path) -> str:
    """The fixture-relative file a finding's first occurrence points at."""
    locator = finding.evidence.occurrences[0].locator
    path, _, _line = locator.rpartition(":")
    return str(Path(path).resolve().relative_to(root.resolve()))


@dataclass(frozen=True, slots=True)
class Score:
    """Recall and precision for one pack, plus what went wrong."""

    recall: float
    precision: float
    planted: int
    found: int
    emitted: int
    missed: list[tuple[str, str]]
    spurious: list[tuple[str, str]]

    def report(self, language: str) -> str:
        lines = [
            f"\n  {language} rule pack vs its answer key",
            f"  RECALL    {self.recall:6.1%}  ({self.found}/{self.planted} planted)",
            f"  PRECISION {self.precision:6.1%}  ({self.found}/{self.emitted} emitted)",
        ]
        if self.missed:
            lines.append(f"  MISSED    {self.missed}")
        if self.spurious:
            lines.append(f"  SPURIOUS  {self.spurious}")
        return "\n".join(lines)


def score(findings: list[Finding], answers: PackAnswers) -> Score:
    """Recall against the key, precision against the union of every entry.

    Precision counts an OVER-firing rule against itself too: a rule declared
    once that fires three times contributes one true positive and two emitted,
    so the number falls. Only counting undeclared (file, rule) pairs would let a
    rule fire twice on the same line and still score 1.0.
    """
    actual = Counter(
        (relative_path_of(f, answers.root), rule_id_of(f)) for f in findings
    )
    expected = answers.counts

    planted = sum(expected.values())
    found = sum(min(count, actual[key]) for key, count in expected.items())
    emitted = sum(actual.values())

    return Score(
        recall=found / planted if planted else 0.0,
        precision=found / emitted if emitted else 0.0,
        planted=planted,
        found=found,
        emitted=emitted,
        missed=sorted(k for k, c in expected.items() if actual[k] < c),
        spurious=sorted(k for k in actual if k not in expected),
    )
