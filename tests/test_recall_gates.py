"""ADR-0037 PART B -- an answer-key recall gate is an EQUALITY, never a floor.

ADR-0027's lesson: a floor hides a regression. A pack at 100% behind a 0.9
floor can lose a tenth of its detections and stay green -- and that loss is
exactly what the gate exists to catch. The Python and JS pack gates were
already `== 1.0`. The Go and Java pack gates and the Python dataflow gate were
floors, while each scored 100%.

This is structural on purpose: it reads the test sources, so a floor added to
any gate tomorrow fails here, not months later when a detection quietly goes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

#: A recall assertion that tolerates less than everything.
FLOOR = re.compile(r"\brecall\s*(?:>=|>)\s*0?\.\d")
EXACT = re.compile(r"\brecall\s*==\s*1\.0\b")


def _floors() -> list[str]:
    hits: list[str] = []
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            if FLOOR.search(line):
                hits.append(f"{path.name}:{number}: {line.strip()}")
    return hits


def test_no_answer_key_recall_gate_is_a_floor() -> None:
    assert _floors() == []


@pytest.mark.parametrize(
    "module", ["test_rules_go.py", "test_rules_java.py", "test_dataflow.py"]
)
def test_the_swept_gates_are_exactly_one(module: str) -> None:
    assert EXACT.search((TESTS / module).read_text(encoding="utf-8")), module
