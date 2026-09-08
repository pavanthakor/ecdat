"""Regenerate tests/golden/quantumbank.cbom.json (`make golden`).

The golden CBOM is the byte-level determinism guard: it is committed, and
test_cbom compares fresh output against it. Regenerate it only when a CBOM
change is intended, and review the diff -- an unexplained change means the
normaliser stopped being deterministic.
"""

from __future__ import annotations

from pathlib import Path

from core.normalise import normalise
from tests.factories import golden_findings, golden_target

GOLDEN = Path(__file__).parent / "golden" / "quantumbank.cbom.json"


def main() -> None:
    _, cbom_json = normalise(golden_findings(), golden_target())
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(cbom_json, encoding="utf-8")
    print(f"wrote {GOLDEN} ({len(cbom_json)} bytes)")


if __name__ == "__main__":
    main()
