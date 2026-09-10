"""The verdict summary of a CBOM: one definition, two consumers.

The store denormalises this onto the scan row at save time; the API serves it
from those columns. Before ADR-0016 the API computed it by parsing every stored
document on every list request, and the shape of the calculation lived in
``api/app.py`` -- so "what the dashboard shows" and "what the database records"
were two implementations that could disagree. They are one now.

Everything here is read out of the document rather than recomputed from the
packs, deliberately: a summary must report **what was stored**, not what
today's guidance would say about it. Re-scoring is `ecdat rescore`, which
writes a new row -- never a side effect of listing scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from policy.engine import BANDS

__all__ = ["BAND_NAMES", "VerdictSummary", "summarise"]

#: Band names straight from the policy engine, so a summary cannot drift from
#: the bands the engine actually assigns.
BAND_NAMES: tuple[str, ...] = tuple(band for _threshold, band in BANDS)


@dataclass(frozen=True, slots=True)
class VerdictSummary:
    """What a scan concluded, in the four numbers a dashboard opens with."""

    #: Components per policy band, e.g. ``{"Critical": 0, ..., "Low": 4}``.
    #: Always carries every band name, including the zeroes -- an absent key
    #: and a zero look the same in a bar chart and are not the same claim.
    band_counts: dict[str, int] = field(default_factory=dict)
    #: The highest component score; 0 for an empty CBOM.
    max_score: int = 0
    #: Components carrying drift, by kind. Empty when the views agree OR when
    #: only one view was scanned -- ``coverage_gaps`` separates those, because
    #: "they agree" and "we did not look" are different answers (ADR-0012).
    drift_counts: dict[str, int] = field(default_factory=dict)
    #: Components whose correlation group was missing a view.
    coverage_gaps: int = 0


def summarise(document: dict[str, Any]) -> VerdictSummary:
    """Read the verdict summary out of a parsed CBOM."""
    counts = dict.fromkeys(BAND_NAMES, 0)
    top = 0
    drift: dict[str, int] = {}
    gaps = 0

    for component in document.get("components", []):
        for prop in component.get("properties", []):
            name = prop.get("name")
            if name == "ecdat:band" and prop["value"] in counts:
                counts[prop["value"]] += 1
            elif name == "ecdat:score":
                top = max(top, int(prop["value"]))
            elif name == "ecdat:drift:kind":
                drift[prop["value"]] = drift.get(prop["value"], 0) + 1
            elif name == "ecdat:coverage:missing":
                gaps += 1

    return VerdictSummary(
        band_counts=counts, max_score=top, drift_counts=drift, coverage_gaps=gaps
    )
