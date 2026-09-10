"""Reports: three PDFs generated from a stored scan (ADR-0020).

Nothing here scans. A report is a projection of a CBOM the store already holds,
so a PDF and the dashboard cannot disagree about the same scan, and a report
issued last quarter can be regenerated from the row that produced it.

* :class:`~reports.executive.ExecutiveReport` -- two pages for a decision.
* :class:`~reports.technical.TechnicalReport` -- every artefact with its receipts.
* :class:`~reports.coverage.CoverageReport` -- what was NOT looked at.

Output is deterministic: the same scan renders byte-identical bytes, because a
report that changed on every render could not be checksummed or compared
against the copy somebody was sent. See :mod:`reports.layout`.
"""

from __future__ import annotations

import io
from typing import Protocol

from reports.coverage import CoverageReport
from reports.executive import ExecutiveReport
from reports.layout import Page, new_canvas
from reports.model import ScanView, UnknownScanError, load_scan
from reports.technical import TechnicalReport

__all__ = [
    "REPORT_KINDS",
    "CoverageReport",
    "ExecutiveReport",
    "Report",
    "TechnicalReport",
    "UnknownScanError",
    "render",
    "report_for",
]


class Report(Protocol):
    """A report kind: a name, a title, and how to draw itself."""

    kind: str
    title: str

    @staticmethod
    def render(page: Page, view: ScanView) -> None: ...


#: THE LIST. Adding a report is one import and one entry.
REPORT_KINDS: dict[str, type[Report]] = {
    ExecutiveReport.kind: ExecutiveReport,
    TechnicalReport.kind: TechnicalReport,
    CoverageReport.kind: CoverageReport,
}


def report_for(kind: str) -> type[Report]:
    """Look a report kind up by name, or fail naming what is available."""
    try:
        return REPORT_KINDS[kind]
    except KeyError:
        raise ValueError(
            f"unknown report kind {kind!r}; available: "
            f"{', '.join(sorted(REPORT_KINDS))}"
        ) from None


def render(report: type[Report], scan_id: str) -> bytes:
    """Render ``report`` for a stored scan.

    The document's dates come from the SCAN, never from `now()` -- that is what
    makes two renders of one scan byte-identical.
    """
    view = load_scan(scan_id)
    buffer = io.BytesIO()
    canvas = new_canvas(
        buffer,
        title=f"ECDAT — {report.title}",
        scan_id=view.scan.id,
        created=view.scan.created_at,
    )
    page = Page(
        canvas=canvas,
        footer=(
            f"ECDAT · {view.system} · scan {view.scan.id} · "
            f"generated from the stored CBOM, not from a new scan"
        ),
    )
    report.render(page, view)
    page.finish()
    return buffer.getvalue()
