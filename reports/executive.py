"""The executive report: two pages a decision-maker can act on.

Everything on these pages is read off the stored scan. The one editorial
decision is what leads: the estate's shape, then the five artefacts that
actually decide the migration plan, then the deadline the organisation is
measured against.

The honesty rule from ADR-0017 travels with it. A fact nobody confirmed is
labelled provisional in the TEXT -- a reader holding a printout has no tooltip
to hover, and a deadline that reads as confirmed is one they will plan around.
"""

from __future__ import annotations

from reports.layout import MUTED, Page, band_colour
from reports.model import Artefact, ScanView

__all__ = ["ExecutiveReport"]

TOP_N = 5

#: The DST milestone an Indian CII operator is measured against first, and the
#: source it was confirmed against (ADR-0017). Quoted rather than paraphrased:
#: a deadline an organisation may act on must arrive with its citation.
DST_INVENTORY_DEADLINE = "2027-12-31"
DST_MIGRATION_DEADLINE = "2028-12-31"
DST_SOURCE = (
    'DST/NQM "Report on Quantum-Safe Ecosystem in India: Roadmap to Quantum '
    'Resiliency", May 2026, Section 9.0 — '
    "https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf"
)


class ExecutiveReport:
    """Two pages: what is here, what is worst, and by when."""

    kind = "executive"
    title = "Cryptographic risk — executive summary"

    @staticmethod
    def render(page: Page, view: ScanView) -> None:
        scan = view.scan
        page.title(
            ExecutiveReport.title,
            f"{view.system} · scan {scan.id} · "
            f"{scan.created_at.isoformat(timespec='seconds')}",
        )

        page.metrics(
            [
                ("artefacts", str(scan.component_count)),
                ("max score", str(scan.max_score)),
                ("critical", str(view.summary.band_counts.get("Critical", 0))),
                ("drift", str(view.drift_total)),
            ]
        )
        page.band_bar(view.summary.band_counts)

        page.heading("Position")
        page.body(_position(view))

        page.heading(f"Highest risk — top {TOP_N}")
        page.row(
            [
                ("artefact", 0),
                ("band", 190),
                ("score", 250),
                ("deadline", 300),
                ("where", 380),
            ],
            bold=True,
            colour=MUTED,
        )
        for artefact in view.worst(TOP_N):
            page.row(
                [
                    (_clip(artefact.name, 30), 0),
                    (artefact.band, 190),
                    (str(artefact.score), 250),
                    (artefact.deadline or "-", 300),
                    (_clip_left(_where(artefact), 28), 380),
                ],
                colour=band_colour(artefact.band),
            )
            action = artefact.actions[0] if artefact.actions else ""
            if action:
                page.body(_clip(action, 300), size=7.5, colour=MUTED, indent=10)
            if artefact.provisional:
                page.body(
                    "PROVISIONAL: part of this verdict rests on a rule that has "
                    "not been confirmed against its source, and contributed 0 to "
                    f"the score — {', '.join(artefact.provisional_rules)}",
                    size=7.5,
                    colour=MUTED,
                    indent=10,
                )
            page.space(3)

        page.heading("India DST / National Quantum Mission")
        page.body(
            f"The first obligation on critical information infrastructure is a "
            f"complete cryptographic inventory by {DST_INVENTORY_DEADLINE}, a "
            f"year ahead of the {DST_MIGRATION_DEADLINE} high-priority migration "
            f"milestone. This report is evidence toward it."
        )
        page.space(2)
        page.body(f"Source: {DST_SOURCE}", size=7.5, colour=MUTED)

        if view.provisional:
            page.heading("Facts not yet confirmed")
            page.body(
                f"{len(view.provisional)} artefact(s) carry a verdict that "
                f"includes an unverified rule. Those rules are DISPLAYED and "
                f"contributed nothing to any score — the figures above stand on "
                f"confirmed facts only.",
                colour=MUTED,
            )
            for artefact in view.provisional[:TOP_N]:
                page.body(
                    f"{artefact.name} — provisional: "
                    f"{', '.join(artefact.provisional_rules)}",
                    size=7.5,
                    colour=MUTED,
                    indent=10,
                )

        page.heading("Provenance")
        page.kv("system", view.system)
        page.kv("target", f"{scan.target_kind} {scan.target_ref}")
        page.kv(
            "context",
            f"sector={scan.sector or '—'} exposure={scan.exposure or '—'} "
            f"data={scan.target_data_class or '—'} crqc_horizon={scan.z_years or '—'}y",
        )
        page.kv("scanners", _scanners(view))
        page.kv("engine", _engines(view))
        page.note(
            "Every figure is read from the stored CBOM for this scan; nothing "
            "was re-scanned or re-scored to produce this report."
        )


def _position(view: ScanView) -> str:
    counts = view.summary.band_counts
    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)
    parts = [
        f"{view.scan.component_count} cryptographic artefacts were inventoried "
        f"across {len(view.views_present)} of 3 views."
    ]
    if critical or high:
        parts.append(
            f"{critical} are Critical and {high} High: quantum-vulnerable, "
            f"reachable, and carrying data whose lifetime exceeds the CRQC "
            f"horizon this scan was scored against."
        )
    else:
        parts.append("Nothing reached Critical or High in this scan's context.")
    if view.drift_total:
        parts.append(
            f"{view.drift_total} drift finding(s): what the estate DECLARES and "
            f"what it SHIPS or is OBSERVED doing disagree. An inventory error is "
            f"worse than a known weakness — a wrong description cannot be planned "
            f"around."
        )
    if view.views_missing:
        parts.append(
            f"NOT COLLECTED: {', '.join(view.views_missing)}. Those views were "
            f"not looked at, which is not the same as their being clean."
        )
    return " ".join(parts)


def _where(artefact: Artefact) -> str:
    """Where a reader should go to look at this. Endpoint first, then the
    evidence locator -- the endpoint is what an operator owns."""
    if artefact.endpoint:
        return artefact.endpoint
    if artefact.occurrences:
        return artefact.occurrences[0].locator
    return "-"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _clip_left(text: str, limit: int) -> str:
    """Keep the TAIL. `.../auth/tokens.py:5` identifies a site; the checkout
    path it sits under does not."""
    return text if len(text) <= limit else "..." + text[-(limit - 3) :]


def _scanners(view: ScanView) -> str:
    ran = view.scan.scanners_ran
    if ran is None:
        return "not recorded for this scan"
    if not ran:
        return "none ran"
    return ", ".join(entry["id"] for entry in ran)


def _engines(view: ScanView) -> str:
    versions = view.scan.engine_versions or {}
    if not versions:
        return "not recorded for this scan"
    parts = []
    ecdat = versions.get("ecdat")
    if isinstance(ecdat, str):
        parts.append(f"ECDAT {ecdat}")
    for key, value in sorted(versions.items()):
        if key == "ecdat" or not isinstance(value, dict):
            continue
        engine = "semgrep" if key == "source" else key
        installed = value.get("installed")
        parts.append(f"{engine} {installed if installed else 'not installed'}")
    return ", ".join(parts)
