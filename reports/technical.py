"""The technical report: every artefact, with its receipts.

The executive report says what to do; this one says how ECDAT knows. Its order
is the order a reviewer argues in -- WHAT was found, WHERE it was seen, WHY it
scored what it did, whether the views DISAGREE, and what a verified fix would
change.

Grouped by band because that is how remediation is planned, and every section
states its own count so a reader can tell "none in this band" from "this band
was left out".
"""

from __future__ import annotations

from reports.layout import FAINT, MUTED, Page, band_colour
from reports.model import Artefact, ScanView

__all__ = ["TechnicalReport"]

#: Diff lines shown inline before the rest is elided. A full patch belongs in
#: the .patch file `ecdat fix --out` writes, not in a PDF.
DIFF_LINES = 14


class TechnicalReport:
    """Everything on every artefact, grouped by band."""

    kind = "technical"
    title = "Cryptographic inventory — technical detail"

    @staticmethod
    def render(page: Page, view: ScanView) -> None:
        scan = view.scan
        page.title(
            TechnicalReport.title,
            f"{view.system} · scan {scan.id} · "
            f"{scan.created_at.isoformat(timespec='seconds')}",
        )
        page.band_bar(view.summary.band_counts)

        _drift_section(page, view)

        page.heading("Artefacts by band")
        for band, artefacts in view.by_band():
            page.room(40)
            page.subheading(f"{band} — {len(artefacts)}", colour=band_colour(band))
            for artefact in artefacts:
                _artefact_block(page, artefact)
            page.space(4)

        page.heading("Scan provenance")
        page.kv("target", f"{scan.target_kind} {scan.target_ref}")
        page.kv("views collected", ", ".join(view.views_present) or "none")
        page.kv("views NOT collected", ", ".join(view.views_missing) or "none")
        page.kv(
            "context",
            f"sector={scan.sector or '—'} exposure={scan.exposure or '—'} "
            f"data={scan.target_data_class or '—'} crqc_horizon={scan.z_years or '—'}y",
        )


def _drift_section(page: Page, view: ScanView) -> None:
    page.heading(f"Drift — {view.drift_total}")
    if not view.drift_total:
        # Stated, not omitted: "no drift was found" and "drift could not be
        # computed" are different claims, and a single-view scan can only make
        # the second one.
        if len(view.views_present) < 2:
            page.body(
                "No drift found — and none was COMPUTABLE. Drift is a "
                f"disagreement between views, and this scan collected only "
                f"{', '.join(view.views_present) or 'none'}. Use "
                "`ecdat scan-system` with a manifest naming the repo, the image "
                "and a spool to make the comparison possible.",
                colour=MUTED,
            )
        else:
            page.body(
                "No drift found. All collected views agree about the artefacts "
                "they share.",
                colour=MUTED,
            )
        return

    page.body(
        "What the estate DECLARES against what it SHIPS or is OBSERVED doing. A "
        "drifted component is floored to High: an inventory error is worse than "
        "a known weakness, because a wrong description cannot be planned around.",
        colour=MUTED,
    )
    page.space(4)
    for artefact in view.drifted:
        for drift in artefact.drift:
            page.room(60)
            page.subheading(
                f"{drift.kind} — {artefact.name}", colour=band_colour("High")
            )
            page.kv("endpoint", artefact.endpoint or "—")
            page.kv("declared", drift.declared or "—")
            page.kv("observed / shipped", drift.observed or "—")
            if drift.cause:
                page.body(f"Cause: {drift.cause}", size=8, indent=6)
            for entry in drift.evidence[:4]:
                page.mono(entry, indent=6)
            page.space(4)


def _artefact_block(page: Page, artefact: Artefact) -> None:
    page.room(70)
    header = f"{artefact.name}   {artefact.score}   {artefact.view}"
    page.subheading(header, colour=band_colour(artefact.band))
    page.mono(artefact.bom_ref, indent=0, colour=FAINT)

    page.kv("asset / usage", f"{artefact.asset_type} · {artefact.usage}")
    if artefact.endpoint:
        page.kv("endpoint", artefact.endpoint)
    if artefact.deadline:
        suffix = (
            " (PROVISIONAL — unconfirmed source)"
            if artefact.deadline_provisional
            else ""
        )
        page.kv("deadline", f"{artefact.deadline}{suffix}")
    if artefact.quantum_status:
        page.kv("quantum status", artefact.quantum_status)

    if artefact.categories:
        page.kv(
            "score breakdown",
            "  ".join(f"{name}={value}" for name, value in artefact.categories),
        )

    if artefact.fired_rules:
        page.body("Fired rules", size=8, colour=MUTED, indent=0)
        unverified = set(artefact.provisional_rules)
        for rule in artefact.fired_rules:
            mark = "  [PROVISIONAL — scored 0]" if rule in unverified else ""
            page.body(f"· {rule}{mark}", size=7.5, colour=MUTED, indent=10)

    if artefact.occurrences:
        page.body("Evidence", size=8, colour=MUTED, indent=0)
        for occurrence in artefact.occurrences:
            page.mono(
                f"{occurrence.locator}  [{occurrence.scanner or occurrence.view}]  "
                f"{occurrence.detail}",
                indent=10,
            )
            if occurrence.snippet:
                page.mono(occurrence.snippet, indent=18, colour=FAINT)

    if artefact.drift:
        for drift in artefact.drift:
            page.body(
                f"DRIFT {drift.kind}: declared {drift.declared} vs {drift.observed}",
                size=7.5,
                colour=band_colour("High"),
                indent=10,
            )

    if artefact.fix_template:
        state = "VERIFIED" if artefact.fix_verified else "NOT VERIFIED"
        page.body(f"Proposed fix [{state}] {artefact.fix_template}", size=8, indent=0)
        if artefact.fix_reason:
            page.body(artefact.fix_reason, size=7.5, colour=MUTED, indent=10)
        if artefact.fix_verified and artefact.fix_diff:
            lines = artefact.fix_diff.splitlines()
            for line in lines[:DIFF_LINES]:
                page.mono(line, indent=10)
            if len(lines) > DIFF_LINES:
                page.mono(f"… {len(lines) - DIFF_LINES} more lines", indent=10)

    if artefact.actions:
        page.body("Recommended action", size=8, colour=MUTED, indent=0)
        for action in artefact.actions[:2]:
            page.body(f"· {action}", size=7.5, colour=MUTED, indent=10)

    page.space(6)
