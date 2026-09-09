"""Run scanners over a target and persist the resulting CBOM.

The orchestrator is the only place that knows about all four stages at once:
select plugins, collect findings, normalise, store. It draws one deliberate
line through the middle of that:

* **A broken plugin is an expected condition.** Six scanner families will be
  parsing hostile input -- other people's binaries, containers and packet
  captures. One of them falling over must degrade the scan, not end it. The
  failure is logged with the plugin's id and cause, and the scan continues.
* **A normalisation or validation failure is a real failure.** It means ECDAT
  produced a document that is not a valid CBOM, and there is nothing partial
  about that. It propagates, and nothing is written to the store.

Policy scoring runs between normalisation and the store, so a stored CBOM
already carries its verdicts and the dashboard never has to score anything
itself. A pack that will not load -- unsigned, tampered, uncited -- fails the
scan rather than downgrading it to an unscored document, for the same reason a
broken CBOM does: a document that looks scored but is not is worse than one
that is obviously missing.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from core import store
from core.logs import get_logger
from core.normalise import normalise, validate_cbom_json
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from correlate.apply import apply_drift
from policy.apply import DEFAULT_Z_YEARS, ScoreInputs, apply_policy
from policy.engine import Pack, default_packs

__all__ = ["default_context", "run_scan"]

ENV_KNOWLEDGE_DIR = "ECDAT_KNOWLEDGE_DIR"
ENV_SCRATCH_DIR = "ECDAT_SCRATCH_DIR"
DEFAULT_KNOWLEDGE_DIR = "knowledge"
DEFAULT_SCRATCH_DIR = ".ecdat-scratch"

_log = get_logger("orchestrator")


def default_context() -> ScanContext:
    """The context the CLI and API hand to scanners.

    The scratch directory is created; the knowledge directory is not, because a
    missing knowledge pack is a condition a scanner should notice rather than
    have papered over with an empty directory.
    """
    scratch = Path(os.environ.get(ENV_SCRATCH_DIR, DEFAULT_SCRATCH_DIR))
    scratch.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        knowledge_dir=Path(os.environ.get(ENV_KNOWLEDGE_DIR, DEFAULT_KNOWLEDGE_DIR)),
        scratch_dir=scratch,
    )


def _collect(
    scanner: Scanner, target: Target, ctx: ScanContext
) -> tuple[list[Finding], Exception | None]:
    """Drain one scanner, keeping whatever it produced before any failure.

    A scanner is a generator, so it can die halfway through. Findings it had
    already yielded are real evidence and are kept; the truncation is reported
    to the caller so it can be logged rather than silently absorbed.
    """
    findings: list[Finding] = []
    try:
        findings.extend(scanner.scan(target, ctx))
    except Exception as exc:  # plugin isolation is the point
        return findings, exc
    return findings, None


def run_scan(
    target: Target,
    scanners: Sequence[Scanner],
    ctx: ScanContext,
    packs: Sequence[Pack] | None = None,
    z_years: int = DEFAULT_Z_YEARS,
) -> str:
    """Scan ``target`` with every applicable scanner and store the scored CBOM.

    ``packs`` defaults to the signed packs under ``policy/packs``. Pass an
    explicit (possibly empty) sequence to score with something else, or with
    nothing.

    ``z_years`` is the CRQC horizon every Mosca calculation is measured
    against. It is a global assumption rather than a per-component fact, so it
    is passed in here and recorded on every component.
    """
    _log.info(
        "scan_started",
        extra={
            "event": "scan_started",
            "target_kind": target.kind,
            "target_ref": target.ref,
            "target_system": target.system,
            "scanners_offered": [s.id for s in scanners],
        },
    )

    findings: list[Finding] = []
    ran: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    for scanner in scanners:
        try:
            applicable = scanner.supports(target)
        except Exception as exc:  # a broken supports() is still broken
            failed.append(scanner.id)
            _log.warning(
                "scanner_failed",
                extra={
                    "event": "scanner_failed",
                    "scanner_id": scanner.id,
                    "phase": "supports",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "findings_kept": 0,
                },
            )
            continue

        if not applicable:
            skipped.append(scanner.id)
            _log.debug(
                "scanner_skipped",
                extra={"event": "scanner_skipped", "scanner_id": scanner.id},
            )
            continue

        produced, failure = _collect(scanner, target, ctx)
        findings.extend(produced)

        if failure is None:
            ran.append(scanner.id)
            _log.info(
                "scanner_completed",
                extra={
                    "event": "scanner_completed",
                    "scanner_id": scanner.id,
                    "finding_count": len(produced),
                },
            )
        else:
            failed.append(scanner.id)
            _log.warning(
                "scanner_failed",
                extra={
                    "event": "scanner_failed",
                    "scanner_id": scanner.id,
                    "phase": "scan",
                    "error_type": type(failure).__name__,
                    "error": str(failure),
                    "findings_kept": len(produced),
                },
            )

    # Deliberately outside any try/except: a document that does not validate is
    # a failure of ECDAT, not of a plugin, and must not be written.
    bom, cbom_json = normalise(findings, target)

    # Score before storing, so a stored CBOM is always a scored CBOM. Re-scoring
    # an estate under new guidance is then re-running policy over stored
    # documents rather than re-scanning it.
    resolved_packs = default_packs() if packs is None else list(packs)
    cbom_json = apply_policy(
        cbom_json,
        resolved_packs,
        inputs=ScoreInputs(
            data_class=target.data_class,
            sector=target.sector,
            exposure=target.exposure,
            z_years=z_years,
            knowledge_dir=ctx.knowledge_dir,
        ),
    )
    validate_cbom_json(cbom_json)

    # Correlation runs last, over the scored document: drift is a statement
    # about components, and it raises their score, so it must see the policy
    # verdict it is amending. A stored CBOM therefore carries findings,
    # verdicts and drift together (ADR-0012).
    cbom_json = apply_drift(cbom_json)
    validate_cbom_json(cbom_json)

    scan_id = store.save_scan(target, cbom_json)

    _log.info(
        "scan_completed",
        extra={
            "event": "scan_completed",
            "scan_id": scan_id,
            "finding_count": len(findings),
            "component_count": len(bom.components),
            "scanners_ran": ran,
            "scanners_failed": failed,
            "scanners_skipped": skipped,
            "packs_applied": [f"{p.name}@{p.version}" for p in resolved_packs],
        },
    )
    return scan_id
