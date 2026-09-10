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

Three passes live here, and they share one scoring pipeline
(:func:`score_and_correlate`) so they cannot drift apart:

* :func:`run_scan`     -- scan a target, score, correlate, store.
* :func:`run_fix`      -- propose verified fixes for a stored scan (ADR-0015)
                          and store them as a NEW linked row.
* :func:`run_rescore`  -- re-score a STORED document under a different CRQC
                          horizon, without re-running a single scanner.

The last two never amend their parent (ADR-0016). They read it, derive from it
and write a new row; the original inventory is immutable.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from core import store
from core.logs import get_logger
from core.normalise import normalise, validate_cbom_json
from core.scanner import ScanContext, Scanner, Target, TargetKind
from core.schema import Finding
from correlate.apply import DRIFT_PROPERTIES, apply_drift
from correlate.fixit.apply import apply_fixes, propose_fixes
from correlate.fixit.engine import FixResult
from policy.apply import DEFAULT_Z_YEARS, ScoreInputs, apply_policy
from policy.engine import Pack, default_packs

#: ``propose_fixes`` is re-exported deliberately: it is the seam tests patch to
#: observe the Target a fix pass was actually handed.
__all__ = [
    "FixRun",
    "collect_findings",
    "default_context",
    "propose_fixes",
    "run_fix",
    "run_rescore",
    "run_scan",
    "scanner_records",
    "score_and_correlate",
    "target_kind_of",
]

_INDENT = 2

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


def scanner_records(scanners: Sequence[Scanner]) -> list[store.ScannerRecord]:
    """What ran, as the store records it.

    Derived from the SELECTION rather than from which plugins produced
    findings: the question this column exists to answer is "did anything look
    for binaries here?", and a scanner that ran and found nothing has still
    looked. ``version`` is included only when a plugin declares one -- an
    absent key means the plugin has no version, which is a different claim
    from a null.
    """
    records: list[store.ScannerRecord] = []
    for scanner in scanners:
        record: store.ScannerRecord = {"id": scanner.id}
        version = getattr(scanner, "version", None)
        if version is not None:
            record["version"] = str(version)
        records.append(record)
    return records


def target_kind_of(value: str) -> TargetKind | None:
    """Narrow a target kind read back out of the store to the closed vocabulary.

    ``store.Scan.target_kind`` is a plain column, so a row could in principle
    hold anything. Refusing an unrecognised kind is better than casting: a
    derived pass against a target ECDAT cannot classify would pick the wrong
    scanners.
    """
    kinds: tuple[TargetKind, ...] = (
        "repo",
        "directory",
        "image",
        "host",
        "endpoint",
        "spool",
    )
    for kind in kinds:
        if value == kind:
            return kind
    return None


def _without_drift(cbom_json: str) -> str:
    """Strip the correlator's properties so a re-score is not compounded.

    ``apply_drift`` remembers each component's PRE-drift score so re-running it
    replaces rather than multiplies. That carried value is stale the moment
    policy re-scores under a different horizon -- it would amplify the OLD
    number -- so a re-score clears the drift pass before re-running it. Uses
    the correlator's own property list, so the two cannot drift apart.
    """
    document = json.loads(cbom_json)
    for component in document.get("components", []):
        component["properties"] = [
            p
            for p in component.get("properties", [])
            if p.get("name") not in DRIFT_PROPERTIES
        ]
    return (
        json.dumps(document, indent=_INDENT, sort_keys=True, ensure_ascii=False) + "\n"
    )


def score_and_correlate(
    cbom_json: str, packs: Sequence[Pack], inputs: ScoreInputs
) -> str:
    """Score, then correlate, validating after each. The one scoring pipeline.

    Correlation runs last, over the scored document: drift is a statement about
    components and it raises their score, so it must see the policy verdict it
    is amending (ADR-0012). Shared by `run_scan` and `run_rescore` so a
    re-scored document is produced exactly the way the original was.
    """
    scored = apply_policy(_without_drift(cbom_json), packs, inputs=inputs)
    validate_cbom_json(scored)
    correlated = apply_drift(scored)
    validate_cbom_json(correlated)
    return correlated


def collect_findings(
    scanners: Sequence[Scanner], target: Target, ctx: ScanContext
) -> list[Finding]:
    """Drain every applicable scanner, isolating failures.

    Used by the fix pass, which has to re-read the target: a stored CBOM
    records what a scan saw, and a diff must be generated against the bytes
    that are there NOW or it patches a line that has since moved.
    """
    findings: list[Finding] = []
    for scanner in scanners:
        try:
            if not scanner.supports(target):
                continue
        except Exception as exc:  # a broken supports() is still broken
            _log.warning(
                "scanner_failed",
                extra={
                    "event": "scanner_failed",
                    "scanner_id": scanner.id,
                    "phase": "supports",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            continue
        produced, failure = _collect(scanner, target, ctx)
        findings.extend(produced)
        if failure is not None:
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
    return findings


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
    # an estate under new guidance is then `ecdat rescore` over the stored
    # document rather than a re-scan.
    resolved_packs = default_packs() if packs is None else list(packs)
    cbom_json = score_and_correlate(
        cbom_json,
        resolved_packs,
        ScoreInputs(
            data_class=target.data_class,
            sector=target.sector,
            exposure=target.exposure,
            z_years=z_years,
            knowledge_dir=ctx.knowledge_dir,
        ),
    )

    # The row records what was OFFERED, not what happened to produce findings:
    # "nothing looked for binaries" and "binaries were clean" are different
    # answers, and only the scanner set can tell them apart (ADR-0016).
    scan_id = store.save_scan(
        target,
        cbom_json,
        scanners_ran=scanner_records(scanners),
        z_years=z_years,
    )

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


# ---------------------------------------------------------------------------
# Passes derived from a stored scan. Neither one amends its parent (ADR-0016).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FixRun:
    """The outcome of a fix pass: the new row, and what it found."""

    scan_id: str
    parent_scan_id: str
    target: Target
    #: ``bom-ref -> FixResult`` for every finding a template spoke to.
    fixes: dict[str, FixResult]
    finding_count: int

    @property
    def verified(self) -> int:
        return sum(1 for result in self.fixes.values() if result.verified)


class UnknownScanError(LookupError):
    """A derived pass was asked for a scan the store does not have."""


class UnscannableTargetError(ValueError):
    """A stored row names a target kind ECDAT cannot classify."""


def _parent(scan_id: str) -> store.Scan:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise UnknownScanError(f"no scan with id {scan_id!r} in the store")
    return scan


def resolved_context(
    scan: store.Scan,
    *,
    sector: str | None = None,
    exposure: str | None = None,
    z_years: int | None = None,
) -> store.StoredContext:
    """The context a derived pass runs in: explicit > parent > default.

    The middle term is the whole point. Falling straight from "not supplied" to
    ``other``/``unknown`` is the PERMISSIVE direction, so a fix would be judged
    more leniently than the scan that found the problem -- and a fix that
    introduces a Critical could be accepted because the context that made it
    Critical was forgotten. The defaults apply only to a row that genuinely
    never recorded a context.
    """
    stored = scan.context()
    return store.StoredContext(
        sector=sector or stored.sector or "other",
        exposure=exposure or stored.exposure or "unknown",
        z_years=z_years if z_years is not None else (stored.z_years or DEFAULT_Z_YEARS),
    )


def _target_of(scan: store.Scan, context: store.StoredContext) -> Target:
    kind = target_kind_of(scan.target_kind)
    if kind is None:
        raise UnscannableTargetError(
            f"scan {scan.id} records target kind {scan.target_kind!r}, which is "
            f"not a kind ECDAT knows about"
        )
    return Target(
        kind=kind,
        ref=scan.target_ref,
        system=scan.target_system,
        data_class=scan.target_data_class,
        sector=context.sector or "other",  # type: ignore[arg-type]
        exposure=context.exposure or "unknown",  # type: ignore[arg-type]
    )


def run_fix(
    parent_scan_id: str,
    scanners: Sequence[Scanner],
    ctx: ScanContext,
    *,
    sector: str | None = None,
    exposure: str | None = None,
    z_years: int | None = None,
    packs: Sequence[Pack] | None = None,
) -> FixRun:
    """Propose verified fixes for a stored scan; store them as a NEW row.

    Read-only twice over: the fix engine never writes to the target
    (ADR-0015), and this never writes to the parent row (ADR-0016).
    """
    parent = _parent(parent_scan_id)
    context = resolved_context(
        parent, sector=sector, exposure=exposure, z_years=z_years
    )
    target = _target_of(parent, context)
    horizon = context.z_years if context.z_years is not None else DEFAULT_Z_YEARS

    findings = collect_findings(scanners, target, ctx)
    fixes = propose_fixes(findings, target, context=ctx, packs=packs, z_years=horizon)
    annotated = apply_fixes(parent.cbom_json, fixes)

    scan_id = store.save_fix_result(
        parent_scan_id,
        annotated,
        scanners_ran=scanner_records(scanners),
        context=context,
    )
    _log.info(
        "fix_pass_completed",
        extra={
            "event": "fix_pass_completed",
            "scan_id": scan_id,
            "parent_scan_id": parent_scan_id,
            "finding_count": len(findings),
            "fixable": len(fixes),
            "verified": sum(1 for r in fixes.values() if r.verified),
        },
    )
    return FixRun(
        scan_id=scan_id,
        parent_scan_id=parent_scan_id,
        target=target,
        fixes=fixes,
        finding_count=len(findings),
    )


def run_rescore(
    parent_scan_id: str,
    ctx: ScanContext,
    *,
    z_years: int | None = None,
    packs: Sequence[Pack] | None = None,
) -> str:
    """Re-score a STORED CBOM under a (possibly different) CRQC horizon.

    No scanner runs. This is the entry point the dashboard's Mosca slider
    needs: the components are already inventoried, and what changes is the
    assumption they are judged against. The result is a new linked row, so the
    original verdict stays on the record beside the new one -- which is what
    makes "we re-prioritised in March" an auditable statement rather than a
    silently different number.
    """
    parent = _parent(parent_scan_id)
    context = resolved_context(parent, z_years=z_years)
    horizon = context.z_years if context.z_years is not None else DEFAULT_Z_YEARS

    rescored = score_and_correlate(
        parent.cbom_json,
        default_packs() if packs is None else list(packs),
        ScoreInputs(
            data_class=parent.target_data_class,
            sector=context.sector or "other",  # type: ignore[arg-type]
            exposure=context.exposure or "unknown",  # type: ignore[arg-type]
            z_years=horizon,
            knowledge_dir=ctx.knowledge_dir,
        ),
    )

    scan_id = store.save_rescore(parent_scan_id, rescored, context=context)
    _log.info(
        "rescore_completed",
        extra={
            "event": "rescore_completed",
            "scan_id": scan_id,
            "parent_scan_id": parent_scan_id,
            "z_years": horizon,
        },
    )
    return scan_id
