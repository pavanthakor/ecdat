"""Scanning a SYSTEM: three views into one CBOM, so drift is real (ADR-0019).

``run_scan`` takes one target of one kind. That is the right shape for "what is
in this repo?" and the wrong shape for the question Pillar 2 exists to answer,
because **drift is a property of the union, not of any one view.** A config
that promises a post-quantum group and an image that cannot negotiate one are
each individually unremarkable; only a document containing both is a finding.

Until this module, the only place the three views met was ``kpi/harness.py``,
which merged three scans by hand to make its measurement possible. So the
correlator worked, and the product never used it: every scan a user could
actually load had exactly one view in it and therefore no drift, forever.

A manifest names one system's targets. Every applicable scanner runs over every
target, the findings become ONE CBOM, and the correlator sees all three views.

Three things this module is careful about:

* **The cross-view non-merge still holds.** A declared ``X25519MLKEM768`` and an
  observed ``x25519`` remain two components (ADR-0002). Merging them would
  destroy the disagreement the correlator is looking for.
* **A missing target fails loud.** Degrading to "we scanned what we could"
  produces a document that looks like an inventory and is silently missing a
  whole view. A broken *scanner* still degrades rather than aborting, which is
  the orchestrator's existing discipline (ADR-0003) -- the difference is that
  one is an operator error and the other is a hostile input.
* **The spool is copied before it is read.** The runtime-spool scanner moves
  what it ingests into ``consumed/`` (ADR-0010), which is right for a real seam
  and would eat a committed fixture on first use.

Synchronous, deliberately: it runs the scanners and returns when they are done.
The job model ``POST /scans`` has owed since ADR-0003 is still owed, and a
system scan wants it more than a single-target one does.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_args

import yaml

from core import registry, store
from core.logs import get_logger
from core.normalise import normalise, validate_cbom_json
from core.orchestrator import (
    collect_findings,
    default_context,
    scanner_records,
    score_and_correlate,
)
from core.scanner import Exposure, ScanContext, Scanner, Sector, Target, TargetKind
from core.schema import Finding
from policy.apply import DEFAULT_Z_YEARS, ScoreInputs
from policy.engine import Pack, default_packs

__all__ = [
    "ManifestError",
    "SystemManifest",
    "SystemTarget",
    "TargetUnreadableError",
    "load_manifest",
    "parse_manifest",
    "scan_system",
]

_log = get_logger("system")

_KINDS: tuple[TargetKind, ...] = get_args(TargetKind)
_SECTORS: tuple[Sector, ...] = get_args(Sector)
_EXPOSURES: tuple[Exposure, ...] = get_args(Exposure)

#: Target kinds whose ``ref`` is a directory on disk.
_DIRECTORY_KINDS = frozenset({"repo", "directory", "spool"})

#: Kinds whose ref names one file.
_FILE_KINDS = frozenset({"image"})

#: Kinds that establish the system's canonical root. See :func:`_system_root`.
_PATH_KINDS = ("repo", "directory")

_INDENT = 2


class ManifestError(ValueError):
    """A system manifest is malformed. Raised at load, never at scan time."""


class TargetUnreadableError(RuntimeError):
    """A target named in the manifest is not there. Names which one."""


@dataclass(frozen=True, slots=True)
class SystemTarget:
    kind: TargetKind
    ref: str


@dataclass(frozen=True, slots=True)
class SystemManifest:
    """A durable description of one system's targets and its scan context.

    The context is system-level rather than per-target on purpose: one system
    has one sector, one exposure and one data classification, and scoring a
    component differently depending on which target it happened to turn up in
    would be incoherent.
    """

    system: str
    targets: tuple[SystemTarget, ...]
    sector: Sector = "other"
    exposure: Exposure = "unknown"
    data_class: str | None = None
    #: Where it was loaded from, so an error can say which file was wrong.
    source: Path | None = None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _where(source: Path | None) -> str:
    return str(source) if source is not None else "<manifest>"


def _vocabulary(
    value: Any, allowed: Sequence[str], field: str, source: Path | None
) -> str:
    """Reject an unknown value rather than falling back to a default.

    Silently defaulting `sector: banking` to `other` would under-score an
    entire CII estate, and nothing in the output would say why.
    """
    if not isinstance(value, str) or value not in allowed:
        raise ManifestError(
            f"{_where(source)}: {field} {value!r} is not one of "
            f"{sorted(allowed)}. It is refused rather than defaulted, because "
            f"a silently wrong {field} changes every score in the scan."
        )
    return value


def parse_manifest(document: Any, *, source: Path | None = None) -> SystemManifest:
    """Validate a parsed manifest into a :class:`SystemManifest`."""
    if not isinstance(document, dict):
        raise ManifestError(f"{_where(source)}: a manifest must be a mapping")

    system = document.get("system")
    if not isinstance(system, str) or not system.strip():
        raise ManifestError(
            f"{_where(source)}: `system` is required -- it names the estate every "
            f"target belongs to, and it is what the correlator groups on."
        )

    raw_targets = document.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ManifestError(
            f"{_where(source)}: `targets` must be a non-empty list. A system "
            f"with no targets is a scan with nothing to compare."
        )

    targets: list[SystemTarget] = []
    for index, raw in enumerate(raw_targets):
        position = f"targets[{index}]"
        if not isinstance(raw, dict):
            raise ManifestError(f"{_where(source)}: {position} must be a mapping")

        ref = raw.get("ref")
        if not isinstance(ref, str) or not ref.strip():
            raise ManifestError(
                f"{_where(source)}: {position} has no `ref` (kind="
                f"{raw.get('kind')!r}); every target must say what to scan"
            )

        kind = raw.get("kind")
        if kind not in _KINDS:
            raise ManifestError(
                f"{_where(source)}: {position} has kind {kind!r} for ref {ref!r}, "
                f"which is not one of {sorted(_KINDS)}. Refused rather than "
                f"skipped: a typo'd kind would drop a whole view from the scan "
                f"and the CBOM would look complete."
            )
        targets.append(SystemTarget(kind=kind, ref=ref))

    sector = document.get("sector", "other")
    exposure = document.get("exposure", "unknown")
    data_class = document.get("data_class")
    if data_class is not None and not isinstance(data_class, str):
        raise ManifestError(f"{_where(source)}: `data_class` must be a string")

    return SystemManifest(
        system=system,
        targets=tuple(targets),
        sector=_vocabulary(sector, _SECTORS, "sector", source),  # type: ignore[arg-type]
        exposure=_vocabulary(exposure, _EXPOSURES, "exposure", source),  # type: ignore[arg-type]
        data_class=data_class,
        source=source,
    )


def load_manifest(path: Path | str) -> SystemManifest:
    """Read and validate a manifest file."""
    manifest_path = Path(path)
    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {manifest_path}: {exc}") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{manifest_path}: not valid YAML: {exc}") from exc
    return parse_manifest(document, source=manifest_path)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _system_root(manifest: SystemManifest) -> str:
    """The path locators are made relative to.

    The first ``repo``/``directory`` target in manifest order, because that is
    the system's checkout and every declared locator sits under it. This is
    what keeps a component's ``bom-ref`` IDENTICAL between
    ``ecdat scan <repo>`` and ``ecdat scan-system`` -- identity folds in the
    artefact's path relative to the target root, so a different root would
    silently give the same artefact two identities across the two entry points.

    With no path target at all, the system name stands in and every locator is
    kept verbatim.
    """
    for target in manifest.targets:
        if target.kind in _PATH_KINDS:
            return target.ref
    return manifest.system


def _check_readable(target: SystemTarget) -> None:
    path = Path(target.ref)
    if target.kind in _DIRECTORY_KINDS and not path.is_dir():
        raise TargetUnreadableError(
            f"target {target.ref!r} (kind={target.kind}) is not a readable "
            f"directory. A system scan refuses to continue rather than quietly "
            f"produce an inventory missing a whole view."
        )
    if target.kind in _FILE_KINDS and not path.is_file():
        raise TargetUnreadableError(
            f"target {target.ref!r} (kind={target.kind}) is not a readable "
            f"file. A system scan refuses to continue rather than quietly "
            f"produce an inventory missing a whole view."
        )


def _prepare(target: SystemTarget, ctx: ScanContext, index: int) -> str:
    """The ref a scanner should actually be pointed at.

    Everything is scanned in place except a spool, which is COPIED into the
    scratch directory first: the runtime-spool scanner moves what it ingests
    into ``consumed/`` (ADR-0010), which is correct for a live seam and would
    eat a committed fixture the first time anybody ran a system scan.
    """
    if target.kind != "spool":
        return target.ref

    destination = Path(ctx.scratch_dir) / f"spool-{index}"
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(target.ref, destination)
    return str(destination)


def _applicable(scanners: Sequence[Scanner], target: Target) -> list[Scanner]:
    chosen: list[Scanner] = []
    for scanner in scanners:
        try:
            if scanner.supports(target):
                chosen.append(scanner)
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
    return chosen


def _name_the_system(cbom_json: str, system: str) -> str:
    """Record which system the document describes.

    The correlator groups on it, and a document that cannot say what estate it
    is about is one nobody can file. Written here rather than in the normaliser
    so single-target CBOMs keep their existing bytes.
    """
    document = json.loads(cbom_json)
    metadata = document.setdefault("metadata", {})
    metadata["component"] = {"name": system, "type": "application"}
    return (
        json.dumps(document, indent=_INDENT, sort_keys=True, ensure_ascii=False) + "\n"
    )


def scan_system(
    manifest: SystemManifest,
    ctx: ScanContext | None = None,
    *,
    packs: Sequence[Pack] | None = None,
    z_years: int = DEFAULT_Z_YEARS,
) -> str:
    """Scan every target in ``manifest`` into ONE stored, correlated CBOM."""
    context = default_context() if ctx is None else ctx
    Path(context.scratch_dir).mkdir(parents=True, exist_ok=True)

    # Every target is checked BEFORE anything runs, so a manifest with a typo
    # in its last entry fails in a second rather than after a full image scan.
    for target in manifest.targets:
        _check_readable(target)

    available = registry.get_scanners()
    findings: list[Finding] = []
    ran: dict[str, Scanner] = {}

    for index, entry in enumerate(manifest.targets):
        scan_target = Target(
            kind=entry.kind,
            ref=_prepare(entry, context, index),
            system=manifest.system,
            data_class=manifest.data_class,
            sector=manifest.sector,
            exposure=manifest.exposure,
        )
        chosen = _applicable(available, scan_target)
        if not chosen:
            # Not an error: a manifest may name a kind no plugin handles yet.
            # It IS worth saying out loud, because the resulting document will
            # be missing that view and nothing else will mention it.
            _log.warning(
                "target_unscanned",
                extra={
                    "event": "target_unscanned",
                    "target_kind": entry.kind,
                    "target_ref": entry.ref,
                },
            )
            continue

        produced = collect_findings(chosen, scan_target, context)
        findings.extend(produced)
        for scanner in chosen:
            ran[scanner.id] = scanner

        _log.info(
            "system_target_scanned",
            extra={
                "event": "system_target_scanned",
                "target_kind": entry.kind,
                "target_ref": entry.ref,
                "scanners": sorted(s.id for s in chosen),
                "finding_count": len(produced),
            },
        )

    # ONE normalisation over ALL the findings, so de-duplication is global and
    # a bom-ref cannot repeat. The locus target carries the system's canonical
    # root; see `_system_root`.
    locus = Target(
        kind="directory",
        ref=_system_root(manifest),
        system=manifest.system,
        data_class=manifest.data_class,
        sector=manifest.sector,
        exposure=manifest.exposure,
    )
    bom, cbom_json = normalise(findings, locus)
    cbom_json = _name_the_system(cbom_json, manifest.system)
    validate_cbom_json(cbom_json)

    # Score, then correlate. THIS is the line the slice exists for: the
    # correlator finally sees declared, shipped and observed in one document.
    cbom_json = score_and_correlate(
        cbom_json,
        default_packs() if packs is None else list(packs),
        ScoreInputs(
            data_class=manifest.data_class,
            sector=manifest.sector,
            exposure=manifest.exposure,
            z_years=z_years,
            knowledge_dir=context.knowledge_dir,
        ),
    )

    ordered = [ran[key] for key in sorted(ran)]
    versions, engine_warning = _engines(ordered)
    scan_id = store.save_scan(
        locus,
        cbom_json,
        scanners_ran=scanner_records(ordered),
        z_years=z_years,
        engine_versions=versions,
        engine_warning=engine_warning,
    )

    _log.info(
        "system_scan_completed",
        extra={
            "event": "system_scan_completed",
            "scan_id": scan_id,
            "system": manifest.system,
            "target_count": len(manifest.targets),
            "finding_count": len(findings),
            "component_count": len(bom.components),
            "scanners_ran": sorted(ran),
        },
    )
    return scan_id


def _engines(scanners: Sequence[Scanner]) -> tuple[dict[str, Any], str | None]:
    from core.orchestrator import engine_versions

    return engine_versions(scanners)
