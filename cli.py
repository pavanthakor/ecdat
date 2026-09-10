"""`ecdat scan <ref>` and `ecdat fix <scan-id>` -- ECDAT from the command line.

    python cli.py scan /srv/quantumbank --system quantumbank
    python cli.py scan /srv/quantumbank -o cbom.json
    python cli.py scan /srv/quantumbank --scanner source
    python cli.py scan-system testdata/quantumbank/system.yaml
    python cli.py fix <scan-id> --out patches/
    python cli.py --list-scanners

`fix` proposes a verified diff for every fixable finding in a stored scan and
prints it. **It never writes to the target.** Every diff it prints has been
applied to a throwaway sandbox copy and re-scanned; anything it could not prove
is reported with the reason instead of the patch (ADR-0015).

The CBOM goes to stdout (or to ``-o``); the summary and the structured log go
to stderr. That split is what makes ``python cli.py scan . > cbom.json``
produce a file containing only the document.

Which plugins run is not decided here: the CLI asks :mod:`core.registry`, the
same way the API does, so the two can never drift apart.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from core import registry, store
from core.logs import configure_logging
from core.orchestrator import (
    UnknownScanError,
    UnscannableTargetError,
    default_context,
    resolved_context,
    run_fix,
    run_rescore,
    run_scan,
)
from core.scanner import Exposure, Sector, Target, TargetKind
from core.summary import summarise
from core.system import ManifestError, TargetUnreadableError, load_manifest, scan_system
from correlate.fixit.apply import write_patches
from correlate.fixit.engine import FixResult
from policy.apply import DEFAULT_Z_YEARS
from reports import REPORT_KINDS, render, report_for

__all__ = ["main"]

TARGET_KINDS: tuple[TargetKind, ...] = (
    "repo",
    "directory",
    "image",
    "host",
    "endpoint",
    "spool",
)

#: Where a report lands when no -o is given.
DEFAULT_REPORT_DIR = "reports-out"

SECTORS: tuple[Sector, ...] = (
    "government",
    "strategic",
    "defence",
    "power",
    "telecom",
    "transport",
    "bfsi",
    "other",
)
EXPOSURES: tuple[Exposure, ...] = ("internet", "internal", "build", "unknown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdat", description="Cryptographic discovery and analysis."
    )
    parser.add_argument(
        "--list-scanners",
        action="store_true",
        help="print the available scanner ids and exit",
    )
    # Not required, because --list-scanners is a complete invocation on its
    # own. main() rejects the empty case explicitly.
    subcommands = parser.add_subparsers(dest="command", required=False)

    scan = subcommands.add_parser("scan", help="scan a target and emit its CBOM")
    scan.add_argument("ref", help="path, image reference or hostname")
    scan.add_argument(
        "--kind", choices=TARGET_KINDS, default="repo", help="what REF names"
    )
    scan.add_argument("--system", default=None, help="service or system name")
    scan.add_argument(
        "--data-class",
        default=None,
        help=(
            "data-classification tag (Public/Internal/Confidential/Personal/"
            "Sovereign, or an alias). Supplies X in Mosca's inequality; omit it "
            "and Mosca urgency is reported as unknown rather than assumed zero"
        ),
    )
    scan.add_argument(
        "--sector",
        choices=SECTORS,
        default="other",
        help="sector this target serves; drives the DST CII deadline",
    )
    scan.add_argument(
        "--exposure",
        choices=EXPOSURES,
        default="unknown",
        help="how reachable the target is; feeds blast-radius prioritisation",
    )
    scan.add_argument(
        "--crqc-years",
        type=int,
        default=DEFAULT_Z_YEARS,
        metavar="Z",
        help=(
            "years until a cryptographically relevant quantum computer "
            f"(default {DEFAULT_Z_YEARS}). An assumption, not a measurement"
        ),
    )
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the CBOM here instead of stdout",
    )
    scan.add_argument(
        "--scanner",
        action="append",
        dest="scanners",
        metavar="ID",
        default=None,
        help=(
            "run only this scanner; repeatable. Defaults to every registered "
            "scanner. See --list-scanners."
        ),
    )

    scan_system_parser = subcommands.add_parser(
        "scan-system",
        help=(
            "scan every target in a system manifest into ONE correlated CBOM "
            "(this is what makes drift visible)"
        ),
    )
    scan_system_parser.add_argument(
        "manifest", type=Path, help="path to a system manifest (YAML)"
    )
    scan_system_parser.add_argument(
        "--crqc-years",
        type=int,
        default=DEFAULT_Z_YEARS,
        metavar="Z",
        help=f"years until a CRQC (default {DEFAULT_Z_YEARS})",
    )
    scan_system_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the CBOM here instead of stdout",
    )

    report = subcommands.add_parser(
        "report",
        help="render a PDF report from a stored scan (no re-scan)",
    )
    report.add_argument("scan_id", help="the id of a scan already in the store")
    report.add_argument(
        "--kind",
        choices=sorted(REPORT_KINDS),
        required=True,
        help=(
            "executive: two pages for a decision. technical: every artefact "
            "with its evidence. coverage: what this scan did NOT look at"
        ),
    )
    report.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the PDF here (default ./reports-out/<kind>-<scan>.pdf)",
    )

    subcommands.add_parser(
        "scans",
        help="list the scans stored in the current database (and name the file)",
    )

    fix = subcommands.add_parser(
        "fix",
        help="propose verified diffs for a stored scan (never writes to the target)",
    )
    fix.add_argument("scan_id", help="the id of a scan already in the store")
    fix.add_argument(
        "--scanner",
        action="append",
        dest="scanners",
        metavar="ID",
        default=None,
        help="re-collect findings with only this scanner; repeatable",
    )
    # These default to None, not to "other"/"unknown" -- the difference is
    # load-bearing. An unsupplied flag means "use what the parent scan
    # recorded"; falling straight to the permissive defaults would judge a fix
    # more leniently than the scan that found the problem (ADR-0016).
    fix.add_argument(
        "--sector",
        choices=SECTORS,
        default=None,
        help="override the sector recorded on the scan being fixed",
    )
    fix.add_argument(
        "--exposure",
        choices=EXPOSURES,
        default=None,
        help="override the exposure recorded on the scan being fixed",
    )
    fix.add_argument(
        "--crqc-years",
        type=int,
        default=None,
        metavar="Z",
        help="override the CRQC horizon recorded on the scan being fixed",
    )
    fix.add_argument(
        "--out",
        type=Path,
        default=None,
        metavar="DIR",
        help="also save each VERIFIED diff here as a .patch file",
    )
    fix.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the fix-annotated CBOM here",
    )

    rescore = subcommands.add_parser(
        "rescore",
        help="re-score a stored CBOM under a new CRQC horizon (no re-scan)",
    )
    rescore.add_argument("scan_id", help="the id of a scan already in the store")
    rescore.add_argument(
        "--z-years",
        type=int,
        default=None,
        metavar="Z",
        help=(
            "years until a cryptographically relevant quantum computer. "
            "Defaults to the horizon the scan was originally scored against"
        ),
    )
    rescore.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the re-scored CBOM here instead of stdout",
    )
    return parser


def _list_scanners() -> int:
    for scanner_id in registry.available_ids():
        print(scanner_id)
    return 0


def _scan(args: argparse.Namespace) -> int:
    try:
        scanners = registry.get_scanners(args.scanners)
    except registry.UnknownScannerError as exc:
        # Refused rather than silently narrowed: a scan that quietly skipped a
        # scanner still produces a CBOM, and that CBOM looks like an inventory.
        print(str(exc), file=sys.stderr)
        return 2

    configure_logging()
    target = Target(
        kind=args.kind,
        ref=args.ref,
        system=args.system,
        data_class=args.data_class,
        sector=args.sector,
        exposure=args.exposure,
    )
    scan_id = run_scan(target, scanners, default_context(), z_years=args.crqc_years)
    scan = store.get_scan(scan_id)
    if scan is None:  # pragma: no cover - the row was just committed
        print("scan disappeared after saving", file=sys.stderr)
        return 1

    if args.output is not None:
        args.output.write_text(scan.cbom_json, encoding="utf-8")
    else:
        sys.stdout.write(scan.cbom_json)

    destination = str(args.output) if args.output is not None else "stdout"
    print(
        f"scan_id={scan.id} component_count={scan.component_count} "
        f"cbom={destination} db={store.database_location()}",
        file=sys.stderr,
    )
    return 0


def _status_line(result: FixResult) -> str:
    if result.verified:
        return result.reason
    if result.applicable:
        return result.reason
    return (
        result.reason
        if result.reason.startswith("not applicable")
        else (f"not applicable -- {result.reason}")
    )


def _print_fix(index: int, total: int, reference: str, result: FixResult) -> None:
    print(f"=== fix {index}/{total} -- component {reference[:12]} ===")
    print(f"  template : {result.template_id}")
    print(f"  status   : {_status_line(result)}")
    if result.source:
        print(f"  source   : {result.source}")
    for entry in result.new_findings:
        print(f"  introduces: {entry}")
    if result.verified and result.diff:
        # Unindented, so the block can be piped straight into `git apply -p1`.
        print()
        print(result.diff, end="")
    print()


def _inherited_context(
    scan: store.Scan,
    sector: str | None,
    exposure: str | None,
    z_years: int | None,
) -> store.StoredContext:
    """Explicit flag > what the parent scan recorded > the permissive default.

    A seam, so `tests/test_store_migration.py` can disable the middle term and
    prove it is load-bearing: without it, `ecdat fix` silently scores against
    `other`/`unknown` and judges an introduced Critical more leniently than the
    scan that found the original problem.
    """
    return resolved_context(scan, sector=sector, exposure=exposure, z_years=z_years)


def _fix(args: argparse.Namespace) -> int:
    scan = store.get_scan(args.scan_id)
    if scan is None:
        print(f"no scan with id {args.scan_id!r} in the store", file=sys.stderr)
        return 2

    try:
        scanners = registry.get_scanners(args.scanners)
    except registry.UnknownScannerError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    context = _inherited_context(scan, args.sector, args.exposure, args.crqc_years)

    configure_logging()
    try:
        run = run_fix(
            args.scan_id,
            scanners,
            default_context(),
            sector=context.sector,
            exposure=context.exposure,
            z_years=context.z_years,
        )
    except (UnknownScanError, UnscannableTargetError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(f"ecdat fix -- scan {scan.id}")
    print(f"target: {run.target.kind} {run.target.ref}")
    print(
        f"context: sector={context.sector} exposure={context.exposure} "
        f"crqc_years={context.z_years}"
        + ("" if scan.sector is None else "  (inherited from the scan)")
    )
    print(
        "ECDAT NEVER applies a fix. Every diff below was applied to a throwaway "
        "sandbox copy and re-scanned; the target is untouched."
    )
    print()

    fixes = run.fixes
    for index, reference in enumerate(sorted(fixes), start=1):
        _print_fix(index, len(fixes), reference, fixes[reference])

    unverified = sum(1 for r in fixes.values() if r.applicable and not r.verified)
    declined = sum(1 for r in fixes.values() if not r.applicable)
    print(
        f"findings={run.finding_count} fixable={len(fixes)} "
        f"verified={run.verified} unverified={unverified} "
        f"not_applicable={declined}"
    )
    print(f"fix_scan_id={run.scan_id} parent_scan_id={run.parent_scan_id}")

    if args.out is not None:
        written = write_patches(fixes, args.out)
        print(f"saved {len(written)} verified patch(es) to {args.out}")

    if args.output is not None:
        stored = store.get_scan(run.scan_id)
        if stored is not None:
            args.output.write_text(stored.cbom_json, encoding="utf-8")
            print(f"fix-annotated CBOM written to {args.output}")

    return 0


def _rescore(args: argparse.Namespace) -> int:
    """Re-score a stored CBOM. No scanner runs; the parent row is untouched."""
    if store.get_scan(args.scan_id) is None:
        print(f"no scan with id {args.scan_id!r} in the store", file=sys.stderr)
        return 2

    configure_logging()
    try:
        scan_id = run_rescore(args.scan_id, default_context(), z_years=args.z_years)
    except (UnknownScanError, UnscannableTargetError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    rescored = store.get_scan(scan_id)
    if rescored is None:  # pragma: no cover - the row was just committed
        print("rescore disappeared after saving", file=sys.stderr)
        return 1

    if args.output is not None:
        args.output.write_text(rescored.cbom_json, encoding="utf-8")
    print(
        f"rescore_scan_id={scan_id} parent_scan_id={args.scan_id} "
        f"z_years={rescored.z_years} max_score={rescored.max_score}"
    )
    return 0


def _scan_system(args: argparse.Namespace) -> int:
    """Scan a whole system. The drift count is the headline, so it is printed.

    A single-target scan can never report drift -- the comparison needs two
    views in one document -- so this is the command whose drift line is worth
    reading (ADR-0019).
    """
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    configure_logging()
    try:
        scan_id = scan_system(manifest, default_context(), z_years=args.crqc_years)
    except TargetUnreadableError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    scan = store.get_scan(scan_id)
    if scan is None:  # pragma: no cover - the row was just committed
        print("scan disappeared after saving", file=sys.stderr)
        return 1

    if args.output is not None:
        args.output.write_text(scan.cbom_json, encoding="utf-8")
    else:
        sys.stdout.write(scan.cbom_json)

    summary = summarise(json.loads(scan.cbom_json))
    drift_total = sum(summary.drift_counts.values())
    destination = str(args.output) if args.output is not None else "stdout"
    print(
        f"scan_id={scan.id} system={manifest.system} "
        f"targets={len(manifest.targets)} "
        f"component_count={scan.component_count} "
        f"drift_count={drift_total} cbom={destination} "
        f"db={store.database_location()}",
        file=sys.stderr,
    )
    for kind, count in sorted(summary.drift_counts.items()):
        print(f"  drift {kind}={count}", file=sys.stderr)
    return 0


def _scans(args: argparse.Namespace) -> int:  # noqa: ARG001 - uniform handler
    """List what is actually in the database this environment points at.

    The one-command answer to "I scanned, why is the dashboard empty?". The
    path is printed with the rows, so the answer and the question arrive
    together (ADR-0020).
    """
    location = store.database_location()
    print(f"database: {location}")

    scans = store.list_scans()
    if not scans:
        # Distinct from printing nothing: an empty database and a command that
        # silently did nothing look identical otherwise.
        print("no scans in this database")
        return 0

    print(f"{'scan id':36}  {'kind':8}  {'components':>10}  {'drift':>7}  created")
    for scan in scans:
        drift = sum((scan.drift_counts or {}).values())
        print(
            f"{scan.id:36}  {scan.kind:8}  {scan.component_count:>10}  "
            f"drift={drift:<2}  {scan.created_at.isoformat(timespec='seconds')}"
        )
    print(f"{len(scans)} scan(s)")
    return 0


def _report(args: argparse.Namespace) -> int:
    """Render a report from a STORED scan. Nothing is re-scanned (ADR-0020)."""
    try:
        payload = render(report_for(args.kind), args.scan_id)
    except UnknownScanError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ValueError as exc:  # an unknown kind, named
        print(str(exc), file=sys.stderr)
        return 2

    destination = args.output
    if destination is None:
        directory = Path(DEFAULT_REPORT_DIR)
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"{args.kind}-{args.scan_id[:8]}.pdf"
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_bytes(payload)
    print(f"report={destination} kind={args.kind} bytes={len(payload)}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_scanners:
        return _list_scanners()
    if args.command == "scan":
        return _scan(args)
    if args.command == "scan-system":
        return _scan_system(args)
    if args.command == "scans":
        return _scans(args)
    if args.command == "report":
        return _report(args)
    if args.command == "fix":
        return _fix(args)
    if args.command == "rescore":
        return _rescore(args)
    parser.error("a command is required (or use --list-scanners)")


if __name__ == "__main__":
    raise SystemExit(main())
