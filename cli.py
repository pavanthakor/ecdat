"""`ecdat scan <ref>` and `ecdat fix <scan-id>` -- ECDAT from the command line.

    python cli.py scan /srv/quantumbank --system quantumbank
    python cli.py scan /srv/quantumbank -o cbom.json
    python cli.py scan /srv/quantumbank --scanner source
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
from correlate.fixit.apply import write_patches
from correlate.fixit.engine import FixResult
from policy.apply import DEFAULT_Z_YEARS

__all__ = ["main"]

TARGET_KINDS: tuple[TargetKind, ...] = (
    "repo",
    "directory",
    "image",
    "host",
    "endpoint",
    "spool",
)

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
        f"scan_id={scan.id} component_count={scan.component_count} cbom={destination}",
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_scanners:
        return _list_scanners()
    if args.command == "scan":
        return _scan(args)
    if args.command == "fix":
        return _fix(args)
    if args.command == "rescore":
        return _rescore(args)
    parser.error("a command is required (or use --list-scanners)")


if __name__ == "__main__":
    raise SystemExit(main())
