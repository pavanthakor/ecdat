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
from core.orchestrator import default_context, run_scan
from core.scanner import Exposure, ScanContext, Scanner, Sector, Target, TargetKind
from core.schema import Finding
from correlate.fixit.apply import apply_fixes, propose_fixes, write_patches
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

SECTORS: tuple[Sector, ...] = ("defence", "power", "telecom", "bfsi", "other")
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
    # sector and exposure are NOT persisted on the scan row (see PUNCHLIST), so
    # they have to be supplied again. They matter here: they decide whether a
    # finding the fix introduces counts as Critical.
    fix.add_argument(
        "--sector",
        choices=SECTORS,
        default="other",
        help=(
            "sector this target serves. Not stored on the scan row, so it is "
            "re-supplied here; it decides whether an introduced finding is "
            "Critical"
        ),
    )
    fix.add_argument(
        "--exposure",
        choices=EXPOSURES,
        default="unknown",
        help="how reachable the target is; same caveat as --sector",
    )
    fix.add_argument(
        "--crqc-years",
        type=int,
        default=DEFAULT_Z_YEARS,
        metavar="Z",
        help=f"years until a CRQC (default {DEFAULT_Z_YEARS})",
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


def _stored_kind(value: str) -> TargetKind | None:
    """Narrow a target kind read back out of the store to the closed vocabulary.

    ``store.Scan.target_kind`` is a plain column, so a row could in principle
    hold anything. Refusing an unrecognised kind is better than casting: a fix
    run against a target ECDAT cannot classify would pick the wrong scanners.
    """
    for kind in TARGET_KINDS:
        if value == kind:
            return kind
    return None


def _collect_findings(
    scanners: Sequence[Scanner], target: Target, ctx: ScanContext
) -> list[Finding]:
    """Re-read the target so fixes are proposed against what is there NOW.

    A stored CBOM records what a scan saw; a fix has to be generated against
    the current bytes, or it patches a line that has since moved. A scanner
    that fails degrades the fix run the same way it degrades a scan.
    """
    findings: list[Finding] = []
    for scanner in scanners:
        if not scanner.supports(target):
            continue
        try:
            findings.extend(scanner.scan(target, ctx))
        except Exception as exc:  # plugin isolation, as in the orchestrator
            print(f"scanner {scanner.id!r} failed: {exc}", file=sys.stderr)
    return findings


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

    kind = _stored_kind(scan.target_kind)
    if kind is None:
        print(
            f"scan {scan.id} records target kind {scan.target_kind!r}, which is "
            f"not a kind ECDAT knows about",
            file=sys.stderr,
        )
        return 2

    configure_logging()
    target = Target(
        kind=kind,
        ref=scan.target_ref,
        system=scan.target_system,
        data_class=scan.target_data_class,
        sector=args.sector,
        exposure=args.exposure,
    )
    ctx = default_context()

    print(f"ecdat fix -- scan {scan.id}")
    print(f"target: {target.kind} {target.ref}")
    print(
        "ECDAT NEVER applies a fix. Every diff below was applied to a throwaway "
        "sandbox copy and re-scanned; the target is untouched."
    )
    print()

    findings = _collect_findings(scanners, target, ctx)
    fixes = propose_fixes(findings, target, context=ctx, z_years=args.crqc_years)

    for index, reference in enumerate(sorted(fixes), start=1):
        _print_fix(index, len(fixes), reference, fixes[reference])

    verified = sum(1 for r in fixes.values() if r.verified)
    unverified = sum(1 for r in fixes.values() if r.applicable and not r.verified)
    declined = sum(1 for r in fixes.values() if not r.applicable)
    print(
        f"findings={len(findings)} fixable={len(fixes)} verified={verified} "
        f"unverified={unverified} not_applicable={declined}"
    )

    if args.out is not None:
        written = write_patches(fixes, args.out)
        print(f"saved {len(written)} verified patch(es) to {args.out}")

    if args.output is not None:
        args.output.write_text(apply_fixes(scan.cbom_json, fixes), encoding="utf-8")
        print(f"fix-annotated CBOM written to {args.output}")

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
    parser.error("a command is required (or use --list-scanners)")


if __name__ == "__main__":
    raise SystemExit(main())
