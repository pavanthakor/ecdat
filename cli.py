"""`ecdat scan <ref>` -- run a scan from the command line.

    python cli.py scan /srv/quantumbank --system quantumbank
    python cli.py scan /srv/quantumbank -o cbom.json
    python cli.py scan /srv/quantumbank --scanner source
    python cli.py --list-scanners

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
from core.scanner import Target, TargetKind

__all__ = ["main"]

TARGET_KINDS: tuple[TargetKind, ...] = (
    "repo",
    "directory",
    "image",
    "host",
    "endpoint",
)


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
        "--data-class", default=None, help="data-classification tag for the target"
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
    )
    scan_id = run_scan(target, scanners, default_context())
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_scanners:
        return _list_scanners()
    if args.command == "scan":
        return _scan(args)
    parser.error("a command is required (or use --list-scanners)")


if __name__ == "__main__":
    raise SystemExit(main())
