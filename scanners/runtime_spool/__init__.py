"""Scanner D -- the spool consumer. Observed findings reach the store.

The runtime agent runs as root and attaches eBPF probes. The scan path
deliberately does not, and giving a privileged sensor an API credential to hold
would undo that (ADR-0010). So the two never talk: the agent writes JSON lines
into a directory, and this scanner reads them back as ordinary Findings. **The
filesystem is the trust boundary**, and it is the only thing they share.

That makes the spool a *scanner* rather than a service, which is the point: it
inherits the registry, the Finding contract, the orchestrator's per-plugin
isolation and the whole policy pipeline for free, and there is no second way for
a finding to enter the system.

**A pure consumer.** It never probes, never attaches, never needs root, and is
tested without any. Everything privileged happens in the agent, on the other
side of a rename.

**Untrusted input, by construction.** The producer is a root process decoding
kernel perf buffers, so a truncated or malformed line is a question of when, not
if. A bad line costs one line, is logged with a reason, and is counted. A file
whose lines were all bad moves to ``rejected/`` rather than being deleted -- a
silently discarded producer is a blind spot nobody knows they have.

**Idempotent.** An ingested file moves to ``consumed/``, so re-scanning a
directory does not double-count. Counting an estate's cryptography twice is
worse than missing it, because it looks like growth.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from agent.spool_format import (
    MAX_LINE_BYTES,
    SPOOL_SUFFIXES,
    TEMP_PREFIX,
    TEMP_SUFFIX,
)
from agent.to_finding import event_to_findings
from core.logs import get_logger
from core.scanner import ScanContext, Target
from core.schema import Finding, View

__all__ = [
    "CONSUMED_DIR",
    "MAX_LINE_BYTES",
    "REJECTED_DIR",
    "SPOOL_SUFFIXES",
    "TEMP_PREFIX",
    "TEMP_SUFFIX",
    "RuntimeSpoolScanner",
    "SpoolError",
    "SpoolUnreadableError",
]

_log = get_logger("scanner.runtime-spool")

#: Where ingested and unusable files go. Subdirectories of the spool, so one
#: path is the whole seam and there is nothing else to configure.
CONSUMED_DIR = "consumed"
REJECTED_DIR = "rejected"

#: TEMP_PREFIX, SPOOL_SUFFIXES and MAX_LINE_BYTES are re-exported from
#: agent.spool_format, which is the single definition both halves import.


class SpoolError(RuntimeError):
    """A condition that makes a spool scan impossible."""


class SpoolUnreadableError(SpoolError):
    """The spool path is missing or is not a readable directory."""


def _spool_files(root: Path) -> list[Path]:
    """Completed spool files, in a deterministic order.

    Excludes mid-write files by BOTH guards -- the ``.tmp-`` prefix and the
    absence of a spool suffix -- and anything under ``consumed/`` or
    ``rejected/`` (already handled). Not recursive: a spool is flat, and
    walking into it would re-ingest the archive.
    """
    return sorted(
        path
        for path in root.iterdir()
        if path.is_file()
        and not path.name.startswith(TEMP_PREFIX)
        and path.suffix in SPOOL_SUFFIXES
    )


def _archive(path: Path, root: Path, subdirectory: str) -> Path:
    """Move a handled file aside, without ever overwriting one already there.

    Two agent runs can produce the same filename. Losing the older record to a
    silent overwrite would destroy evidence the seam exists to preserve, so a
    collision gets a numeric suffix rather than a clobber.
    """
    destination_dir = root / subdirectory
    destination_dir.mkdir(parents=True, exist_ok=True)

    destination = destination_dir / path.name
    counter = 1
    while destination.exists():
        destination = destination_dir / f"{path.stem}.{counter}{path.suffix}"
        counter += 1

    path.rename(destination)
    return destination


class RuntimeSpoolScanner:
    """Reads observed findings the runtime agent left in a spool directory."""

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "runtime-spool"
    view: View = "observed"

    def supports(self, target: Target) -> bool:
        return target.kind == "spool"

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:  # noqa: ARG002
        root = Path(target.ref)
        if not root.is_dir():
            raise SpoolUnreadableError(
                f"the spool directory does not exist or is not a directory: "
                f"{root}\n"
                "  Point --ref at the directory the agent was given with "
                "--spool, and check the consumer can read it (the agent runs "
                "as root)."
            )

        ingested = 0
        skipped = 0
        files_consumed = 0
        files_rejected = 0

        for path in _spool_files(root):
            valid = 0
            for found, bad in self._read_file(path):
                for finding in found:
                    valid += 1
                    ingested += 1
                    yield finding
                skipped += bad

            if valid:
                _archive(path, root, CONSUMED_DIR)
                files_consumed += 1
            else:
                # Kept, not deleted: a producer emitting nothing usable is a
                # fact about the estate, and deleting the evidence would make
                # it invisible.
                _archive(path, root, REJECTED_DIR)
                files_rejected += 1
                _log.warning(
                    "spool_file_rejected: %s yielded no valid findings",
                    path.name,
                    extra={
                        "event": "spool_file_rejected",
                        "spool_file": path.name,
                        "lines_skipped": skipped,
                    },
                )

        _log.info(
            "spool_ingested",
            extra={
                "event": "spool_ingested",
                "spool_dir": str(root),
                "findings_ingested": ingested,
                "lines_skipped": skipped,
                "files_consumed": files_consumed,
                "files_rejected": files_rejected,
            },
        )

    def _read_file(self, path: Path) -> Iterator[tuple[list[Finding], int]]:
        """Yield ``(findings, bad_line_count)`` for each line in one file.

        One line can yield several artefacts: a TLS handshake negotiates a
        version, a cipher suite and a key-exchange group, and each is its own
        component in the CBOM (ADR-0011).
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning(
                "spool_file_unreadable: %s (%s)",
                path.name,
                exc,
                extra={"event": "spool_file_unreadable", "spool_file": path.name},
            )
            return

        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            yield self._read_line(line, path, number)

    def _read_line(
        self, line: str, path: Path, number: int
    ) -> tuple[list[Finding], int]:
        def skip(reason: str) -> tuple[list[Finding], int]:
            _log.warning(
                "spool_line_skipped: %s:%d %s",
                path.name,
                number,
                reason,
                extra={
                    "event": "spool_line_skipped",
                    "spool_file": path.name,
                    "line_number": number,
                    "reason": reason,
                },
            )
            return [], 1

        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return skip(f"line is longer than {MAX_LINE_BYTES} bytes")

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            return skip(f"not valid JSON ({exc.msg})")

        if not isinstance(event, dict):
            return skip(f"line is a {type(event).__name__}, expected an object")

        # The same mapping the agent uses for --findings, so producer and
        # consumer cannot disagree about what an event means. It returns an
        # empty list and logs for anything it cannot trust.
        findings = event_to_findings(event)
        if not findings:
            return skip("the event could not be mapped to any Finding")

        # Re-attributed to this scanner: the agent observed it, but this plugin
        # is what put it in the CBOM, and scanner_id is how a claim is traced
        # back to the thing that emitted it.
        return [f.model_copy(update={"scanner_id": self.id}) for f in findings], 0
