"""The spool wire format -- the one definition both halves of the seam share.

The producer (``agent/agent.py``, running as root) and the consumer
(``scanners/runtime_spool``, running as anyone) agree on exactly three things:
which files are complete, which are mid-write, and how a record is named. Those
live here so there is a single definition rather than two that can drift.

Deliberately dependency-free -- no pydantic, no core imports. The agent must
stay importable on the system interpreter, where bcc lives and this repo's
dependencies do not (ADR-0009), so anything the agent imports at module scope
has to be as plain as this.
"""

from __future__ import annotations

import os
import re
import socket
import time

__all__ = [
    "MAX_LINE_BYTES",
    "SPOOL_SUFFIXES",
    "TEMP_PREFIX",
    "TEMP_SUFFIX",
    "spool_stem",
]

#: A file being written carries this prefix and MUST NEVER be read. The
#: producer writes ``.tmp-<uniq>`` and renames into place; rename within a
#: directory is atomic on POSIX, so the consumer -- polling a directory it does
#: not coordinate with -- can never see a half-written record.
TEMP_PREFIX = ".tmp-"

#: An in-progress file also does NOT end in a spool suffix. Two independent
#: guards rather than one: ``pathlib.Path.glob("*.jsonl")`` matches dotfiles,
#: unlike a shell glob, so a temp file named ``.tmp-x.jsonl`` would be picked up
#: by any consumer that reached for the obvious pattern. Making the prefix and
#: the suffix each sufficient means getting it wrong takes two mistakes.
TEMP_SUFFIX = ".partial"

#: What counts as a spool record. Anything else in the directory belongs to
#: somebody else and is left alone.
SPOOL_SUFFIXES = (".jsonl", ".json")

#: A spool line is one event. Longer than this is not a line we wrote, and
#: reading it into memory is the consumer's problem to refuse.
MAX_LINE_BYTES = 64 * 1024

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def spool_stem(host: str, pid: int, sequence: int) -> str:
    """``<host>-<pid>-<timestamp_ns>-<seq>`` -- unique, and sortable by time.

    Unique across hosts, across concurrent agents on one host, and across
    re-runs of the same agent, so a later record can never overwrite an earlier
    one the consumer has not read yet. The nanosecond timestamp makes the
    natural filename order the arrival order, which is what makes ingest
    deterministic.
    """
    safe_host = _UNSAFE.sub("_", host)[:40] or "host"
    return f"{safe_host}-{pid}-{time.time_ns()}-{sequence:06d}"


def local_stem(sequence: int) -> str:
    """:func:`spool_stem` for this process."""
    return spool_stem(socket.gethostname(), os.getpid(), sequence)
