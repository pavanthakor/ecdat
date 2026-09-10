"""The scanner plugin contract (ADR-0001).

Every discovery capability in ECDAT -- source, dependencies, containers,
binaries, running processes, network handshakes -- is a plugin that satisfies
:class:`Scanner`. Plugins are structural, not inherited: anything exposing the
four members below is a scanner, which keeps the scanners package free of
imports from the orchestrator.

Two rules bind every implementation:

* **Read-only against targets.** A scanner may open, parse and probe; it must
  never write to, patch or otherwise modify a repo, image or host. Anything a
  scanner needs to unpack goes under :attr:`ScanContext.scratch_dir`.
* **Offline.** No outbound network calls in the scan path. Everything a scanner
  needs to reason with comes from :attr:`ScanContext.knowledge_dir`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from core.schema import Finding, View

__all__ = ["Exposure", "ScanContext", "Scanner", "Sector", "Target", "TargetKind"]

#: What sort of thing is being scanned. Determines which plugins apply and
#: which view their findings land in.
#: ``spool`` is a directory of JSON lines the runtime agent left behind, not a
#: thing to probe. It is a target kind rather than a special case so the
#: observed view enters the system through the same contract as every other
#: view -- see ADR-0010.
TargetKind = Literal["repo", "directory", "image", "host", "endpoint", "spool"]

#: Which part of the estate this target belongs to. Drives the India DST
#: roadmap's critical-information-infrastructure deadlines, which are earlier
#: for critical information infrastructure than for everything else.
#:
#: The seven CII sectors are the roadmap's own list (DST/NQM "Report on
#: Quantum-Safe Ecosystem in India", May 2026, Sec. 9.0). ECDAT's first
#: encoding carried only four of them; government, strategic and transport were
#: missing, which silently under-scored every asset in those sectors. A sector
#: the roadmap names and this vocabulary omits is not a gap somebody notices --
#: the target simply falls through to `other` and the CII rule never fires.
Sector = Literal[
    "government",
    "strategic",
    "defence",
    "power",
    "telecom",
    "transport",
    "bfsi",
    "other",
]

#: How reachable this target is. Feeds blast-radius prioritisation: the same
#: algorithm on an internet-facing service is collectable today in a way the
#: same algorithm in a build tool is not.
Exposure = Literal["internet", "internal", "build", "unknown"]


@dataclass(frozen=True, slots=True)
class Target:
    """A thing to scan. Inert: holds no handles and opens nothing."""

    kind: TargetKind
    #: Path, image reference or hostname, interpreted according to ``kind``.
    ref: str
    #: Optional grouping tag -- the service or system this target belongs to.
    #: Used to roll findings up for blast-radius scoring.
    system: str | None = None
    #: Optional data-classification tag (e.g. ``"pii"``, ``"public"``). Feeds
    #: the Mosca "how long must this stay secret" term via
    #: ``knowledge/data_classes.yaml``. Absent means UNKNOWN, not "public":
    #: the policy engine declines to compute Mosca urgency rather than assume
    #: there is nothing to protect.
    data_class: str | None = None
    #: Which sector this target serves. Drives the DST roadmap's earlier
    #: critical-information-infrastructure deadline.
    sector: Sector = "other"
    #: How reachable this target is. Feeds blast-radius prioritisation.
    exposure: Exposure = "unknown"


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a scanner is allowed to depend on besides its target."""

    #: Read-only knowledge packs: algorithm facts, rules, roadmap deadlines.
    #: The only permitted source of crypto knowledge -- there is no network.
    knowledge_dir: Path
    #: Writable working area. The one place a scanner may create files;
    #: never write inside the target.
    scratch_dir: Path


@runtime_checkable
class Scanner(Protocol):
    """Structural contract for a discovery plugin."""

    #: Stable plugin identifier, ``"<family>.<tool>"``, e.g. ``"source.semgrep"``.
    #: Copied onto every Finding it emits so any claim traces back to its
    #: producer.
    id: str
    #: The drift view this plugin's findings belong to.
    view: View

    def supports(self, target: Target) -> bool:
        """Whether this plugin can say anything about ``target``.

        Must be cheap and side-effect-free: no unpacking, no probing.
        """
        ...

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        """Yield findings for ``target``, lazily.

        Read-only against the target and offline. Yielding nothing is a valid
        result; raising is reserved for a plugin that cannot run at all.
        """
        ...
