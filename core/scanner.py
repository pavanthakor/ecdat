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

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from core.schema import Finding, View

__all__ = [
    "CoverageGap",
    "CoverageLog",
    "Exposure",
    "GapKind",
    "ScanContext",
    "Scanner",
    "Sector",
    "Target",
    "TargetKind",
]

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


#: How much of a file a scanner could read (ADR-0033). ``unparsed``: nothing,
#: so no finding can have come from it. ``partially-parsed``: the parser
#: recovered, so findings from the part it read are real -- and the rest of the
#: file went unexamined all the same.
GapKind = Literal["unparsed", "partially-parsed"]


@dataclass(frozen=True, slots=True)
class CoverageGap:
    """A file a scanner examined and could not fully read.

    A file the parser rejected contributes no finding, and without this record
    its silence would read as a clean file. It is not one.
    """

    scanner: str
    #: As the scanner reported it -- the same spelling its findings' evidence
    #: locators use, so the two can be cross-referenced.
    path: str
    kind: GapKind
    #: The parser's own word for it, e.g. ``"Syntax error"``, ``"PartialParsing"``.
    reason: str


@dataclass(slots=True)
class CoverageLog:
    """Per-scan record of what the scanners could NOT read (ADR-0033).

    Separate from the findings on purpose, like the binary scanner's coverage
    report: "six findings" and "six findings, and two files could not be
    parsed" are different statements, and only the second is safe to act on.
    """

    gaps: list[CoverageGap] = field(default_factory=list)
    #: Files each scanner EXAMINED, readable or not -- the denominator that
    #: turns "two files could not be parsed" into "two of five".
    examined: dict[str, int] = field(default_factory=dict)

    def record(self, scanner: str, examined: int, gaps: Iterable[CoverageGap]) -> None:
        self.examined[scanner] = self.examined.get(scanner, 0) + examined
        self.gaps.extend(gaps)
        # One order, however many targets or scanners contributed.
        self.gaps.sort(key=lambda g: (g.scanner, g.path, g.kind, g.reason))

    def nothing_parsed(self, scanner: str) -> bool:
        """True when ``scanner`` examined files and could read NONE of them."""
        examined = self.examined.get(scanner, 0)
        unparsed = {
            g.path for g in self.gaps if g.scanner == scanner and g.kind == "unparsed"
        }
        return examined > 0 and len(unparsed) >= examined


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a scanner is allowed to depend on besides its target."""

    #: Read-only knowledge packs: algorithm facts, rules, roadmap deadlines.
    #: The only permitted source of crypto knowledge -- there is no network.
    knowledge_dir: Path
    #: Writable working area. The one place a scanner may create files;
    #: never write inside the target.
    scratch_dir: Path
    #: Where a scanner reports what it could NOT read (ADR-0033). Per-scan: the
    #: orchestrator hands every scan a fresh log, so two scans -- or two API
    #: requests sharing a registry's scanner instances -- can never share one.
    #: ``None`` means nobody is collecting; a scanner still LOGS what it could
    #: not read, it just has nowhere durable to record it. Not part of the
    #: context's identity, so it is excluded from equality and hashing.
    coverage: CoverageLog | None = field(default=None, compare=False)


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
