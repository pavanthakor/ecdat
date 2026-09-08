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

__all__ = ["ScanContext", "Scanner", "Target", "TargetKind"]

#: What sort of thing is being scanned. Determines which plugins apply and
#: which view their findings land in.
TargetKind = Literal["repo", "directory", "image", "host", "endpoint"]


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
    #: the Mosca "how long must this stay secret" term.
    data_class: str | None = None


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
