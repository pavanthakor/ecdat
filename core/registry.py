"""The scanner registry -- the single source of truth for which plugins exist.

Before this module, ``api/app.py`` and ``cli.py`` each carried their own
hard-coded list of scanners. Adding a plugin meant editing both and remembering
both, and forgetting one was silent: the CLI would find crypto the API did not.
With six scanner families planned, that was a bug waiting to be shipped.

Now there is one list, at the bottom of this file. **Adding a scanner is one
import and one ``register(...)`` line here, and no change to the API or the
CLI.**

Registration is an explicit call, not entry-point discovery or an import-time
side effect in a package ``__init__``. That is deliberate: mypy and ruff can
see a call, so a scanner that fails the :class:`~core.scanner.Scanner` protocol
is caught statically, and a reader can answer "what runs?" by reading one
block. Plugin magic buys extensibility this project does not need and costs
traceability it does.

**Dependency direction.** This is the one module in ``core`` that imports from
``scanners``. That inversion is the point of a registry -- it is the wiring
layer, so the wiring lives in exactly one place. The rule that still holds is
the one ADR-0001 actually cares about: no scanner imports the orchestrator.
"""

from __future__ import annotations

from collections.abc import Sequence

from core.scanner import Scanner
from scanners.binary import BinaryScanner
from scanners.config import ConfigScanner
from scanners.container import ContainerScanner
from scanners.deps import DepsScanner
from scanners.runtime_spool import RuntimeSpoolScanner
from scanners.source import SourceScanner

__all__ = [
    "DuplicateScannerError",
    "Registry",
    "RegistryError",
    "UnknownScannerError",
    "available_ids",
    "get_scanners",
    "register",
]


class RegistryError(Exception):
    """Base class for registry problems."""


class UnknownScannerError(RegistryError, LookupError):
    """A scanner id was requested that nothing has registered."""


class DuplicateScannerError(RegistryError, ValueError):
    """Two scanners claim the same id."""


class Registry:
    """A named collection of scanner plugins.

    Instantiable so tests can work against a registry of their own rather than
    mutating the process-wide one; application code uses the module-level
    functions, which delegate to :data:`DEFAULT_REGISTRY`.
    """

    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}

    def register(self, scanner: Scanner) -> Scanner:
        """Add ``scanner`` under its own ``id``. Returns it, for inline use.

        A duplicate id is refused rather than overwritten: two plugins claiming
        the same id means findings from one would be attributed to the other,
        and every Finding carries ``scanner_id`` precisely so a claim traces
        back to its producer.
        """
        existing = self._scanners.get(scanner.id)
        if existing is not None:
            raise DuplicateScannerError(
                f"scanner id {scanner.id!r} is already registered by "
                f"{type(existing).__name__}; ids must be unique because every "
                f"Finding is attributed by scanner_id"
            )
        self._scanners[scanner.id] = scanner
        return scanner

    def get_scanners(self, ids: Sequence[str] | None = None) -> list[Scanner]:
        """The scanners to run.

        ``None`` means "everything registered" -- the default for a scan. A
        sequence selects that subset; an *empty* sequence selects nothing,
        which is a different thing from ``None`` and is honoured as written.

        The result is always sorted by id and de-duplicated, whatever order the
        caller asked in, so a CBOM never depends on how a request happened to
        be phrased.
        """
        if ids is None:
            return [self._scanners[key] for key in sorted(self._scanners)]

        wanted = set(ids)
        unknown = sorted(wanted - self._scanners.keys())
        if unknown:
            available = ", ".join(self.available_ids()) or "(none registered)"
            raise UnknownScannerError(
                f"unknown scanner id(s): {', '.join(unknown)}. Available: {available}"
            )
        return [self._scanners[key] for key in sorted(wanted)]

    def available_ids(self) -> list[str]:
        """Every registered id, sorted. Deterministic by construction."""
        return sorted(self._scanners)


#: The registry the application uses.
DEFAULT_REGISTRY = Registry()


def register(scanner: Scanner) -> Scanner:
    """Register ``scanner`` in the process-wide registry."""
    return DEFAULT_REGISTRY.register(scanner)


def get_scanners(ids: Sequence[str] | None = None) -> list[Scanner]:
    """Scanners from the process-wide registry. ``None`` means all of them."""
    return DEFAULT_REGISTRY.get_scanners(ids)


def available_ids() -> list[str]:
    """Every id in the process-wide registry, sorted."""
    return DEFAULT_REGISTRY.available_ids()


# ---------------------------------------------------------------------------
# The built-in scanners.
#
# THIS IS THE LIST. Adding a scanner family means adding an import above and
# one register() line here -- nothing in api/ or cli.py changes.
# ---------------------------------------------------------------------------

register(BinaryScanner())
register(ConfigScanner())
register(ContainerScanner())
register(DepsScanner())
register(RuntimeSpoolScanner())
register(SourceScanner())
