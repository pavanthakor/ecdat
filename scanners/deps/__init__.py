"""Scanner B -- dependencies: cryptography a project declares by depending on it.

The fourth producer of the `declared` view, and it answers a question the source
scanner structurally cannot. A repo with no `hashlib` call and
`cryptography==41.0` in its lockfile is carrying an RSA implementation, a set of
weak defaults and an end-of-support date — and only the manifest says so.

**THE BOUNDARY (ADR-0021).** This scanner finds THIRD-PARTY crypto LIBRARIES.
It does not find stdlib crypto usage: `hashlib.md5(...)` in Python and
`crypto/aes` in Go are call sites in source, and Scanner A owns those. The two
are different assets about different things —

* `asset_type="library"`, `algorithm="cryptography"`, version 42.0.5, from
  `poetry.lock` — *this project depends on somebody else's crypto*;
* `asset_type="algorithm"`, `algorithm="RSA"`, key_size 2048, from
  `keys.py:12` — *this project generates an RSA key here*.

They never merge (ADR-0002 keys identity on asset type, algorithm, params and
locus), and a scan carrying both is not double-counting: it is saying a library
is present AND naming where it is used, which is exactly what a migration plan
needs.

**LOCKFILE-PREFERRED.** A manifest range and a lockfile pin describe the same
dependency with different certainty. The lockfile wins, because a
post-quantum-capability verdict on "somewhere between 41 and 43" is a verdict on
a version nobody has installed. Where only a range exists it is recorded AS a
range, with a note and reduced confidence, and the capability question is left
unanswered rather than guessed at either end of the interval.

**The knowledge pack decides what counts as cryptography.** Package names live
in `knowledge/libraries.yaml`, not here — the same rule the container scanner
follows (ADR-0006) and the source scanner follows for algorithm names
(ADR-0004). A non-crypto dependency produces no finding at all: an inventory
that lists `lodash` is an inventory nobody will read.

Read-only and offline: it opens files and parses text.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.logs import get_logger
from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence, View
from scanners.libraries import (
    LibraryFact,
    index_for,
    is_pqc_capable,
    upstream_version,
)

__all__ = ["Dependency", "DepsScanner"]

_log = get_logger("scanner.deps")

_VIEW: View = "declared"

#: Manifests and lockfiles this scanner understands, and which ecosystem each
#: belongs to. Explicit filenames rather than a glob: parsing "anything that
#: looks like a lockfile" produces confident nonsense.
PYTHON_FILES = ("poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml")
NODE_FILES = ("package-lock.json", "yarn.lock", "package.json")
GO_FILES = ("go.mod", "go.sum")

#: Per ecosystem, files in DESCENDING order of certainty. The first one present
#: in a directory wins: a lockfile's resolved version beats a manifest's range,
#: and a range is only read when nothing pinned it.
PRECEDENCE: dict[str, tuple[str, ...]] = {
    "pypi": PYTHON_FILES,
    "npm": NODE_FILES,
    "go": GO_FILES,
}

#: Directories that hold OTHER projects' manifests. A dependency's own
#: `package.json` is not this project's dependency, and walking into
#: `node_modules` would turn one project into its whole transitive world.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        "site-packages",
        ".tox",
        ".nox",
    }
)

#: A manifest larger than this is not one of these formats.
MAX_MANIFEST_BYTES = 8 * 1024 * 1024

#: Confidence for a dependency whose version is only a range. Not a heuristic
#: match -- the dependency is certain, its VERSION is not, and every capability
#: statement downstream rests on the version.
RANGE_CONFIDENCE = 0.7

#: Characters that make a version specifier a range rather than a pin.
_RANGE_MARKERS = ("^", "~", ">", "<", "*", "||", " - ", ",")

_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*?)\s*$"
)
_GO_REQUIRE = re.compile(r"^\s*(?P<module>[^\s]+)\s+(?P<version>v[^\s/]+)\s*(//.*)?$")
_YARN_ENTRY = re.compile(r'^"?(?P<name>@?[^@\s"]+)@')
_YARN_VERSION = re.compile(r'^\s+version\s+"?(?P<version>[^"\s]+)"?')


@dataclass(frozen=True, slots=True)
class Dependency:
    """One declared dependency, before the knowledge pack has judged it."""

    name: str
    version: str
    #: True when ``version`` is a specifier rather than a resolved version.
    is_range: bool
    #: 1-based line in the manifest, for the evidence locator.
    line: int


# ---------------------------------------------------------------------------
# Parsers. Each returns what the file SAYS; none of them decide what counts.
# ---------------------------------------------------------------------------


def _is_range(spec: str) -> bool:
    return any(marker in spec for marker in _RANGE_MARKERS)


def parse_requirements(text: str) -> list[Dependency]:
    """``requirements.txt``: one requirement per line, ranges and pins alike."""
    found: list[Dependency] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            # `-r other.txt`, `-e .`, `--index-url ...`: directives, not
            # dependencies. The referenced file is walked on its own if it is
            # inside the target.
            continue
        match = _REQUIREMENT.match(line)
        if match is None:
            continue
        spec = match.group("spec").strip()
        if spec.startswith("=="):
            found.append(
                Dependency(match.group("name"), spec[2:].strip(), False, number)
            )
        elif spec:
            found.append(Dependency(match.group("name"), spec, True, number))
        else:
            # A bare name pins nothing at all -- the loosest possible range.
            found.append(Dependency(match.group("name"), "*", True, number))
    return found


def parse_poetry_lock(text: str) -> list[Dependency]:
    """``poetry.lock``: TOML, ``[[package]]`` tables with resolved versions."""
    document = tomllib.loads(text)
    found: list[Dependency] = []
    for package in document.get("package", []):
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            found.append(Dependency(name, version, False, _line_of(text, name)))
    return found


def parse_pipfile_lock(text: str) -> list[Dependency]:
    """``Pipfile.lock``: JSON, versions written as ``"==1.2.3"``."""
    document = json.loads(text)
    found: list[Dependency] = []
    for section in ("default", "develop"):
        for name, entry in (document.get(section) or {}).items():
            version = (entry or {}).get("version", "")
            if isinstance(version, str) and version.startswith("=="):
                found.append(Dependency(name, version[2:], False, _line_of(text, name)))
            elif isinstance(version, str) and version:
                found.append(Dependency(name, version, True, _line_of(text, name)))
    return found


def parse_pyproject(text: str) -> list[Dependency]:
    """``pyproject.toml``: PEP 621 ``project.dependencies`` and Poetry's table."""
    document = tomllib.loads(text)
    found: list[Dependency] = []

    for requirement in document.get("project", {}).get("dependencies", []) or []:
        if isinstance(requirement, str):
            found.extend(parse_requirements(requirement))

    poetry = document.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            found.append(Dependency(name, spec, _is_range(spec), _line_of(text, name)))
        elif isinstance(spec, dict) and isinstance(spec.get("version"), str):
            version = spec["version"]
            found.append(
                Dependency(name, version, _is_range(version), _line_of(text, name))
            )

    for dependency in found:
        object.__setattr__(dependency, "line", _line_of(text, dependency.name))
    return found


def parse_package_lock(text: str) -> list[Dependency]:
    """``package-lock.json``: v2/v3 ``packages`` or v1 ``dependencies``."""
    document = json.loads(text)
    found: list[Dependency] = []

    for path, entry in (document.get("packages") or {}).items():
        if not path:  # the root project describes itself, not a dependency
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        version = (entry or {}).get("version")
        if isinstance(version, str):
            found.append(Dependency(name, version, False, _line_of(text, name)))

    if not found:
        for name, entry in (document.get("dependencies") or {}).items():
            version = (entry or {}).get("version")
            if isinstance(version, str):
                found.append(Dependency(name, version, False, _line_of(text, name)))
    return found


def parse_package_json(text: str) -> list[Dependency]:
    """``package.json``: declared ranges, read only when nothing pinned them."""
    document = json.loads(text)
    found: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (document.get(section) or {}).items():
            if isinstance(spec, str):
                found.append(
                    Dependency(name, spec, _is_range(spec), _line_of(text, name))
                )
    return found


def parse_yarn_lock(text: str) -> list[Dependency]:
    """``yarn.lock``: ``name@range:`` blocks, each with a resolved ``version``."""
    found: list[Dependency] = []
    name: str | None = None
    name_line = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace() and not line.startswith("#"):
            match = _YARN_ENTRY.match(line.strip())
            name = match.group("name") if match else None
            name_line = number
            continue
        version = _YARN_VERSION.match(line)
        if version and name:
            found.append(Dependency(name, version.group("version"), False, name_line))
            name = None
    return found


def parse_go_mod(text: str) -> list[Dependency]:
    """``go.mod``: ``require`` blocks and single-line requires."""
    found: list[Dependency] = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue

        if line.startswith("require "):
            candidate = line[len("require ") :].strip()
        else:
            candidate = line if in_block else ""
        if not candidate:
            continue
        match = _GO_REQUIRE.match(candidate)
        if match:
            found.append(
                Dependency(
                    match.group("module"),
                    upstream_version(match.group("version")),
                    False,
                    number,
                )
            )
    return found


def parse_go_sum(text: str) -> list[Dependency]:
    """``go.sum``: every module the build graph touched, deduped."""
    seen: dict[tuple[str, str], Dependency] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        parts = raw.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        module = parts[0]
        version = upstream_version(parts[1].removesuffix("/go.mod"))
        seen.setdefault((module, version), Dependency(module, version, False, number))
    return list(seen.values())


PARSERS = {
    "poetry.lock": ("pypi", parse_poetry_lock),
    "Pipfile.lock": ("pypi", parse_pipfile_lock),
    "requirements.txt": ("pypi", parse_requirements),
    "pyproject.toml": ("pypi", parse_pyproject),
    "package-lock.json": ("npm", parse_package_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "package.json": ("npm", parse_package_json),
    "go.mod": ("go", parse_go_mod),
    "go.sum": ("go", parse_go_sum),
}


def _line_of(text: str, needle: str) -> int:
    """The first line mentioning ``needle``, so evidence points somewhere real.

    JSON and TOML parsers discard position, and a locator without a line sends
    a reviewer to hunt through a lockfile. A best-effort line beats none.
    """
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 0


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class DepsScanner:
    """Finds third-party crypto libraries in manifests and lockfiles (ADR-0021)."""

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "deps"
    view: View = "declared"

    SUPPORTED_KINDS = frozenset({"repo", "directory"})

    def supports(self, target: Target) -> bool:
        return target.kind in self.SUPPORTED_KINDS

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        root = Path(target.ref)
        if not root.is_dir():
            return

        packs = {
            ecosystem: index_for(ctx.knowledge_dir, ecosystem)
            for ecosystem in PRECEDENCE
        }

        # Sorted, so the CBOM never depends on filesystem walk order.
        for directory in sorted(self._project_dirs(root)):
            for ecosystem, filename in self._chosen_files(directory):
                path = directory / filename
                parsed = self._parse(path, filename)
                if parsed is None:
                    continue
                yield from self._findings(parsed, path, ecosystem, packs[ecosystem])

    # -- walking ---------------------------------------------------------

    def _project_dirs(self, root: Path) -> set[Path]:
        """Every directory holding at least one manifest we understand."""
        found: set[Path] = set()
        for path in root.rglob("*"):
            if not path.is_file() or SKIP_DIRS & set(path.parts):
                continue
            if path.name in PARSERS:
                try:
                    if path.stat().st_size > MAX_MANIFEST_BYTES:
                        continue
                except OSError:
                    continue
                found.add(path.parent)
        return found

    def _chosen_files(self, directory: Path) -> list[tuple[str, str]]:
        """One file per ecosystem: the most certain one present.

        THE lockfile-preferred rule (ADR-0021). Reading both would report the
        same dependency twice with two different versions, and the reader would
        have no way to tell which one is installed.
        """
        chosen: list[tuple[str, str]] = []
        for ecosystem, ordered in PRECEDENCE.items():
            for filename in ordered:
                if (directory / filename).is_file():
                    chosen.append((ecosystem, filename))
                    break
        return chosen

    def _parse(self, path: Path, filename: str) -> list[Dependency] | None:
        """Parse one manifest, or log why it was skipped.

        A malformed manifest degrades the scan; it never ends it (ADR-0003).
        The file is somebody else's data and may be truncated, half-written or
        hostile.
        """
        _ecosystem, parser = PARSERS[filename]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log.warning(
                "manifest_unreadable: %s (%s)",
                path,
                exc,
                extra={"event": "manifest_unreadable", "path": str(path)},
            )
            return None
        try:
            return parser(text)
        except Exception as exc:
            _log.warning(
                "manifest_unparseable: %s (%s: %s)",
                path,
                type(exc).__name__,
                exc,
                extra={
                    "event": "manifest_unparseable",
                    "path": str(path),
                    "error_type": type(exc).__name__,
                },
            )
            return None

    # -- construction ----------------------------------------------------

    def _findings(
        self,
        dependencies: list[Dependency],
        path: Path,
        ecosystem: str,
        pack: dict[str, LibraryFact],
    ) -> Iterator[Finding]:
        # Sorted by name so two runs order identically whatever the parser did.
        for dependency in sorted(dependencies, key=lambda d: (d.name.lower(), d.line)):
            fact = pack.get(dependency.name.lower())
            if fact is None:
                # NOT a crypto library. No finding at all -- an inventory that
                # lists `lodash` is an inventory nobody will read.
                continue
            yield self._finding(dependency, path, ecosystem, fact)

    def _finding(
        self,
        dependency: Dependency,
        path: Path,
        ecosystem: str,
        fact: LibraryFact,
    ) -> Finding:
        params: dict[str, Any] = {
            "ecosystem": ecosystem,
            "package": dependency.name,
            "version": dependency.version,
            "manifest": path.name,
        }

        if dependency.is_range:
            # Recorded AS a range, and said out loud. A capability verdict on
            # an interval is a verdict on a version nobody has installed.
            params["version_is_range"] = True
            params["version_note"] = (
                f"the manifest declares the range {dependency.version!r} and no "
                f"lockfile resolves it, so the installed version is not known "
                f"from this repository. Capability and end-of-support are left "
                f"unanswered rather than assumed at either end of the range."
            )
        else:
            capable = is_pqc_capable(fact, dependency.version)
            if capable is not None:
                params["pqc_capable"] = capable
            if fact.eol is not None:
                params["eol"] = fact.eol

        snippet = f"{dependency.name} {dependency.version}"
        return Finding(
            scanner_id=self.id,
            view=_VIEW,
            asset_type="library",
            primitive="unknown",
            # The canonical name from the pack, so the same library found
            # through two ecosystems is still one name in the CBOM.
            algorithm=fact.name,
            params=params,
            usage="unknown",
            # A dependency IS changeable without a code edit: it is a line in a
            # manifest. Feeds the migration-effort estimate in ADR-0008.
            configurable=True,
            evidence=Evidence(
                occurrences=[
                    Occurrence(
                        view=_VIEW,
                        locator=f"{path}:{dependency.line}",
                        detail=f"{ecosystem} {path.name}",
                        snippet=snippet,
                    )
                ]
            ),
            confidence=RANGE_CONFIDENCE if dependency.is_range else 1.0,
            raw={
                "package": dependency.name,
                "ecosystem": ecosystem,
                "provides": list(fact.provides),
                "knowledge_source": fact.source,
            },
        )
