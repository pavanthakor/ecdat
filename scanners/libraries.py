"""One reader for ``knowledge/libraries.yaml``, shared by two scanners.

The container scanner asks "is this dpkg package a crypto library?"; the
dependency scanner asks "is this PyPI/npm/Go module a crypto library?". Same
pack, same capability arithmetic, two very different name spaces — and two
separate readers of one pack is how a version comparison drifts until the same
OpenSSL is PQC-capable in one view and not in the other.

**Namespaces do not mix.** An entry carries an ``ecosystem``: ``distro`` for a
system package (what an image ships), or ``pypi``/``npm``/``go`` for a declared
dependency. A lookup is always scoped to one, so a PyPI package called
``openssl`` can never be mistaken for the system OpenSSL, and a dpkg
``python3-cryptography`` can never be mistaken for the PyPI wheel. They are
genuinely different artefacts with different version numbering.

Capability is gated on ``pqc_capable_verified`` (ADR-0017): an unconfirmed
floor answers ``None`` — "the pack does not know" — rather than a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "DISTRO",
    "ECOSYSTEMS",
    "LIBRARY_PACK",
    "LibraryFact",
    "LibraryPackMissingError",
    "index_for",
    "is_pqc_capable",
    "load_library_pack",
    "upstream_version",
    "version_tuple",
]

#: Where the pack lives under ``ScanContext.knowledge_dir``.
LIBRARY_PACK = Path("libraries.yaml")

#: System packages -- what an image ships. The default for an entry that names
#: no ecosystem, so the pack's original distro entries keep working unchanged.
DISTRO = "distro"

#: Declared-dependency ecosystems this pack understands.
ECOSYSTEMS = (DISTRO, "pypi", "npm", "go")


class LibraryPackMissingError(RuntimeError):
    """``knowledge/libraries.yaml`` is not where the knowledge directory says."""


@dataclass(frozen=True, slots=True)
class LibraryFact:
    """One entry from the pack."""

    name: str
    ecosystem: str
    provides: tuple[str, ...]
    pqc_capable_from: str | None
    eol: str | None
    source: str
    #: Whether ``pqc_capable_from`` was confirmed against upstream release
    #: material. FALSE by default, and an unverified floor produces no
    #: capability verdict at all (ADR-0017) — so a version filled in without a
    #: source cannot quietly start driving drift or a migration plan.
    pqc_capable_verified: bool = False
    pqc_capable_source: str | None = None
    weak_defaults: tuple[str, ...] = ()


def load_library_pack(knowledge_dir: Path) -> list[LibraryFact]:
    """Every entry in the pack, with its package names attached by the caller.

    Fails loudly when the pack is missing. A scan that silently reports no
    cryptographic libraries because its knowledge pack was absent is
    indistinguishable from a clean project, and someone would believe it.
    """
    return [_fact(entry) for entry in _raw(knowledge_dir)]


def index_for(knowledge_dir: Path, ecosystem: str) -> dict[str, LibraryFact]:
    """``package name -> fact`` for ONE ecosystem, lower-cased for matching.

    Scoped deliberately: matching across namespaces would let a PyPI package
    inherit a system library's capability floor, which is a different piece of
    software with different version numbers.
    """
    index: dict[str, LibraryFact] = {}
    for entry in _raw(knowledge_dir):
        if str(entry.get("ecosystem", DISTRO)) != ecosystem:
            continue
        fact = _fact(entry)
        for package in entry.get("packages") or ():
            index[str(package).lower()] = fact
    return index


def _raw(knowledge_dir: Path) -> list[dict[str, Any]]:
    path = knowledge_dir / LIBRARY_PACK
    if not path.is_file():
        raise LibraryPackMissingError(
            f"the library knowledge pack is missing: {path} does not exist. "
            "Set ECDAT_KNOWLEDGE_DIR or restore knowledge/libraries.yaml."
        )
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    libraries: list[dict[str, Any]] = document.get("libraries") or []
    return libraries


def _fact(entry: dict[str, Any]) -> LibraryFact:
    return LibraryFact(
        name=str(entry["name"]),
        ecosystem=str(entry.get("ecosystem", DISTRO)),
        provides=tuple(str(p) for p in (entry.get("provides") or ())),
        pqc_capable_from=(
            str(entry["pqc_capable_from"])
            if entry.get("pqc_capable_from") is not None
            else None
        ),
        eol=str(entry["eol"]) if entry.get("eol") is not None else None,
        source=str(entry.get("source", "")),
        pqc_capable_verified=bool(entry.get("pqc_capable_verified", False)),
        pqc_capable_source=(
            str(entry["pqc_capable_source"])
            if entry.get("pqc_capable_source") is not None
            else None
        ),
        weak_defaults=tuple(str(w) for w in (entry.get("weak_defaults") or ())),
    )


def upstream_version(raw: str) -> str:
    """Strip packaging from a version so two of them are comparable.

    ``1:3.0.2-0ubuntu1.10`` -> ``3.0.2`` (dpkg epoch and revision);
    ``3.5.7-r0`` -> ``3.5.7`` (apk); ``v0.31.0`` -> ``0.31.0`` (Go);
    ``42.0.5rc1`` is left alone here and truncated by :func:`version_tuple`.

    The upstream version is the one a capability floor is expressed in, so
    comparing without stripping would put ``3.5.7-r0`` below ``3.5.0``.
    """
    version = raw.strip()
    if version.startswith(("v", "V")) and version[1:2].isdigit():
        version = version[1:]
    _, _, after_epoch = version.rpartition(":")
    version = after_epoch or version
    version = version.split("-", 1)[0]
    return version.split("+", 1)[0]


def version_tuple(version: str) -> tuple[int, ...]:
    """``"3.5.7"`` -> ``(3, 5, 7)``. A non-numeric tail stops the parse.

    So ``42.0.5rc1`` compares as ``(42, 0, 5)``: a release candidate is treated
    as its release rather than sorted arbitrarily, which is the conservative
    reading for a capability question.
    """
    parts: list[int] = []
    for chunk in upstream_version(version).split("."):
        digits = ""
        for character in chunk:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def is_pqc_capable(fact: LibraryFact, version: str) -> bool | None:
    """``None`` when the pack does not know -- never a guess.

    "Does not know" covers two cases, and the second is ADR-0017's point: no
    floor recorded at all, OR a floor nobody has confirmed against upstream
    release material. An unverified floor is data, not a fact, and a scan must
    not compare against it.
    """
    if fact.pqc_capable_from is None or not fact.pqc_capable_verified:
        return None
    return version_tuple(version) >= version_tuple(fact.pqc_capable_from)
