"""The fix-template contract, and the helpers every template needs.

A template is deliberately small and deliberately dumb. It knows one edit to
one file format and nothing about whether that edit is safe -- safety is the
engine's job, and it is decided by re-scanning, not by asking the template.
That split is what lets a wrong template be caught rather than trusted.

The contract:

``id``
    Stable identifier, written onto the CBOM as ``ecdat:fix:template`` so a
    diff traces back to the rule that produced it.
``scanner_to_reverify``
    The id of a **registered** scanner that can see this kind of finding. A
    template naming a scanner that does not exist cannot be verified by
    re-scan, and therefore is not shipped -- that rule is what keeps
    Dockerfile and dependency-manifest fixes out of the current set.
``source``
    The citation for the cryptographic claim the fix makes. CLAUDE.md forbids
    uncited crypto facts in a knowledge pack; a fix that rewrites somebody's
    TLS configuration is held to the same standard.
``matches(finding)``
    Cheap, pure, and side-effect-free: does this template speak to this
    finding at all? Reads the finding only -- never the filesystem.
``preconditions(finding, target)``
    May read the target (read-only) and decides whether the edit is
    *appropriate*. This is where a template declines rather than guesses.
``make_diff(finding, target)``
    A unified diff, relative to the target root. Never writes anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from core.identity import normalise_locator
from core.scanner import Target
from core.schema import Finding

__all__ = [
    "FixTemplate",
    "Precondition",
    "Site",
    "check_site",
    "read_site",
    "rewrite_assignment",
    "rewrite_directive",
    "site_of",
]


@dataclass(frozen=True, slots=True)
class Precondition:
    """Whether a template may proceed, and -- when not -- why not.

    The reason is not decoration. It is what the CLI prints and what lands in
    ``ecdat:fix:reason``, and for the usage-sensitive templates it is the whole
    output: "MD5 here is hashing a password, so a faster digest is the wrong
    fix" is more useful than any patch.
    """

    ok: bool
    reason: str

    @classmethod
    def met(cls) -> Precondition:
        return cls(ok=True, reason="")

    @classmethod
    def refused(cls, reason: str) -> Precondition:
        return cls(ok=False, reason=reason)


@dataclass(frozen=True, slots=True)
class Site:
    """Where in the target a finding was seen: a path and a 1-based line."""

    relative_path: str
    line: int


@runtime_checkable
class FixTemplate(Protocol):
    """Structural contract for a fix template. See the module docstring."""

    id: str
    scanner_to_reverify: str
    source: str

    def matches(self, finding: Finding) -> bool: ...

    def preconditions(self, finding: Finding, target: Target) -> Precondition: ...

    def make_diff(self, finding: Finding, target: Target) -> str: ...


# ---------------------------------------------------------------------------
# Locating the edit
# ---------------------------------------------------------------------------


def site_of(finding: Finding, target: Target) -> Site | None:
    """The file and line a finding's first occurrence points at.

    The path is made relative to the target root by the same function the
    normaliser uses for identity, so a site computed here and a bom-ref
    computed there agree about what "the same file" means -- and so a diff
    generated against a real checkout applies unchanged to a sandbox copy.
    """
    occurrence = finding.evidence.occurrences[0]
    _, separator, tail = occurrence.locator.rpartition(":")
    if not separator or not tail.isdigit():
        return None
    relative = normalise_locator(occurrence.view, occurrence.locator, target)
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        return None
    return Site(relative_path=relative, line=int(tail))


def read_site(target: Target, site: Site) -> str | None:
    """The full text of the file a site names, or ``None`` if unreadable."""
    path = Path(target.ref) / site.relative_path
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def check_site(
    finding: Finding, target: Target, *, expect: str
) -> tuple[Precondition, Site | None, str | None]:
    """The checks every file-editing template repeats.

    Returns the verdict alongside the site and file text, so a template that
    passes does not have to re-open anything.

    ``expect`` is a token the recorded line must still contain. A scan and a
    fix are separate invocations, and a config that changed in between must
    produce a refusal rather than an edit aimed at a line number that has since
    moved.
    """
    if not Path(target.ref).is_dir():
        return (
            Precondition.refused(
                f"the target {target.ref!r} is not a directory on this host, so "
                f"there is nothing to patch"
            ),
            None,
            None,
        )

    site = site_of(finding, target)
    if site is None:
        return (
            Precondition.refused(
                "the finding's evidence does not name a file and line inside the "
                "target, so no edit can be located"
            ),
            None,
            None,
        )

    text = read_site(target, site)
    if text is None:
        return (
            Precondition.refused(
                f"{site.relative_path} could not be read as UTF-8 text"
            ),
            site,
            None,
        )
    if "\r\n" in text:
        # Rewriting line endings would show up as a whole-file diff, which
        # buries the one line that matters.
        return (
            Precondition.refused(
                f"{site.relative_path} uses CRLF line endings, which this "
                f"patcher does not rewrite"
            ),
            site,
            text,
        )

    lines = text.splitlines()
    if not 1 <= site.line <= len(lines):
        return (
            Precondition.refused(
                f"{site.relative_path} has {len(lines)} lines but the finding "
                f"cites line {site.line}; the file has changed since the scan"
            ),
            site,
            text,
        )
    if expect not in lines[site.line - 1]:
        return (
            Precondition.refused(
                f"{site.relative_path}:{site.line} no longer contains {expect!r}; "
                f"the file has changed since the scan"
            ),
            site,
            text,
        )
    return Precondition.met(), site, text


# ---------------------------------------------------------------------------
# Editing a line without disturbing its neighbours
# ---------------------------------------------------------------------------

#: ``    ssl_protocols       TLSv1;`` -> indent, name, gap, value, terminator.
_DIRECTIVE = re.compile(r"^(\s*)([A-Za-z_][\w.]*)(\s+)([^;]*?)(\s*;.*)$")

#: ``MinProtocol = TLSv1`` -> indent, name, separator, value.
_ASSIGNMENT = re.compile(r"^(\s*)([A-Za-z_][\w.]*)(\s*=\s*)(.*)$")


def rewrite_directive(line: str, value: str) -> str | None:
    """Replace an nginx directive's value, keeping its column alignment.

    Operators align nginx directives by hand and a fix that re-flows the block
    turns a one-line review into a whole-block review.
    """
    match = _DIRECTIVE.match(line)
    if match is None:
        return None
    indent, name, gap, _old, terminator = match.groups()
    return f"{indent}{name}{gap}{value}{terminator}"


def rewrite_assignment(line: str, value: str) -> str | None:
    """Replace an ``ini``-style ``Key = value``, keeping its spacing."""
    match = _ASSIGNMENT.match(line)
    if match is None:
        return None
    indent, name, separator, _old = match.groups()
    return f"{indent}{name}{separator}{value}"
