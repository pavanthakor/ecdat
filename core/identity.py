"""Content-addressed identity for findings (resolves PUNCHLIST #1).

Two scanners looking at the same cryptographic artefact in the same place must
agree on what to call it, or the CBOM grows a component per detector and drift
detection becomes noise. This module derives that shared name: a hash over the
fields that say *what* the artefact is and *where* it lives, and over nothing
else.

Identifying (in the hash):
    asset_type, primitive, algorithm, params, usage, and the artefact locus.

Deliberately NOT identifying:
    scanner_id, view, confidence, configurable, raw, snippets, and the
    positional part of a locator -- line numbers, byte offsets and pids. Those
    describe the sighting, not the artefact.

Leaving ``view`` out is what lets the same artefact seen in source, in the
image and at runtime collapse into one component carrying three occurrences.
Keeping the *path* in is what stops unrelated artefacts collapsing with it --
the correlator still needs distinct places to compare.

The resulting digest is used verbatim as the CycloneDX ``bom-ref``.
"""

from __future__ import annotations

import json
from hashlib import blake2b

from core.scanner import Target
from core.schema import Finding, View

__all__ = ["artefact_locus", "finding_identity", "normalise_locator"]

#: ASCII unit separator: cannot occur in a path, algorithm name or param value,
#: so joining with it cannot make two different loci collide.
_SEP = "\x1f"

#: 16 bytes -> 32 hex characters. Long enough that a collision across an
#: estate-sized scan is not a practical concern, short enough to read in a
#: bom-ref.
_DIGEST_BYTES = 16

_PATH_TARGETS = ("repo", "directory")


def _drop_position(view: View, locator: str) -> str:
    """Strip the part of a locator that says *where in* the artefact, not *which*.

    ``declared`` / ``shipped``: a trailing ``:<n>`` is a line number or byte
    offset. ``observed``: a trailing ``:pid<n>`` is a process, but a trailing
    ``:<n>`` is a port and genuinely identifies the service, so it stays.

    Splitting on the view rather than guessing from the string shape is what
    keeps ``services/auth/jwt.py:42`` and ``api.internal:443`` from being
    treated alike.
    """
    head, separator, tail = locator.rpartition(":")
    if not separator:
        return locator
    if view == "observed":
        if tail.startswith("pid") and tail[3:].isdigit():
            return head
        return locator
    return head if tail.isdigit() else locator


def _relative_to_target(path: str, target: Target) -> str:
    """Make paths comparable regardless of where the target was checked out."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if target.kind in _PATH_TARGETS:
        root = target.ref.replace("\\", "/").rstrip("/")
        if root and path.startswith(f"{root}/"):
            path = path[len(root) + 1 :]
    return path


def normalise_locator(view: View, locator: str, target: Target) -> str:
    """The artefact-level address of one occurrence."""
    return _relative_to_target(_drop_position(view, locator), target)


def artefact_locus(finding: Finding, target: Target) -> str:
    """Where this artefact lives: the scope, plus every place it was seen.

    The scope is ``target.system`` when the caller supplied one, so the same
    service scanned from two checkouts is one artefact; otherwise it falls back
    to ``target.ref``.
    """
    scope = target.system or target.ref
    places = sorted(
        {
            normalise_locator(o.view, o.locator, target)
            for o in finding.evidence.occurrences
        }
    )
    return _SEP.join([scope, *places])


def finding_identity(finding: Finding, target: Target) -> str:
    """A stable content hash of what this finding claims to have found."""
    canonical = json.dumps(
        {
            "algorithm": finding.algorithm,
            "asset_type": finding.asset_type,
            "locus": artefact_locus(finding, target),
            "params": finding.params,
            "primitive": finding.primitive,
            "usage": finding.usage,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return blake2b(canonical.encode("utf-8"), digest_size=_DIGEST_BYTES).hexdigest()
