"""Bump a crypto dependency to a version the knowledge pack has CONFIRMED.

ADR-0015 kept this template out of the shipped set because nothing could
re-verify it. Scanner B (ADR-0021) reads dependency manifests, so the fix now
has a producer that can re-read its own edit -- and shipping it brings two
refusals with it.

**The honesty gate (ADR-0017).** A bump is proposed only to a
``pqc_capable_from`` carrying ``pqc_capable_verified: true``. An unverified
floor is a number somebody typed, not a fact confirmed against upstream release
material. ADR-0017 already refuses to *score* on one; telling an operator to
change a dependency their service is built on is a stronger claim than a score,
so the same rule binds harder here. Today that means dep-bump declines every
library in the shipped pack -- all fifteen dependency entries are provisional.
That is the mechanism working, and the entry that gets researched first is the
entry that starts producing fixes.

**No stale-hash lockfile edits.** ``package-lock.json``, ``poetry.lock``,
``Pipfile.lock``, ``yarn.lock`` and ``go.sum`` carry integrity hashes over the
exact version they pin. Rewriting the version and leaving the hash produces a
lockfile that fails on the next install: a broken tree, delivered as
remediation. This template edits the human-authored manifest --
``requirements.txt``, ``package.json``, ``go.mod`` -- and says to regenerate the
lock. Where a resolved lockfile is all there is, it declines.

That second rule has an honest cost, and the engine reports it rather than
hiding it. Scanner B is lockfile-preferred: when a lock exists it is the file
that gets read, so bumping the manifest beside it cannot make the finding
disappear on re-scan. The engine returns ``verified=False`` with "the finding is
still present", which is exactly true -- only regenerating the lock would move
it, and ECDAT does not run package managers.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from core.scanner import Target
from core.schema import Finding
from correlate.fixit.patch import make_unified_diff
from correlate.fixit.template import Precondition, read_site, site_of
from scanners.libraries import (
    LibraryFact,
    LibraryPackMissingError,
    index_for,
    version_tuple,
)

__all__ = ["DepBump", "lower_bound"]

#: The env var and default every ECDAT entry point resolves the knowledge dir
#: from. Read here rather than imported from ``core.orchestrator``, which
#: imports this package -- a module-scope import back would be a cycle as well
#: as a layering inversion. The name is duplicated, not the resolution rule.
ENV_KNOWLEDGE_DIR = "ECDAT_KNOWLEDGE_DIR"
DEFAULT_KNOWLEDGE_DIR = "knowledge"

#: The human-authored manifest per ecosystem: the file a person edits and a
#: package manager reads. One per ecosystem, because a bump has to land in the
#: file that is the source of truth for the version.
EDITABLE_MANIFEST = {
    "pypi": "requirements.txt",
    "npm": "package.json",
    "go": "go.mod",
}

#: Files whose versions come with integrity hashes. NEVER edited by hand.
RESOLVED_LOCKFILES = frozenset(
    {
        "poetry.lock",
        "Pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "go.sum",
    }
)

#: How an operator regenerates the lock after the manifest moves. ECDAT never
#: runs these -- CLAUDE.md's read-only rule -- so the diff names them instead.
REGENERATE = {
    "pypi": "pip-compile",
    "npm": "npm install",
    "go": "go mod tidy",
}

#: Read by Scanner B, but not bumpable this slice -- ``pyproject.toml`` needs a
#: TOML-preserving edit and is deferred (ADR-0022, PUNCHLIST).
UNSUPPORTED_MANIFESTS = frozenset({"pyproject.toml"})

#: PEP 503 name normalisation, so ``PyJWT``, ``pyjwt`` and ``py_jwt`` are one
#: package when matching a requirements line.
_PEP503 = re.compile(r"[-_.]+")

#: ``cryptography[ssh] >= 41.0 , <43`` -> name, extras, specifier.
_REQUIREMENT_LINE = re.compile(
    r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9._-]+)(?P<extras>\[[^\]]*\])?"
    r"(?P<gap>\s*)(?P<spec>.*?)(?P<trail>\s*)$"
)

#: ``    "node-forge": "^1.3.1",`` -> the quoted spec, with its operator prefix.
_JSON_DEP_VALUE = re.compile(
    r'(?P<open>"\s*:\s*")(?P<operator>[\^~><=\s]*)(?P<version>[^"]*)(?P<close>")'
)

#: ``    golang.org/x/crypto v0.31.0 // indirect``
_GO_REQUIRE_LINE = re.compile(
    r"^(?P<lead>\s*)(?P<module>[^\s]+)(?P<gap>\s+)v(?P<version>[^\s/]+)(?P<trail>.*)$"
)

#: The lower bound of a specifier set, and the text either side of it.
_LOWER_BOUND = re.compile(
    r"(?P<operator>>=|>|==|~=)\s*(?P<version>[0-9][0-9A-Za-z.*+!-]*)"
)


def normalised(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def lower_bound(specifier: str) -> str | None:
    """The lowest version a specifier set admits, or ``None`` if it names none.

    ``">=41.0,<43"`` -> ``"41.0"``; ``"^1.3.1"`` -> ``"1.3.1"``; ``"*"`` ->
    ``None``. The lower bound is what decides whether a range PERMITS an
    install below the post-quantum floor, which is the only question a range
    can honestly answer.
    """
    match = _LOWER_BOUND.search(specifier)
    if match is not None:
        return match.group("version")
    stripped = specifier.lstrip("^~v= ").strip()
    if stripped and stripped[0].isdigit():
        return stripped.split(",", 1)[0].strip()
    return None


def knowledge_dir() -> Path:
    return Path(os.environ.get(ENV_KNOWLEDGE_DIR, DEFAULT_KNOWLEDGE_DIR))


class DepBump:
    """Raise a declared crypto dependency to a verified PQC-capable version."""

    id: str = "dep-bump"
    scanner_to_reverify: str = "deps"
    source: str = (
        "knowledge/libraries.yaml -- each entry's `pqc_capable_from` with its "
        "`pqc_capable_source` citation. This template makes no cryptographic "
        "claim of its own: it proposes the version floor the pack records, and "
        "only when that floor carries `pqc_capable_verified: true` (ADR-0017). "
        "An unverified floor produces a refusal, not a bump."
    )

    # -- selection -------------------------------------------------------

    def matches(self, finding: Finding) -> bool:
        """Declared third-party libraries only -- Scanner B's output.

        Pure and finding-only by contract. Whether there is a verified floor to
        bump TO is a pack question, and pack questions belong in
        :meth:`preconditions` where a refusal can carry its reason.
        """
        return (
            finding.scanner_id == "deps"
            and finding.asset_type == "library"
            and bool(finding.params.get("package"))
            and bool(finding.params.get("ecosystem"))
        )

    # -- the two gates ---------------------------------------------------

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        fact, refusal = self._fact(finding)
        if fact is None:
            return refusal

        floor = fact.pqc_capable_from
        if floor is None:
            return Precondition.refused(
                f"not applicable: the knowledge pack records no post-quantum "
                f"floor for {fact.name}, so there is no target version to bump "
                f"to. ECDAT will not invent one."
            )
        if not fact.pqc_capable_verified:
            return Precondition.refused(
                f"not applicable: {fact.name}'s post-quantum floor "
                f"({floor}) is provisional -- target version unverified "
                f"against source, so ECDAT cannot propose a bump to an "
                f"unconfirmed fact (ADR-0017). Confirm the floor against "
                f"upstream release material and set "
                f"`pqc_capable_verified: true` in knowledge/libraries.yaml, "
                f"and this fix becomes available."
            )

        current = self._current_bound(finding)
        if current is None:
            return Precondition.refused(
                f"not applicable: {fact.name}'s declared version "
                f"{finding.params.get('version')!r} names no lower bound, so "
                f"there is nothing to compare against the floor {floor}"
            )
        if version_tuple(current) >= version_tuple(floor):
            span = (
                "range already starts at" if self._is_range(finding) else "is already"
            )
            return Precondition.refused(
                f"not applicable: {fact.name} {span} {current}, at or above the "
                f"verified post-quantum floor {floor}. There is nothing to fix."
            )

        return self._manifest_precondition(finding, target, fact)

    def _manifest_precondition(
        self, finding: Finding, target: Target, fact: LibraryFact
    ) -> Precondition:
        """Where the edit would land -- and the stale-hash refusal."""
        manifest = str(finding.params.get("manifest", ""))
        if manifest in UNSUPPORTED_MANIFESTS:
            return Precondition.refused(
                f"not applicable: {fact.name} is declared in {manifest}, which "
                f"this template does not edit yet. requirements.txt, "
                f"package.json and go.mod are supported (ADR-0022)."
            )

        editable = self._editable_path(finding, target)
        if editable is None:
            wanted = EDITABLE_MANIFEST.get(str(finding.params.get("ecosystem")), "")
            return Precondition.refused(
                f"not applicable: {fact.name} is pinned in {manifest}, a "
                f"resolved lockfile whose entry carries an integrity hash over "
                f"the version it names. Editing the version and leaving the "
                f"hash ships a broken lockfile, so ECDAT will not do it, and "
                f"there is no {wanted} beside it to bump instead. Bump the "
                f"manifest and regenerate {manifest}."
            )

        relative, text = editable
        if "\r\n" in text:
            return Precondition.refused(
                f"{relative} uses CRLF line endings, which this patcher does "
                f"not rewrite"
            )
        if self._rewrite(finding, fact, text) is None:
            return Precondition.refused(
                f"not applicable: {relative} does not declare "
                f"{finding.params.get('package')!r} in a form this template "
                f"can edit, so the bump cannot be located"
            )
        return Precondition.met()

    # -- the edit --------------------------------------------------------

    def make_diff(self, finding: Finding, target: Target) -> str:
        fact, _ = self._fact(finding)
        editable = self._editable_path(finding, target)
        if fact is None or editable is None:  # pragma: no cover - gated above
            return ""
        relative, text = editable
        new = self._rewrite(finding, fact, text)
        if new is None:  # pragma: no cover - gated above
            return ""
        body = make_unified_diff(relative, text, new)
        if not body.strip():
            return ""
        return _header(finding, fact, relative) + body

    # -- pack ------------------------------------------------------------

    def _fact(self, finding: Finding) -> tuple[LibraryFact | None, Precondition]:
        ecosystem = str(finding.params.get("ecosystem", ""))
        package = str(finding.params.get("package", ""))
        try:
            index = index_for(knowledge_dir(), ecosystem)
        except LibraryPackMissingError as exc:
            return None, Precondition.refused(f"not applicable: {exc}")
        fact = index.get(package.lower())
        if fact is None:
            return None, Precondition.refused(
                f"not applicable: {package!r} is not in the {ecosystem} section "
                f"of knowledge/libraries.yaml, so no target version is known. "
                f"The scan and the fix may be reading different packs."
            )
        return fact, Precondition.met()

    # -- version ---------------------------------------------------------

    @staticmethod
    def _is_range(finding: Finding) -> bool:
        return bool(finding.params.get("version_is_range", False))

    def _current_bound(self, finding: Finding) -> str | None:
        """The version to compare against the floor.

        A pin is itself; a range is its lower bound, because a range whose
        floor is below the PQC floor PERMITS a non-capable install however the
        resolver happens to land today.
        """
        version = str(finding.params.get("version", ""))
        if not self._is_range(finding):
            return version or None
        return lower_bound(version)

    # -- locating the manifest -------------------------------------------

    def _editable_path(
        self, finding: Finding, target: Target
    ) -> tuple[str, str] | None:
        """``(path relative to the target, its text)`` for the file to edit.

        The finding's own file when it is already the manifest; otherwise its
        sibling manifest in the same directory. ``None`` when neither exists --
        which is the resolved-lockfile refusal.
        """
        site = site_of(finding, target)
        if site is None:
            return None

        manifest = str(finding.params.get("manifest", ""))
        if manifest in UNSUPPORTED_MANIFESTS:
            return None

        if manifest not in RESOLVED_LOCKFILES:
            text = read_site(target, site)
            return None if text is None else (site.relative_path, text)

        wanted = EDITABLE_MANIFEST.get(str(finding.params.get("ecosystem")))
        if wanted is None:
            return None
        directory = Path(site.relative_path).parent
        relative = (directory / wanted).as_posix()
        try:
            text = (Path(target.ref) / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        return relative, text

    # -- rewriting -------------------------------------------------------

    def _rewrite(self, finding: Finding, fact: LibraryFact, text: str) -> str | None:
        """The whole new file text, or ``None`` if the declaration is not found."""
        target_version = str(fact.pqc_capable_from)
        package = str(finding.params.get("package", ""))
        ecosystem = str(finding.params.get("ecosystem", ""))
        if ecosystem == "pypi":
            return _rewrite_requirements(text, package, target_version, fact)
        if ecosystem == "npm":
            return _rewrite_package_json(text, package, target_version)
        if ecosystem == "go":
            return _rewrite_go_mod(text, package, target_version)
        return None


# ---------------------------------------------------------------------------
# Per-format edits. Each touches the DECLARATION and nothing else.
# ---------------------------------------------------------------------------


def _header(finding: Finding, fact: LibraryFact, relative: str) -> str:
    """Prose above the first ``---``, carried by EVERY dep-bump diff.

    Two things have to reach whoever applies the patch, and neither fits inside
    a hunk: the citation for the target version, and the fact that the bump is
    only half the change. ``package.json`` cannot hold a comment at all, so an
    in-file note would say this on some formats and not others.

    ``git apply`` and :func:`correlate.fixit.patch.apply_unified_diff` both
    ignore everything before the first file header, so the note travels with the
    patch without being part of it.
    """
    manifest = str(finding.params.get("manifest", ""))
    current = str(finding.params.get("version", ""))
    command = REGENERATE.get(
        str(finding.params.get("ecosystem", "")), "your package manager"
    )
    lock = (
        f"{manifest} still pins the old version -- run `{command}` to "
        f"regenerate it, or the bump has no effect."
        if manifest in RESOLVED_LOCKFILES
        else f"Regenerate any lockfile with `{command}` after applying; "
        f"ECDAT does not run package managers."
    )
    citation = (fact.pqc_capable_source or fact.source or "").strip().replace("\n", " ")
    return (
        f"# ecdat dep-bump: {fact.name} {current} -> {fact.pqc_capable_from} "
        f"in {relative}\n"
        f"# {lock}\n"
        f"# verified floor, per knowledge/libraries.yaml: {citation}\n"
    )


def _note(package: str, floor: str, command: str) -> str:
    """The comment a range bump carries.

    A range bump moves the floor and leaves the ceiling alone, so the range may
    still exclude the target -- and the lockfile, if there is one, still pins
    whatever it pinned. Both are said in the diff rather than in a report the
    reviewer of the patch will not be reading.
    """
    return (
        f"# ecdat: raised the lower bound to {floor}, the verified "
        f"post-quantum floor for {package}. Check the upper bound still admits "
        f"it, then `{command}`."
    )


def _rewrite_requirements(
    text: str, package: str, floor: str, fact: LibraryFact
) -> str | None:
    lines = text.splitlines()
    wanted = normalised(package)
    for index, raw in enumerate(lines):
        body = raw.split("#", 1)[0]
        if not body.strip() or body.lstrip().startswith("-"):
            continue
        match = _REQUIREMENT_LINE.match(body)
        if match is None or normalised(match.group("name")) != wanted:
            continue

        lead, name, extras, gap, spec, trail = (
            match.group("lead"),
            match.group("name"),
            match.group("extras") or "",
            match.group("gap"),
            match.group("spec").strip(),
            match.group("trail"),
        )
        comment = raw[len(body) :]

        if spec.startswith("==") and "," not in spec:
            new_spec = f"=={floor}"
            replacement = f"{lead}{name}{extras}{gap}{new_spec}{trail}{comment}"
            lines[index] = replacement
            break

        bound = lower_bound(spec)
        if bound is None:
            return None
        # Only the LOWER bound moves. Rewriting the ceiling would be ECDAT
        # deciding which future major version is acceptable, which it cannot
        # know.
        head, _, tail = spec.partition(bound)
        new_spec = f"{head}{floor}{tail}"
        lines[index] = f"{lead}{name}{extras}{gap}{new_spec}{trail}{comment}"
        lines.insert(index, f"{lead}{_note(fact.name, floor, REGENERATE['pypi'])}")
        break
    else:
        return None
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _rewrite_package_json(text: str, package: str, floor: str) -> str | None:
    lines = text.splitlines()
    needle = f'"{package}"'
    for index, raw in enumerate(lines):
        if not raw.lstrip().startswith(needle):
            continue
        # Keep the operator (`^`, `~`, or nothing): it is the author's stated
        # tolerance for upgrades and is not this template's to change.
        replaced = _JSON_DEP_VALUE.sub(
            lambda m: (
                f"{m.group('open')}{m.group('operator')}{floor}{m.group('close')}"
            ),
            raw,
            count=1,
        )
        if replaced == raw:
            return None
        lines[index] = replaced
        break
    else:
        return None
    _validate_json(lines, text)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _validate_json(lines: list[str], original: str) -> None:
    """A rewritten manifest that is not JSON is a bug, not a patch."""
    candidate = "\n".join(lines) + ("\n" if original.endswith("\n") else "")
    json.loads(candidate)


def _rewrite_go_mod(text: str, module: str, floor: str) -> str | None:
    lines = text.splitlines()
    for index, raw in enumerate(lines):
        body = raw.split("//", 1)[0]
        candidate = body.strip()
        if candidate.startswith("require "):
            candidate = candidate[len("require ") :].strip()
        match = _GO_REQUIRE_LINE.match(body)
        if match is None or match.group("module").strip() in ("require", ""):
            match = _GO_REQUIRE_LINE.match(candidate)
            if match is None:
                continue
            if match.group("module") != module:
                continue
            prefix = body[: len(body) - len(body.lstrip())] + "require "
            lines[index] = (
                f"{prefix}{module}{match.group('gap')}v{floor}"
                f"{match.group('trail')}{raw[len(body) :]}"
            )
            break
        if match.group("module") != module:
            continue
        lines[index] = (
            f"{match.group('lead')}{module}{match.group('gap')}v{floor}"
            f"{match.group('trail')}{raw[len(body) :]}"
        )
        break
    else:
        return None
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
