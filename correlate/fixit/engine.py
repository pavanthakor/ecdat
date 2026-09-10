"""The fix-it engine: propose a diff, then refuse to believe it (ADR-0015).

``propose_fix`` is the whole of Pillar 3's fix half, and it is built around one
refusal: **ECDAT does not trust its own templates.** A template's diff is not a
fix until the producing scanner has re-read a patched copy of the target and
agreed the problem is gone.

The loop, in order, because the order is the safety argument:

1. **Select** the one template that matches, or report that none does.
2. **Check preconditions** -- the file still says what the scan said, and the
   edit is appropriate for this usage. A refusal here carries the reason,
   which for the usage-sensitive templates *is* the useful output.
3. **Generate** a unified diff. Nothing is written to the target. Ever.
4. **Copy** the target into a fresh sandbox directory.
5. **Baseline-scan** the pristine copy, and confirm the finding reproduces
   there. If it does not, the finding is stale or came from another scanner,
   and no conclusion drawn from this sandbox would mean anything.
6. **Apply the diff** -- the diff, as a diff, not the template's in-memory
   idea of the result. A template whose patch does not say what it meant fails
   here.
7. **Re-scan** and require BOTH: the original finding is gone, and no NEW
   Critical finding arrived. Removing a finding is easy; removing it without
   making something worse is the actual claim.

Only then does the diff leave this module. **Nothing here ever applies a fix
to a real target** -- ECDAT produces a verified diff and a human applies it.

Two properties are load-bearing and are named functions rather than inline
code, so ``tests/test_fixit.py`` can disable each one and prove the unsafe
outcome appears: :func:`_sandbox_root` (the real target is never touched),
:func:`_critical_findings` (blast radius), and
:func:`_fix_removed_the_finding` (verification is by re-scan, not by
assertion).
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from core import registry
from core.identity import finding_identity, normalise_locator
from core.logs import get_logger
from core.normalise import normalise
from core.orchestrator import default_context
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from correlate.fixit.patch import PatchError, apply_unified_diff
from correlate.fixit.template import FixTemplate, site_of
from correlate.fixit.templates import DEFAULT_TEMPLATES
from policy.apply import DEFAULT_Z_YEARS, ScoreInputs, apply_policy
from policy.engine import Pack, default_packs

__all__ = ["FixResult", "propose_fix", "site_of"]

_log = get_logger("fixit")

#: Directories never copied into a sandbox. History and build caches are not
#: part of what a scanner reads, and copying them makes the loop slow enough
#: that someone will be tempted to skip it.
SANDBOX_IGNORE = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
)

#: Target kinds whose ``ref`` is a directory that can be copied and patched.
#: An image or a live host is not a text tree; a fix for one of those needs a
#: different verification story and does not exist yet.
PATCHABLE_KINDS = frozenset({"repo", "directory"})

#: The band that makes a fix worse than the problem it solves.
BLOCKING_BAND = "Critical"

#: A constant scope for fingerprinting only. ``artefact_locus`` folds
#: ``target.system or target.ref`` into a finding's identity, and the sandbox
#: has a different ``ref`` by construction -- so a fingerprint that used the
#: real scope would never match one computed in the sandbox. Pinning the scope
#: leaves identity resting on exactly what should decide it here: the artefact
#: and its path relative to the target root.
_FINGERPRINT_SCOPE = "ecdat-fixit"


@dataclass(frozen=True, slots=True)
class FixResult:
    """What ECDAT is willing to say about fixing one finding.

    ``verified`` is the only field a caller should act on. ``diff`` is present
    only when ``verified`` is True: an unverified patch shown next to an
    "apply" button is how an unproven change reaches production, so this type
    declines to carry one.
    """

    applicable: bool
    verified: bool
    template_id: str | None
    diff: str | None
    reason: str
    #: Every finding the fix introduced, scored, as ``"<band> <algorithm> at
    #: <path>"``. Reported even on success -- a verified fix that adds a
    #: control (SHA-256, a hybrid group) should show what it added.
    new_findings: tuple[str, ...] = ()
    #: The subset that reached :data:`BLOCKING_BAND`. Non-empty means rejected.
    new_criticals: tuple[str, ...] = ()
    #: The template's citation, carried through to ``ecdat:fix:source``.
    source: str = field(default="")


def _refused(reason: str, template: FixTemplate | None = None) -> FixResult:
    return FixResult(
        applicable=False,
        verified=False,
        template_id=None if template is None else template.id,
        diff=None,
        reason=reason,
        source="" if template is None else template.source,
    )


def _unverified(
    template: FixTemplate,
    reason: str,
    *,
    new_findings: tuple[str, ...] = (),
    new_criticals: tuple[str, ...] = (),
) -> FixResult:
    """Applicable -- the template was right to match -- but not proven."""
    return FixResult(
        applicable=True,
        verified=False,
        template_id=template.id,
        diff=None,
        reason=reason,
        new_findings=new_findings,
        new_criticals=new_criticals,
        source=template.source,
    )


# ---------------------------------------------------------------------------
# Identity across the sandbox boundary
# ---------------------------------------------------------------------------


def _fingerprint(finding: Finding, target: Target) -> str:
    """A sandbox-independent identity for one finding.

    ``target.ref`` must already be the root the finding's locators are under.
    """
    probe = replace(target, ref=str(target.ref), system=_FINGERPRINT_SCOPE)
    return finding_identity(finding, probe)


def _finding_survives(
    fingerprint: str, findings: Sequence[Finding], target: Target
) -> bool:
    """Whether ``fingerprint`` is still among ``findings``.

    Used for the BASELINE check -- does this finding reproduce on a pristine
    copy at all? Kept separate from :func:`_fix_removed_the_finding` because
    the two ask different questions of the same predicate, and collapsing them
    would mean one mutation could disable both.
    """
    return any(_fingerprint(f, target) == fingerprint for f in findings)


def _fix_removed_the_finding(
    fingerprint: str, after: Sequence[Finding], target: Target
) -> bool:
    """THE verification predicate: is the finding gone from the patched copy?

    This is the line between "a template says it fixed it" and "the scanner
    that found it can no longer find it". Disabling it is one of the mutations
    ``tests/test_fixit.py`` runs: with it forced True, a template that edits a
    comment and fixes nothing is accepted.
    """
    return not _finding_survives(fingerprint, after, target)


def _describe(finding: Finding, target: Target, band: str) -> str:
    locator = normalise_locator(
        finding.evidence.occurrences[0].view,
        finding.evidence.occurrences[0].locator,
        target,
    )
    return f"{band} {finding.algorithm} at {locator}"


def _arrivals(
    before: Sequence[Finding], after: Sequence[Finding], target: Target
) -> list[Finding]:
    """Findings present after the patch that were not there before it."""
    known = {_fingerprint(f, target) for f in before}
    return [f for f in after if _fingerprint(f, target) not in known]


def _score(
    findings: Sequence[Finding],
    target: Target,
    packs: Sequence[Pack],
    z_years: int,
    knowledge_dir: Path,
) -> dict[str, str]:
    """``bom-ref -> band`` for ``findings``, scored in the target's context.

    The same packs, sector, exposure and data class the scan used, because a
    band is meaningless without them -- RSA-2048 is Critical in an
    internet-facing BFSI system and Medium in an internal lab.
    """
    if not findings:
        return {}
    _, cbom_json = normalise(findings, target)
    scored = apply_policy(
        cbom_json,
        packs,
        inputs=ScoreInputs(
            data_class=target.data_class,
            sector=target.sector,
            exposure=target.exposure,
            z_years=z_years,
            knowledge_dir=knowledge_dir,
        ),
    )
    bands: dict[str, str] = {}
    for component in json.loads(scored).get("components", []):
        properties = {p["name"]: p["value"] for p in component.get("properties", [])}
        bands[str(component.get("bom-ref", ""))] = properties.get("ecdat:band", "")
    return bands


def _critical_findings(
    arrivals: Sequence[Finding],
    target: Target,
    packs: Sequence[Pack],
    z_years: int,
    knowledge_dir: Path,
) -> list[str]:
    """The blast-radius check: which new findings reach Critical.

    Disabling this is one of the mutations ``tests/test_fixit.py`` runs: with
    it neutered, a template that trades MD5 for RSA-2048 is accepted, because
    the original finding really did disappear.
    """
    bands = _score(arrivals, target, packs, z_years, knowledge_dir)
    return sorted(
        _describe(finding, target, BLOCKING_BAND)
        for finding in arrivals
        if bands.get(finding_identity(finding, target)) == BLOCKING_BAND
    )


def _all_arrival_descriptions(
    arrivals: Sequence[Finding],
    target: Target,
    packs: Sequence[Pack],
    z_years: int,
    knowledge_dir: Path,
) -> tuple[str, ...]:
    bands = _score(arrivals, target, packs, z_years, knowledge_dir)
    return tuple(
        sorted(
            _describe(
                finding,
                target,
                bands.get(finding_identity(finding, target), "Unscored"),
            )
            for finding in arrivals
        )
    )


# ---------------------------------------------------------------------------
# The sandbox
# ---------------------------------------------------------------------------


def _sandbox_root(real_root: Path, sandbox: Path) -> Path:
    """Copy the target tree into ``sandbox`` and return the copy's root.

    The single point at which the real target stops being involved. Disabling
    this is one of the mutations ``tests/test_fixit.py`` runs: with it
    returning the real root, the engine patches the live tree, and the
    read-only proof fails -- which is what makes that proof meaningful rather
    than incidental.
    """
    destination = sandbox / "target"
    shutil.copytree(
        real_root,
        destination,
        ignore=shutil.ignore_patterns(*SANDBOX_IGNORE),
        symlinks=True,
    )
    return destination


def _scanner_for(template: FixTemplate) -> Scanner | None:
    try:
        return registry.get_scanners([template.scanner_to_reverify])[0]
    except registry.UnknownScannerError:
        return None


# ---------------------------------------------------------------------------
# The entry point
# ---------------------------------------------------------------------------


def propose_fix(
    finding: Finding,
    target: Target,
    *,
    templates: Sequence[FixTemplate] | None = None,
    context: ScanContext | None = None,
    packs: Sequence[Pack] | None = None,
    z_years: int = DEFAULT_Z_YEARS,
) -> FixResult:
    """Propose a verified fix for one finding, or say why there isn't one.

    Pure with respect to the target: it reads, copies and re-scans, and writes
    only inside a temporary directory it also removes. It NEVER applies the
    diff to ``target``.
    """
    candidates = DEFAULT_TEMPLATES if templates is None else tuple(templates)
    template = next((t for t in candidates if t.matches(finding)), None)
    if template is None:
        return _refused(
            f"no fix template matches this finding ({finding.algorithm}, "
            f"{finding.asset_type}, from scanner {finding.scanner_id!r}). "
            f"ECDAT ships fixes only where a registered scanner can re-verify "
            f"them; see docs/adr/0015-fixit.md and PUNCHLIST.md."
        )

    if target.kind not in PATCHABLE_KINDS:
        return _refused(
            f"a {target.kind!r} target is not a patchable directory tree, so a "
            f"diff cannot be generated or verified against it",
            template,
        )

    verdict = template.preconditions(finding, target)
    if not verdict.ok:
        return _refused(verdict.reason, template)

    diff = template.make_diff(finding, target)
    if not diff.strip():
        return _refused(
            f"template {template.id!r} produced an empty diff: there is nothing "
            f"to change at this site",
            template,
        )

    scanner = _scanner_for(template)
    if scanner is None:
        return _unverified(
            template,
            f"not verified: template {template.id!r} names scanner "
            f"{template.scanner_to_reverify!r} to re-verify with, and no such "
            f"scanner is registered. ECDAT does not present an unverified diff.",
        )

    resolved_packs = default_packs() if packs is None else list(packs)
    ctx = default_context() if context is None else context
    return _verify(
        finding, target, template, diff, scanner, ctx, resolved_packs, z_years
    )


def _verify(
    finding: Finding,
    target: Target,
    template: FixTemplate,
    diff: str,
    scanner: Scanner,
    ctx: ScanContext,
    packs: Sequence[Pack],
    z_years: int,
) -> FixResult:
    """Steps 4-7 of the loop. See the module docstring."""
    with tempfile.TemporaryDirectory(prefix="ecdat-fixit-") as temporary:
        root = _sandbox_root(Path(target.ref), Path(temporary))
        # Same system, sector, exposure and data class -- only the root moves,
        # so endpoints and scores are computed exactly as they were.
        sandbox = replace(target, ref=str(root))
        wanted = _fingerprint(finding, replace(target, ref=str(target.ref)))

        before = list(scanner.scan(sandbox, ctx))
        if not _finding_survives(wanted, before, sandbox):
            return _unverified(
                template,
                f"not verified: the finding did not reproduce on a pristine "
                f"sandbox copy scanned with {scanner.id!r}, so nothing this "
                f"sandbox says about it would be evidence. The finding may be "
                f"stale, or it came from a different scanner.",
            )

        try:
            apply_unified_diff(root, diff)
        except PatchError as exc:
            return _unverified(
                template,
                f"not verified: the generated diff did not apply cleanly to the "
                f"sandbox copy ({exc})",
            )

        after = list(scanner.scan(sandbox, ctx))
        if not _fix_removed_the_finding(wanted, after, sandbox):
            return _unverified(
                template,
                f"not verified: the diff applied, but the finding is still "
                f"present when {scanner.id!r} re-scans the patched copy. The "
                f"template did not fix what it claimed to fix.",
            )

        arrivals = _arrivals(before, after, sandbox)
        introduced = _all_arrival_descriptions(
            arrivals, sandbox, packs, z_years, ctx.knowledge_dir
        )
        criticals = _critical_findings(
            arrivals, sandbox, packs, z_years, ctx.knowledge_dir
        )
        if criticals:
            return _unverified(
                template,
                f"not verified: the fix removes the original finding but "
                f"introduces a new {BLOCKING_BAND} finding -- "
                f"{'; '.join(criticals)}. A fix that trades one problem for a "
                f"worse one is rejected.",
                new_findings=introduced,
                new_criticals=tuple(criticals),
            )

        _log.info(
            "fix_verified",
            extra={
                "event": "fix_verified",
                "template_id": template.id,
                "scanner_id": scanner.id,
                "new_findings": len(introduced),
            },
        )
        return FixResult(
            applicable=True,
            verified=True,
            template_id=template.id,
            diff=diff,
            reason=(
                f"verified: re-scanned clean -- {scanner.id!r} no longer reports "
                f"this finding on the patched sandbox copy, and no new "
                f"{BLOCKING_BAND} finding appeared. Apply it yourself; ECDAT "
                f"has not touched {target.ref}."
            ),
            new_findings=introduced,
            new_criticals=(),
            source=template.source,
        )
