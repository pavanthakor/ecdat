"""Write fix results onto a CBOM as ``ecdat:fix:`` component properties.

A post-correlation pass, in the same shape as ``policy.apply`` and
``correlate.apply``: it takes a stored document, strips everything it owns,
writes it again, and is therefore idempotent -- re-running replaces the
previous pass rather than accumulating it.

**Why it is not part of ``run_scan``.** Policy scoring and drift are cheap
reasoning over components already in hand. Verifying a fix copies the target,
re-scans it twice and scores whatever arrived, per finding. Making every scan
pay that is how a scan becomes something people stop running. So the fix pass
is driven by ``ecdat fix <scan-id>``, which is also the honest model: a fix is
something you ask for about an inventory you already have.

**The invariant a dashboard can rely on:** ``ecdat:fix:diff`` is written ONLY
when ``ecdat:fix:verified`` is ``true``. A refusal keeps its template and its
reason -- "MD5 here is a password, use Argon2id" is worth showing -- but never
a patch. An unverified diff rendered next to an apply button is how an
unproven change reaches production.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from core.identity import finding_identity
from core.scanner import ScanContext, Target
from core.schema import Finding
from correlate.fixit.engine import FixResult, propose_fix
from correlate.fixit.template import FixTemplate
from policy.apply import DEFAULT_Z_YEARS
from policy.engine import Pack

__all__ = ["FIX_PROPERTIES", "apply_fixes", "propose_fixes"]

#: Every property this module owns, so stripping before a rewrite and writing
#: after cannot drift apart.
FIX_PROPERTIES = (
    "ecdat:fix:template",
    "ecdat:fix:verified",
    "ecdat:fix:diff",
    "ecdat:fix:reason",
    "ecdat:fix:source",
)

_INDENT = 2


def _preferred(current: FixResult, candidate: FixResult) -> FixResult:
    """Which of two fixes for one component to keep.

    Findings merge into components (ADR-0002), so two findings that became one
    component can each carry a fix. A verified fix beats an unverified one;
    ties break on template id, so the choice never depends on scan order.
    """
    if current.verified != candidate.verified:
        return current if current.verified else candidate
    return min(current, candidate, key=lambda r: (r.template_id or "", r.diff or ""))


def propose_fixes(
    findings: Sequence[Finding],
    target: Target,
    *,
    templates: Sequence[FixTemplate] | None = None,
    context: ScanContext | None = None,
    packs: Sequence[Pack] | None = None,
    z_years: int = DEFAULT_Z_YEARS,
) -> dict[str, FixResult]:
    """``bom-ref -> FixResult`` for every finding a template speaks to.

    Findings no template matches are omitted entirely rather than recorded as
    "no fix": every component in an estate would carry that property and it
    would say nothing.
    """
    fixes: dict[str, FixResult] = {}
    for finding in findings:
        result = propose_fix(
            finding,
            target,
            templates=templates,
            context=context,
            packs=packs,
            z_years=z_years,
        )
        if result.template_id is None:
            continue
        reference = finding_identity(finding, target)
        existing = fixes.get(reference)
        fixes[reference] = result if existing is None else _preferred(existing, result)
    return fixes


def _properties(result: FixResult) -> list[dict[str, str]]:
    properties = [
        {"name": "ecdat:fix:template", "value": result.template_id or ""},
        {"name": "ecdat:fix:verified", "value": "true" if result.verified else "false"},
        {"name": "ecdat:fix:reason", "value": result.reason},
    ]
    if result.source:
        properties.append({"name": "ecdat:fix:source", "value": result.source})
    # The invariant: a diff only ever accompanies a verified result.
    if result.verified and result.diff:
        properties.append({"name": "ecdat:fix:diff", "value": result.diff})
    return properties


def apply_fixes(cbom_json: str, fixes: Mapping[str, FixResult]) -> str:
    """Write ``fixes`` onto the components they belong to, byte-stably."""
    document = json.loads(cbom_json)

    for component in document.get("components", []):
        reference = str(component.get("bom-ref", ""))
        properties = [
            p
            for p in component.get("properties", [])
            if p.get("name") not in FIX_PROPERTIES
        ]
        result = fixes.get(reference)
        if result is not None and result.template_id is not None:
            properties.extend(_properties(result))
        # Stable sort by name: repeated names keep their meaningful order and
        # everything else lands where a reader expects it.
        component["properties"] = sorted(properties, key=lambda p: p["name"])

    return (
        json.dumps(document, indent=_INDENT, sort_keys=True, ensure_ascii=False) + "\n"
    )


def patch_filename(reference: str, result: FixResult) -> str:
    """A stable, filesystem-safe name for a saved patch."""
    return f"{result.template_id}-{reference[:12]}.patch"


def write_patches(fixes: Mapping[str, FixResult], directory: Path) -> list[Path]:
    """Save every VERIFIED diff into ``directory``. Returns what was written.

    Only verified diffs are saved, for the same reason only verified diffs
    reach the CBOM: a ``.patch`` file on disk is one ``git apply`` away from
    being a change nobody proved.
    """
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for reference in sorted(fixes):
        result = fixes[reference]
        if not (result.verified and result.diff):
            continue
        path = directory / patch_filename(reference, result)
        path.write_text(result.diff, encoding="utf-8")
        written.append(path)
    return written
