"""Contract tests for the scanner plugin interface (ADR-0001).

core/scanner.py ships no logic, but it does ship a contract: a conforming
plugin must expose `id`, `view`, `supports()` and `scan()`, and a Target must
be an inert, read-only description of a thing to scan.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from core.scanner import ScanContext, Scanner, Target
from core.schema import Evidence, Finding, Occurrence


class _ConformingScanner:
    """Structurally a Scanner; emits one hard-coded finding.

    Named for what it is -- a conformance double. Nothing to do with the
    retired scanners.stub package (ADR-0005).
    """

    id = "test.conforming"
    view = "declared"

    def supports(self, target: Target) -> bool:
        return target.kind == "repo"

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        yield Finding(
            scanner_id=self.id,
            view="declared",
            asset_type="algorithm",
            primitive="hash",
            algorithm="SHA-1",
            evidence=Evidence(
                occurrences=[
                    Occurrence(
                        view="declared",
                        locator=f"{target.ref}:1",
                        detail="rule=conforming@0",
                    )
                ]
            ),
        )


def test_a_structural_scanner_satisfies_the_protocol() -> None:
    assert isinstance(_ConformingScanner(), Scanner)


def test_an_object_missing_scan_does_not_satisfy_the_protocol() -> None:
    class _NotAScanner:
        id = "test.broken"
        view = "declared"

        def supports(self, target: Target) -> bool:
            return target.kind == "repo"

    assert not isinstance(_NotAScanner(), Scanner)


def test_scan_yields_findings_tagged_with_the_scanner_id() -> None:
    scanner = _ConformingScanner()
    target = Target(kind="repo", ref="/srv/quantumbank", system="quantumbank")
    ctx = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=Path("/tmp/x"))  # noqa: S108

    findings = list(scanner.scan(target, ctx))

    assert [f.scanner_id for f in findings] == ["test.conforming"]
    assert findings[0].evidence.occurrences[0].locator.startswith(target.ref)


def test_supports_discriminates_on_target_kind() -> None:
    scanner = _ConformingScanner()

    assert scanner.supports(Target(kind="repo", ref="/srv/quantumbank"))
    assert not scanner.supports(Target(kind="image", ref="quantumbank:1.4"))


def test_target_defaults_and_immutability() -> None:
    target = Target(kind="endpoint", ref="auth.internal:443")

    assert target.system is None
    assert target.data_class is None
    with pytest.raises(FrozenInstanceError):
        target.ref = "evil.example:443"  # type: ignore[misc]


def test_scan_context_carries_knowledge_and_scratch_dirs() -> None:
    ctx = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=Path("/tmp/s"))  # noqa: S108

    assert ctx.knowledge_dir == Path("knowledge")
    assert ctx.scratch_dir == Path("/tmp/s")  # noqa: S108
