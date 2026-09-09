"""Tests for the end-to-end scan pipe.

Scanners -> findings -> normalise -> validated CBOM -> SQLite. The point is
that the pipe holds together and that one broken plugin cannot take a scan
down with it.

Two kinds of scanner appear here, deliberately. The orchestration mechanics --
plugin isolation, failure logging, partial-yield retention, determinism -- use
hand-built fakes, because they are about the orchestrator and should not depend
on semgrep being installed or on any rule pack. The one genuinely end-to-end
test runs the *real* source scanner over ``testdata/minimal_repo``, so the
claim "findings reach a schema-valid CBOM" is made about real detection rather
than a placeholder. That test previously used the stub scanner, which has been
retired in favour of the registry.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from core import store
from core.normalise import CbomValidationError
from core.orchestrator import default_context, run_scan
from core.scanner import ScanContext, Target
from core.schema import Finding, View
from scanners.source import SourceScanner
from tests.factories import finding, occurrence

#: Two crypto call sites -> two components.
MINIMAL_REPO = "testdata/minimal_repo"
MINIMAL_COMPONENTS = 2


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        knowledge_dir=tmp_path / "knowledge", scratch_dir=tmp_path / "scratch"
    )


@pytest.fixture
def target() -> Target:
    return Target(kind="repo", ref="/srv/quantumbank", system="quantumbank")


class FixedScanner:
    """Yields one predictable finding. Stands in for a detector.

    The orchestrator tests need *a* scanner that reliably produces one
    component; what it detects is irrelevant to them. Keeping that here rather
    than in a shipped package is why the stub scanner could be deleted.
    """

    id: str = "fixed"
    view: View = "declared"

    def supports(self, target: Target) -> bool:
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        yield finding(
            scanner_id=self.id,
            occurrences=[occurrence(locator="fixed/example.py:1")],
        )


class ExplodingScanner:
    """Raises at call time, before yielding anything (a non-generator plugin)."""

    id: str = "boom"
    view: View = "declared"

    def supports(self, target: Target) -> bool:
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        raise RuntimeError("detector segfaulted")


class HalfwayScanner:
    """Raises mid-iteration, after yielding one real finding (a generator)."""

    id: str = "halfway"
    view: View = "declared"

    def supports(self, target: Target) -> bool:
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        yield finding(
            scanner_id=self.id,
            algorithm="DSA",
            occurrences=[occurrence(locator="halfway/a.py:1")],
        )
        raise RuntimeError("ran out of file descriptors")


class UninterestedScanner:
    """Supports nothing; must never be asked to scan."""

    id: str = "uninterested"
    view: View = "shipped"

    def __init__(self) -> None:
        self.scanned = False

    def supports(self, target: Target) -> bool:
        return False

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        self.scanned = True
        yield finding()


# --------------------------------------------------------------------------
# the happy pipe
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_run_scan_persists_a_schema_valid_cbom() -> None:
    """The real pipe: real scanner, real rules, real CBOM.

    Uses ``default_context()`` rather than the tmp-path ``ctx`` fixture: the
    source scanner needs the actual rule pack under ``knowledge/``, and a
    scan pointed at an empty knowledge directory is a different test.

    Uses the source scanner over a two-call-site fixture rather than a fake,
    because this is the one test whose claim would be hollow without a genuine
    detection at the front of it.
    """
    real_target = Target(kind="repo", ref=MINIMAL_REPO, system="minimal")

    scan_id = run_scan(real_target, [SourceScanner()], default_context())

    scan = store.get_scan(scan_id)
    assert scan is not None
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(scan.cbom_json) is None
    assert scan.component_count == MINIMAL_COMPONENTS
    assert scan.target_ref == MINIMAL_REPO
    assert "RSA-2048" in scan.cbom_json
    assert "SHA-256" in scan.cbom_json


@pytest.mark.validation
def test_run_scan_with_a_fake_scanner_persists_a_schema_valid_cbom(
    target: Target, ctx: ScanContext
) -> None:
    scan_id = run_scan(target, [FixedScanner()], ctx)

    scan = store.get_scan(scan_id)
    assert scan is not None
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(scan.cbom_json) is None
    assert scan.component_count == 1
    assert scan.target_ref == target.ref
    assert "RSA" in scan.cbom_json


def test_run_scan_with_no_findings_still_stores_a_valid_cbom(
    target: Target, ctx: ScanContext
) -> None:
    scan_id = run_scan(target, [], ctx)

    scan = store.get_scan(scan_id)
    assert scan is not None
    assert scan.component_count == 0
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(scan.cbom_json) is None


def test_a_scanner_that_supports_nothing_is_never_run(
    target: Target, ctx: ScanContext
) -> None:
    uninterested = UninterestedScanner()

    run_scan(target, [FixedScanner(), uninterested], ctx)

    assert uninterested.scanned is False


# --------------------------------------------------------------------------
# determinism, all the way through the database
# --------------------------------------------------------------------------


def test_two_scans_of_the_same_target_store_identical_documents(
    target: Target, ctx: ScanContext
) -> None:
    first = store.get_scan(run_scan(target, [FixedScanner()], ctx))
    second = store.get_scan(run_scan(target, [FixedScanner()], ctx))

    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert first.cbom_json == second.cbom_json


# --------------------------------------------------------------------------
# a broken scanner must not take the scan down
# --------------------------------------------------------------------------


def test_a_throwing_scanner_does_not_abort_the_scan(
    target: Target, ctx: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    scan_id = run_scan(target, [ExplodingScanner(), FixedScanner()], ctx)

    scan = store.get_scan(scan_id)
    assert scan is not None
    assert scan.component_count == 1
    assert "fixed/example.py" in scan.cbom_json


def test_a_scanner_failure_is_logged_with_its_id_and_cause(
    target: Target, ctx: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    run_scan(target, [ExplodingScanner(), FixedScanner()], ctx)

    failures = [
        r for r in caplog.records if getattr(r, "event", None) == "scanner_failed"
    ]
    assert len(failures) == 1
    assert failures[0].scanner_id == "boom"  # type: ignore[attr-defined]
    assert failures[0].error_type == "RuntimeError"  # type: ignore[attr-defined]
    assert "segfaulted" in failures[0].error  # type: ignore[attr-defined]


def test_the_run_records_which_scanners_ran_and_which_failed(
    target: Target, ctx: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    run_scan(target, [ExplodingScanner(), FixedScanner(), UninterestedScanner()], ctx)

    completed = next(
        r for r in caplog.records if getattr(r, "event", None) == "scan_completed"
    )
    assert completed.scanners_ran == ["fixed"]  # type: ignore[attr-defined]
    assert completed.scanners_failed == ["boom"]  # type: ignore[attr-defined]
    assert completed.scanners_skipped == ["uninterested"]  # type: ignore[attr-defined]


def test_findings_yielded_before_a_scanner_died_are_kept(
    target: Target, ctx: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    scan_id = run_scan(target, [HalfwayScanner(), FixedScanner()], ctx)

    scan = store.get_scan(scan_id)
    assert scan is not None
    # Evidence already produced is real evidence; it is kept, and the partial
    # run is visible in the log rather than silently dropped.
    assert scan.component_count == 2
    failure = next(
        r for r in caplog.records if getattr(r, "event", None) == "scanner_failed"
    )
    assert failure.findings_kept == 1  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# a real failure must NOT be swallowed
# --------------------------------------------------------------------------


def test_a_validation_failure_propagates(
    target: Target, ctx: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_normalise(*_args: object, **_kwargs: object) -> object:
        raise CbomValidationError("document does not validate against CycloneDX 1.6")

    monkeypatch.setattr("core.orchestrator.normalise", broken_normalise)

    with pytest.raises(CbomValidationError):
        run_scan(target, [FixedScanner()], ctx)

    assert store.list_scans() == []


# --------------------------------------------------------------------------
# context defaults
# --------------------------------------------------------------------------


def test_default_context_is_usable_and_scratch_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECDAT_KNOWLEDGE_DIR", str(tmp_path / "knowledge"))
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))

    context = default_context()

    assert context.knowledge_dir == tmp_path / "knowledge"
    assert context.scratch_dir.is_dir()
