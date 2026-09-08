"""The stub scanner exists only to exercise the pipe; pin what it promises."""

from __future__ import annotations

from pathlib import Path

from core.scanner import ScanContext, Scanner, Target
from scanners.stub import StubScanner

CTX = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=Path("scratch"))


def test_the_stub_satisfies_the_scanner_protocol() -> None:
    assert isinstance(StubScanner(), Scanner)


def test_the_stub_supports_every_target_kind() -> None:
    scanner = StubScanner()

    for kind in ("repo", "directory", "image", "host", "endpoint"):
        assert scanner.supports(Target(kind=kind, ref="x"))


def test_the_stub_yields_one_declared_rsa_finding() -> None:
    findings = list(StubScanner().scan(Target(kind="repo", ref="/srv/x"), CTX))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner_id == "stub"
    assert finding.view == "declared"
    assert finding.algorithm == "RSA"
    assert finding.primitive == "signature"
    assert finding.params["key_size"] == 2048
    assert [o.locator for o in finding.evidence.occurrences] == ["stub/example.py:1"]


def test_the_stub_is_repeatable() -> None:
    target = Target(kind="repo", ref="/srv/x")

    first = list(StubScanner().scan(target, CTX))
    second = list(StubScanner().scan(target, CTX))

    assert first == second
