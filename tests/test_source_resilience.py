"""The source scanner survives files it cannot parse (ADR-0033).

Scanning OWASP Juice Shop, one deliberately-malformed challenge snippet
(`data/static/codefixes/registerAdminChallenge_*.ts`) made semgrep report a
per-file "Syntax error". ECDAT treated EVERY entry in semgrep's `errors` array
as fatal, raised SemgrepOutputError, and discarded the findings semgrep had
already returned for every other file: the whole codebase yielded one
dependency finding. Real repositories almost always hold something
unparseable -- generated code, vendored junk, broken-on-purpose fixtures.

STEP 0 measured semgrep 1.176.1 OSS directly: it already skips an unparseable
file and exits 0 with the good files' results, and the error is `level: warn`
naming the file. The blindness was ours, so the fix is ours:

* a per-file PARSE error -- `warn`, a parse type, a named file -- is
  TOLERATED: the file becomes a coverage gap, and every other file's findings
  stand;
* anything else -- an `error`-level entry, an unknown type, an error naming no
  file, or a non-0/1 exit (a broken rule pack exits 7) -- still fails LOUD.

A file semgrep could not read is not a file that came back clean.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

import pytest

from core import scanner as scanner_api
from core.normalise import normalise
from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners import source
from scanners.source import SourceScanner
from tests.rulepack import load_answers, relative_path_of, rule_id_of, score

KNOWLEDGE_DIR = Path("knowledge")
ROOT = Path("testdata/resilience_fixtures")
MIXED = ROOT / "mixed"
UNPARSEABLE = ROOT / "unparseable"

#: What every PARSEABLE file in the mixed fixture holds -- and nothing more.
MIXED_FINDINGS = {
    ("app/hashing.py", "py-hashlib-md5"),
    ("src/crypto_utils.ts", "js-hash-md5"),
    # Semgrep's Go parser recovers PARTIALLY, so this one is both a finding
    # and a gap: the MD5 before the break is real and was read.
    ("pkg/partial.go", "go-md5"),
}

MIXED_GAPS = {
    ("app/broken_view.py", "unparsed", "Syntax error"),
    ("src/codefixes/registerAdminChallenge_1.ts", "unparsed", "Syntax error"),
    ("pkg/partial.go", "partially-parsed", "PartialParsing"),
}


def _context(tmp_path: Path, *, collect: bool = True) -> ScanContext:
    """A context; with `collect`, one carrying a fresh per-scan coverage log."""
    if not collect:
        return ScanContext(KNOWLEDGE_DIR, scratch_dir=tmp_path)
    return ScanContext(
        KNOWLEDGE_DIR, scratch_dir=tmp_path, coverage=scanner_api.CoverageLog()
    )


def _target(root: Path) -> Target:
    return Target(kind="directory", ref=str(root), system="resilience")


def _scan(root: Path, ctx: ScanContext) -> list[Finding]:
    return list(SourceScanner().scan(_target(root), ctx))


def _rel(path: str, root: Path) -> str:
    return Path(path).resolve().relative_to(root.resolve()).as_posix()


def _gaps(ctx: ScanContext, root: Path) -> set[tuple[str, str, str]]:
    assert ctx.coverage is not None
    return {(_rel(g.path, root), g.kind, g.reason) for g in ctx.coverage.gaps}


def _metadata(document: dict[str, Any]) -> dict[str, list[str]]:
    collected: dict[str, list[str]] = {}
    for prop in (document.get("metadata") or {}).get("properties", []):
        collected.setdefault(prop["name"], []).append(prop["value"])
    return collected


# ---------------------------------------------------------------------------
# THE JUICE SHOP BUG
# ---------------------------------------------------------------------------


def test_one_unparseable_file_does_not_blind_the_scan(tmp_path: Path) -> None:
    """The regression itself. Before ADR-0033 this RAISED and returned nothing.

    Deliberately written without the new coverage API, so that on the old code
    it fails for the real reason -- SemgrepOutputError on a parse warning --
    and not merely because a new name is missing.
    """
    findings = _scan(MIXED, _context(tmp_path, collect=False))

    got = {(relative_path_of(f, MIXED), rule_id_of(f)) for f in findings}
    assert got == MIXED_FINDINGS


def test_the_unparseable_files_are_recorded_as_coverage_gaps(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    _scan(MIXED, ctx)

    assert _gaps(ctx, MIXED) == MIXED_GAPS
    assert ctx.coverage is not None
    # Every file semgrep examined, parseable or not: five.
    assert ctx.coverage.examined == {"source": 5}


def test_a_rejected_file_contributes_nothing_and_is_never_called_clean(
    tmp_path: Path,
) -> None:
    """`broken_view.py` holds a real SHA-1 that ECDAT cannot see.

    Semgrep's `paths.scanned` lists it as SCANNED. Believing that would record
    a file nobody read as a file that came back clean -- so the gap comes from
    the parse error, never from the scanned list.
    """
    ctx = _context(tmp_path)
    findings = _scan(MIXED, ctx)

    assert not [
        f for f in findings if relative_path_of(f, MIXED) == "app/broken_view.py"
    ]
    assert ("app/broken_view.py", "unparsed", "Syntax error") in _gaps(ctx, MIXED)


def test_a_partially_parsed_file_keeps_its_findings_and_is_still_a_gap(
    tmp_path: Path,
) -> None:
    ctx = _context(tmp_path)
    findings = _scan(MIXED, ctx)

    assert ("pkg/partial.go", "go-md5") in {
        (relative_path_of(f, MIXED), rule_id_of(f)) for f in findings
    }
    assert ("pkg/partial.go", "partially-parsed", "PartialParsing") in _gaps(ctx, MIXED)


def test_the_skip_is_logged_with_the_files(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        _scan(MIXED, _context(tmp_path))

    events = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "source_files_unparsed"
    ]
    assert len(events) == 1
    assert getattr(events[0], "unparsed_count", None) == 2
    assert getattr(events[0], "partially_parsed_count", None) == 1


# ---------------------------------------------------------------------------
# EVERYTHING UNPARSEABLE: an honest "nothing parsed", not a crash, not a clean
# ---------------------------------------------------------------------------


def test_an_entirely_unparseable_repo_is_nothing_parsed_not_clean(
    tmp_path: Path,
) -> None:
    ctx = _context(tmp_path)

    findings = _scan(UNPARSEABLE, ctx)  # must not raise

    assert findings == []
    assert _gaps(ctx, UNPARSEABLE) == {
        ("half_written.py", "unparsed", "Syntax error"),
        ("registerAdminChallenge_2.ts", "unparsed", "Syntax error"),
    }
    assert ctx.coverage is not None
    assert ctx.coverage.examined == {"source": 2}
    assert ctx.coverage.nothing_parsed("source")


# ---------------------------------------------------------------------------
# THE STORED CBOM CARRIES THE GAP
# ---------------------------------------------------------------------------


def _stored(root: Path, tmp_path: Path) -> dict[str, Any]:
    from core import store
    from core.orchestrator import run_scan

    scan_id = run_scan(
        _target(root), [SourceScanner()], _context(tmp_path, collect=False), packs=[]
    )
    row = store.get_scan(scan_id)
    assert row is not None
    document: dict[str, Any] = json.loads(row.cbom_json)
    return document


def test_the_gap_reaches_the_stored_cbom(tmp_path: Path) -> None:
    document = _stored(MIXED, tmp_path)
    props = _metadata(document)

    assert props["ecdat:coverage:unparsed"] == ["2"]
    assert sorted(_rel(p, MIXED) for p in props["ecdat:coverage:unparsed:file"]) == [
        "app/broken_view.py",
        "src/codefixes/registerAdminChallenge_1.ts",
    ]
    assert props["ecdat:coverage:partially_parsed"] == ["1"]
    assert [_rel(p, MIXED) for p in props["ecdat:coverage:partially_parsed:file"]] == [
        "pkg/partial.go"
    ]
    assert props["ecdat:coverage:source:examined"] == ["5"]
    # And the good files' findings are IN the document, not only in memory.
    places = {
        _rel(o["location"], MIXED)
        for c in document["components"]
        for o in c.get("evidence", {}).get("occurrences", [])
    }
    assert places == {path for path, _ in MIXED_FINDINGS}


def test_nothing_parsed_is_stated_in_the_stored_cbom_not_left_looking_clean(
    tmp_path: Path,
) -> None:
    document = _stored(UNPARSEABLE, tmp_path)
    props = _metadata(document)

    assert document["components"] == []
    assert props["ecdat:coverage:unparsed"] == ["2"]
    assert props["ecdat:coverage:source:examined"] == ["2"]
    assert any(
        "nothing could be parsed" in note for note in props["ecdat:coverage:note"]
    )


def test_a_fully_parsed_scan_writes_no_coverage_metadata(tmp_path: Path) -> None:
    """No gap, no property -- so every existing document keeps its bytes."""
    document = _stored(Path("testdata/minimal_repo"), tmp_path)
    assert not [k for k in _metadata(document) if k.startswith("ecdat:coverage:")]


# ---------------------------------------------------------------------------
# A REAL FAILURE STILL FAILS LOUD -- never swallowed as a "skip"
# ---------------------------------------------------------------------------


def test_a_missing_semgrep_still_fails_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source, "SEMGREP_BINARY", "semgrep-does-not-exist")
    ctx = _context(tmp_path)

    with pytest.raises(source.SemgrepUnavailableError):
        _scan(MIXED, ctx)
    assert ctx.coverage is not None and ctx.coverage.gaps == []


def test_a_broken_rule_pack_still_fails_loud(tmp_path: Path) -> None:
    """Semgrep exits 7 on a schema-invalid rule: that is a failure, not a skip."""
    knowledge = tmp_path / "knowledge"
    rules = knowledge / "rules"
    rules.mkdir(parents=True)
    shutil.copy(
        KNOWLEDGE_DIR / "rules" / "javascript" / "hashes.yaml", rules / "good.yaml"
    )
    (rules / "bad.yaml").write_text(
        "rules:\n"
        "  - id: broken-rule\n"
        "    languages: [typescript]\n"
        "    severity: INFO\n"
        '    message: "ecdat|"\n'
        "    patternz: foo(...)\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        knowledge, scratch_dir=tmp_path / "scratch", coverage=scanner_api.CoverageLog()
    )

    with pytest.raises(source.SemgrepFailedError):
        _scan(MIXED, ctx)
    assert ctx.coverage is not None and ctx.coverage.gaps == []


def _payload(*errors: dict[str, Any], scanned: tuple[str, ...] = ("a.ts",)) -> str:
    return json.dumps(
        {"results": [], "errors": list(errors), "paths": {"scanned": list(scanned)}}
    )


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        pytest.param(
            {"type": "Syntax error", "level": "warn", "path": "a.ts", "message": "x"},
            "unparsed",
            id="syntax-error",
        ),
        pytest.param(
            {"type": "Lexical error", "level": "warn", "path": "a.ts", "message": "x"},
            "unparsed",
            id="lexical-error",
        ),
        pytest.param(
            {
                "type": ["PartialParsing", [{"path": "a.ts"}]],
                "level": "warn",
                "path": "a.ts",
                "message": "x",
            },
            "partially-parsed",
            id="partial-parsing",
        ),
    ],
)
def test_a_per_file_parse_error_is_tolerated_and_recorded(
    error: dict[str, Any], kind: str
) -> None:
    output = source._parse_semgrep_json(_payload(error))
    assert [(g.path, g.kind) for g in output.gaps] == [("a.ts", kind)]
    assert output.examined == 1


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(
            {"type": "Syntax error", "level": "error", "path": "a.ts"}, id="error-level"
        ),
        pytest.param({"type": "Syntax error", "level": "warn"}, id="names-no-file"),
        pytest.param(
            {"type": "Fatal error", "level": "warn", "path": "a.ts"}, id="unknown-type"
        ),
        pytest.param(
            {
                "type": "InvalidRuleSchemaError",
                "level": "error",
                "path": "rules/bad.yaml",
            },
            id="invalid-rule-schema",
        ),
        pytest.param(
            {"type": "SemgrepError", "level": "error", "message": "invalid config"},
            id="semgrep-error",
        ),
    ],
)
def test_anything_but_a_per_file_parse_error_still_fails_loud(
    error: dict[str, Any],
) -> None:
    """The boundary, pinned from both sides. Tolerance is an ALLOWLIST: an
    error type nobody listed fails loud rather than being quietly skipped."""
    with pytest.raises(source.SemgrepOutputError):
        source._parse_semgrep_json(_payload(error))


# ---------------------------------------------------------------------------
# NO REGRESSION: the clean packs, at == 1.0 (no floors)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "root",
    [
        "testdata/python_fixtures",
        "testdata/go_fixtures",
        "testdata/js_fixtures",
        "testdata/java_fixtures",
    ],
)
def test_the_clean_packs_parse_fully_at_exact_recall_and_precision(
    root: str, tmp_path: Path
) -> None:
    """Held at == 1.0 here, whatever floor a pack's own module still carries."""
    ctx = _context(tmp_path)
    findings = _scan(Path(root), ctx)

    assert ctx.coverage is not None and ctx.coverage.gaps == [], ctx.coverage
    result = score(findings, load_answers(Path(root)))
    assert result.recall == 1.0, (
        f"{root} recall {result.recall:.1%}; missed {result.missed}"
    )
    assert result.precision == 1.0, f"{root} spurious {result.spurious}"


def test_quantumbank_is_unchanged_at_exact_recall() -> None:
    """The KPI estate, end to end, at == 1.0 -- and it parses fully."""
    from kpi.harness import run_kpi

    report = run_kpi()

    assert report.findings.recall == 1.0, f"missed {report.findings.missed}"
    assert report.findings.precision == 1.0, "a decoy fired"
    document = json.loads(report.cbom_json)
    assert not [k for k in _metadata(document) if k.startswith("ecdat:coverage:")]


# ---------------------------------------------------------------------------
# DETERMINISM
# ---------------------------------------------------------------------------


def test_the_partial_scan_is_deterministic(tmp_path: Path) -> None:
    fixed: dict[str, Any] = {
        "serial_number": uuid.UUID(int=0),
        "timestamp": dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    }

    def once(scratch: Path) -> str:
        ctx = _context(scratch)
        findings = _scan(MIXED, ctx)
        return normalise(findings, _target(MIXED), coverage=ctx.coverage, **fixed)[1]

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert once(tmp_path / "a") == once(tmp_path / "b")
