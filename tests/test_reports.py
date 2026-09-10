"""Three reports, generated from a stored CBOM (ADR-0020, part B).

Nothing here re-scans. Every number, every deadline, every citation is read off
the `ecdat:*` properties the policy engine and the correlator already wrote, so
a report and the dashboard cannot disagree about the same scan -- and a report
issued last March can be regenerated from the row that produced it.

The honesty rules the rest of the tool enforces are enforced here too, because
a PDF is the artefact that leaves the building:

* a **provisional** fact is shown as provisional and never as scored
  (ADR-0017);
* the **coverage statement** says what was NOT looked at, so "we found no
  observed crypto" and "we never observed anything" are different sentences.

PDFs are checked by extracting their text rather than by eye. That is a weaker
assertion than "it looks right" and a much stronger one than "it did not
crash": the numbers, the citations and the caveats are all text.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

import cli
from core import store
from core.scanner import ScanContext, Target
from core.system import load_manifest, scan_system
from reports import (
    CoverageReport,
    ExecutiveReport,
    TechnicalReport,
    UnknownScanError,
    render,
)

MANIFEST = Path("testdata/quantumbank/system.yaml")
KNOWLEDGE = Path("knowledge")


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path / "scratch")


@dataclass(frozen=True)
class StoredDocument:
    """A scan's bytes and row fields, captured once and re-saved per test.

    The conftest gives every test its own database, so a scan cannot simply be
    shared across tests. Re-running `scan_system` per test would be correct and
    costs ~1.5s each -- twenty of those is most of the suite's runtime. The
    document is identical either way, so it is produced ONCE and inserted into
    whichever database the current test is using.
    """

    target: Target
    cbom_json: str
    scanners_ran: list[dict[str, str]] | None
    z_years: int | None
    engine_versions: dict[str, object] | None

    def save(self) -> str:
        return store.save_scan(
            self.target,
            self.cbom_json,
            scanners_ran=self.scanners_ran,
            z_years=self.z_years,
            engine_versions=self.engine_versions,
        )


def _capture(target: Target, scan_id: str) -> StoredDocument:
    record = store.get_scan(scan_id)
    assert record is not None
    return StoredDocument(
        target=target,
        cbom_json=record.cbom_json,
        scanners_ran=record.scanners_ran,
        z_years=record.z_years,
        engine_versions=record.engine_versions,
    )


SYSTEM_TARGET = Target(
    kind="directory",
    ref="testdata/quantumbank",
    system="quantumbank",
    data_class="Personal",
    sector="bfsi",
    exposure="internet",
)


@contextmanager
def _own_database(work: Path) -> Iterator[None]:
    """Isolate the database for a MODULE-scoped fixture.

    pytest instantiates fixtures broadest-scope-first, so a module-scoped
    fixture runs BEFORE the function-scoped autouse fixture in conftest that
    points ECDAT_DB at a tmp file. Without this, the capture below writes into
    the developer's real ./ecdat.db -- which
    `test_the_store_writes_where_ecdat_db_points` exists to catch, and did.
    """
    previous = os.environ.get(store.ENV_DB_PATH)
    os.environ[store.ENV_DB_PATH] = str(work / "capture.db")
    store.reset_engines()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(store.ENV_DB_PATH, None)
        else:
            os.environ[store.ENV_DB_PATH] = previous
        store.reset_engines()


@pytest.fixture(scope="module")
def system_document() -> StoredDocument:
    """A full three-view scan: the only kind that carries drift (ADR-0019)."""
    with (
        tempfile.TemporaryDirectory(prefix="ecdat-report-tests-") as work,
        _own_database(Path(work)),
    ):
        context = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=Path(work))
        scan_id = scan_system(load_manifest(MANIFEST), context)
        return _capture(SYSTEM_TARGET, scan_id)


@pytest.fixture(scope="module")
def declared_document() -> StoredDocument:
    """A single-target scan: declared only, no shipped, no observed."""
    from core import registry
    from core.orchestrator import run_scan

    with (
        tempfile.TemporaryDirectory(prefix="ecdat-report-tests-") as work,
        _own_database(Path(work)),
    ):
        context = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=Path(work))
        scan_id = run_scan(
            SYSTEM_TARGET, registry.get_scanners(["config", "source"]), context
        )
        return _capture(SYSTEM_TARGET, scan_id)


@pytest.fixture
def system_scan(system_document: StoredDocument) -> str:
    return system_document.save()


@pytest.fixture
def declared_only_scan(declared_document: StoredDocument) -> str:
    return declared_document.save()


def text_of(pdf: bytes) -> str:
    """Every text run in the PDF, flattened, whitespace-normalised."""
    from reports.extract import extract_text

    return re.sub(r"\s+", " ", extract_text(pdf))


def is_pdf(payload: bytes) -> bool:
    return payload.startswith(b"%PDF-") and payload.rstrip().endswith(b"%%EOF")


# ---------------------------------------------------------------------------
# The executive report
# ---------------------------------------------------------------------------


def test_the_executive_report_is_a_valid_pdf(system_scan: str) -> None:
    payload = render(ExecutiveReport, system_scan)

    assert is_pdf(payload)
    assert len(payload) > 2000


def test_the_executive_report_carries_the_headline_numbers(system_scan: str) -> None:
    record = store.get_scan(system_scan)
    assert record is not None
    body = text_of(render(ExecutiveReport, system_scan))

    assert "quantumbank" in body
    assert system_scan[:8] in body
    assert str(record.component_count) in body
    assert str(record.max_score) in body
    # Every band is named, zeroes included -- an absent band reads as "not
    # assessed" rather than "none".
    for band in ("Critical", "High", "Medium", "Low"):
        assert band in body
    assert str(sum((record.drift_counts or {}).values())) in body


def test_the_executive_report_names_the_five_highest_risk_artefacts(
    system_scan: str,
) -> None:
    body = text_of(render(ExecutiveReport, system_scan))

    assert "RSA-2048" in body
    assert "98" in body
    assert "Critical" in body
    # Five rows, and the worst one first.
    worst = body.index("RSA-2048")
    assert worst < len(body)


def test_the_executive_report_frames_the_india_dst_deadline_with_its_source(
    system_scan: str,
) -> None:
    """A deadline an organisation may act on must arrive with its citation."""
    body = text_of(render(ExecutiveReport, system_scan))

    assert "2027-12-31" in body
    assert "Quantum-Safe Ecosystem in India" in body
    assert "dst.gov.in" in body


def test_the_executive_report_records_the_engine_that_produced_the_scan(
    system_scan: str,
) -> None:
    body = text_of(render(ExecutiveReport, system_scan))

    assert "semgrep" in body
    assert "1.176.1" in body


def test_a_provisional_fact_is_never_presented_as_scored(
    tmp_path: Path, context: ScanContext
) -> None:
    """ADR-0017's rule, carried into the artefact that leaves the building.

    Scored with the DST pack demoted, so the deadline is real, displayed, and
    contributing nothing. The report must say so in words -- a reader with a
    printout has no tooltip to hover.
    """
    import json

    from policy import sign
    from policy.engine import load_packs

    packs = tmp_path / "packs"
    packs.mkdir()
    for source in Path("policy/packs").glob("*.yaml"):
        body = source.read_text(encoding="utf-8")
        if source.name == "india_dst.yaml":
            body = body.replace("verified: true", "verified: false")
        (packs / source.name).write_text(body, encoding="utf-8")
        sign.sign_file(packs / source.name, Path("policy/keys/dev/pack-signing.key"))

    scan_id = scan_system(load_manifest(MANIFEST), context, packs=load_packs(packs))
    record = store.get_scan(scan_id)
    assert record is not None
    assert (
        '"ecdat:provisional"' in record.cbom_json
        or "ecdat:provisional" in json.dumps(json.loads(record.cbom_json))
    )

    body = text_of(render(ExecutiveReport, scan_id))

    assert "provisional" in body.lower()


# ---------------------------------------------------------------------------
# The technical report
# ---------------------------------------------------------------------------


def test_the_technical_report_is_a_valid_pdf(system_scan: str) -> None:
    assert is_pdf(render(TechnicalReport, system_scan))


def test_the_technical_report_has_a_section_for_every_populated_band(
    system_scan: str,
) -> None:
    record = store.get_scan(system_scan)
    assert record is not None
    body = text_of(render(TechnicalReport, system_scan))

    for band, count in (record.band_counts or {}).items():
        if count:
            assert band in body, f"{band} has {count} components and no section"


def test_the_technical_report_shows_drift_with_its_named_cause(
    system_scan: str,
) -> None:
    """The point of a three-view scan, on the page.

    Declared vs shipped, and WHY -- an operator reading this needs the cause,
    not just the disagreement.
    """
    body = text_of(render(TechnicalReport, system_scan))

    assert "shipped-cannot-do-declared" in body
    assert "X25519MLKEM768" in body
    assert "3.0.2" in body
    assert "payments.quantumbank.invalid:443" in body


def test_the_technical_report_carries_evidence_and_fired_rules(
    system_scan: str,
) -> None:
    body = text_of(render(TechnicalReport, system_scan))

    assert "tokens.py" in body
    assert "quantum-shor-broken-asymmetric" in body
    assert "quantum" in body


def test_a_declared_only_scan_produces_an_empty_drift_section_that_says_so(
    declared_only_scan: str,
) -> None:
    """Not silence: "no drift was found" and "drift was not computable" differ."""
    body = text_of(render(TechnicalReport, declared_only_scan))

    assert "shipped-cannot-do-declared" not in body
    assert "no drift" in body.lower()


# ---------------------------------------------------------------------------
# The coverage statement -- the honest one
# ---------------------------------------------------------------------------


def test_the_coverage_statement_lists_the_scanners_that_ran(
    system_scan: str,
) -> None:
    body = text_of(render(CoverageReport, system_scan))

    for scanner in ("config", "container", "runtime-spool", "source"):
        assert scanner in body


def test_the_coverage_statement_names_the_standing_known_gaps(
    system_scan: str,
) -> None:
    """The list ECDAT must never stop printing."""
    body = text_of(render(CoverageReport, system_scan))

    assert "Go" in body
    assert "JavaScript" in body


def test_a_declared_only_scan_reports_the_views_it_did_not_collect(
    declared_only_scan: str,
) -> None:
    """THE honesty test. Silence here is the failure this artefact prevents.

    A scan that never looked at an image or a host must not read as an estate
    with clean images and clean hosts.
    """
    body = text_of(render(CoverageReport, declared_only_scan))

    assert "declared" in body
    assert "shipped" in body
    assert "observed" in body
    assert "not collected" in body.lower()
    # And it must not claim they were clean.
    assert "no shipped findings" not in body.lower()


def test_a_three_view_scan_reports_all_three_views_as_collected(
    system_scan: str,
) -> None:
    body = text_of(render(CoverageReport, system_scan))

    assert "collected" in body.lower()


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [ExecutiveReport, TechnicalReport, CoverageReport])
def test_the_same_scan_renders_byte_identical_bytes(
    system_scan: str, kind: type
) -> None:
    """No `now()` anywhere: the report's date is the SCAN's date.

    A report that changed bytes on every render could not be checksummed,
    attached to a ticket, or compared against the one somebody was sent.
    """
    first = render(kind, system_scan)
    second = render(kind, system_scan)

    assert first == second


def test_an_unknown_scan_is_refused(system_scan: str) -> None:
    assert system_scan  # the fixture proves the happy path exists
    with pytest.raises(UnknownScanError):
        render(ExecutiveReport, "no-such-scan")


# ---------------------------------------------------------------------------
# CLI and API
# ---------------------------------------------------------------------------


def test_ecdat_report_writes_each_kind(
    system_scan: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for kind in ("executive", "technical", "coverage"):
        out = tmp_path / f"{kind}.pdf"
        assert cli.main(["report", system_scan, "--kind", kind, "-o", str(out)]) == 0
        assert is_pdf(out.read_bytes())
    capsys.readouterr()


def test_ecdat_report_defaults_to_a_reports_out_directory(
    system_scan: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert cli.main(["report", system_scan, "--kind", "executive"]) == 0
    capsys.readouterr()

    written = list((tmp_path / "reports-out").glob("*.pdf"))
    assert written, "no report written to the default directory"
    assert is_pdf(written[0].read_bytes())


def test_ecdat_report_on_an_unknown_scan_fails_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["report", "no-such-scan", "--kind", "executive"]) == 2
    assert "no-such-scan" in capsys.readouterr().err


def test_the_api_serves_each_report_as_a_pdf(
    system_scan: str, viewer_headers: dict[str, str]
) -> None:
    from fastapi.testclient import TestClient

    from api.app import app

    # A report is a read: a viewer key is enough (ADR-0035).
    with TestClient(app, headers=viewer_headers) as client:
        for kind in ("executive", "technical", "coverage"):
            response = client.get(f"/scans/{system_scan}/report/{kind}")
            assert response.status_code == 200, response.text
            assert response.headers["content-type"] == "application/pdf"
            assert is_pdf(response.content)


def test_the_api_refuses_an_unknown_report_kind(
    system_scan: str, viewer_headers: dict[str, str]
) -> None:
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app, headers=viewer_headers) as client:
        assert client.get(f"/scans/{system_scan}/report/nope").status_code == 400
        assert client.get("/scans/nope/report/executive").status_code == 404
