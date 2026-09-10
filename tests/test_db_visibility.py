"""Which database am I looking at? (ADR-0020, part A)

The demo footgun this closes: `ecdat scan` writes wherever `ECDAT_DB` points
(or `./ecdat.db`), `uvicorn` opens whatever `ECDAT_DB` points at *in its own
shell*, and `make kpi` uses `.ecdat-kpi.db`. Get those out of step and the scan
succeeds, the server starts, and the dashboard is empty -- with nothing
anywhere saying why.

The fix is deliberately NOT magic path resolution. Two processes legitimately
using two databases is a real thing to want, and a tool that quietly
reconciled them would be guessing. What was missing is that the path was
invisible on both sides, so a mismatch could not be diagnosed without
`sqlite3`.

So: every writer prints the ABSOLUTE path it wrote to, the API logs the
absolute path it opened, and `ecdat scans` lists what is actually in the
database the current environment points at. One command, one answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import cli
from core import store
from core.scanner import Target

CBOM = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}\n'


def target() -> Target:
    return Target(kind="repo", ref="testdata/minimal_repo", system="lab")


# ---------------------------------------------------------------------------
# The absolute path is visible
# ---------------------------------------------------------------------------


def test_database_path_is_reported_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative path in a log line is only meaningful with the cwd beside it."""
    monkeypatch.setenv(store.ENV_DB_PATH, "some/relative/ecdat.db")
    store.reset_engines()

    resolved = store.database_location()

    assert resolved.is_absolute()
    assert resolved.name == "ecdat.db"
    assert tmp_path is not None  # fixture kept for isolation


def test_scan_prints_the_absolute_database_it_wrote_to(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "demo.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    store.reset_engines()

    exit_code = cli.main(
        ["scan", "testdata/minimal_repo", "-o", str(tmp_path / "c.json")]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert f"db={database.resolve()}" in captured.err


def test_scan_system_prints_the_absolute_database_it_wrote_to(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "demo.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    store.reset_engines()

    exit_code = cli.main(
        [
            "scan-system",
            "testdata/quantumbank/system.yaml",
            "-o",
            str(tmp_path / "c.json"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert f"db={database.resolve()}" in captured.err


def test_the_api_logs_the_absolute_database_it_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half the diagnosis is on the serving side, and it must be in the log."""
    from fastapi.testclient import TestClient

    from api.app import app

    database = tmp_path / "served.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()

    records: list[dict[str, object]] = []
    monkeypatch.setattr(
        "api.app._log.info",
        lambda message, **kwargs: records.append(
            {"message": message, **(kwargs.get("extra") or {})}
        ),
    )

    with TestClient(app):
        pass

    started = [r for r in records if r.get("event") == "api_started"]
    assert started, f"no api_started log line; got {records}"
    assert started[0]["database"] == str(database.resolve())


# ---------------------------------------------------------------------------
# `ecdat scans` -- the one-command diagnosis
# ---------------------------------------------------------------------------


def test_scans_lists_what_is_in_the_current_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "a.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()
    scan_id = store.save_scan(target(), CBOM, scanners_ran=[{"id": "config"}])

    exit_code = cli.main(["scans"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert scan_id in captured.out
    assert "scan" in captured.out
    # The path is printed too, so the answer and the question are together.
    assert str(database.resolve()) in captured.out + captured.err


def test_a_scan_written_to_one_database_is_absent_from_another(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE footgun, reproduced and made diagnosable in one command.

    Scan under one ECDAT_DB, list under another: the scan is missing, and the
    printed path says exactly why. Before this, the same situation produced an
    empty dashboard and no explanation anywhere.
    """
    first = tmp_path / "scanned-here.db"
    second = tmp_path / "served-from-here.db"

    monkeypatch.setenv(store.ENV_DB_PATH, str(first))
    store.reset_engines()
    scan_id = store.save_scan(target(), CBOM)

    monkeypatch.setenv(store.ENV_DB_PATH, str(first))
    store.reset_engines()
    cli.main(["scans"])
    same = capsys.readouterr().out
    assert scan_id in same

    monkeypatch.setenv(store.ENV_DB_PATH, str(second))
    store.reset_engines()
    cli.main(["scans"])
    other = capsys.readouterr().out
    assert scan_id not in other
    assert str(second.resolve()) in other


def test_scans_on_an_empty_database_says_so_rather_than_printing_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silence and "no scans here" are different answers to the same question."""
    monkeypatch.setenv(store.ENV_DB_PATH, str(tmp_path / "empty.db"))
    store.reset_engines()

    assert cli.main(["scans"]) == 0
    output = capsys.readouterr().out
    assert "no scans" in output.lower()


def test_scans_reports_the_drift_count_per_row(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A system scan is the one with drift; the list should show which."""
    monkeypatch.setenv(store.ENV_DB_PATH, str(tmp_path / "d.db"))
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    store.reset_engines()

    from core.system import load_manifest, scan_system

    scan_id = scan_system(load_manifest(Path("testdata/quantumbank/system.yaml")))
    record = store.get_scan(scan_id)
    assert record is not None
    expected = sum((record.drift_counts or {}).values())
    assert expected > 0

    cli.main(["scans"])
    output = capsys.readouterr().out

    line = next(row for row in output.splitlines() if scan_id[:8] in row)
    assert f"drift={expected}" in line
