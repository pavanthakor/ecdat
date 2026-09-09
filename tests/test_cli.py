"""CLI tests: `ecdat scan <ref>`.

Scans run the real source scanner over ``testdata/minimal_repo`` -- two crypto
call sites, so an exact component count is assertable. This replaces the old
coverage that ran the stub scanner against a path that did not exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cli
from core import store

#: Two crypto call sites -> two components.
MINIMAL_REPO = "testdata/minimal_repo"
MINIMAL_COMPONENTS = 2


def test_scan_writes_the_cbom_to_stdout_and_the_summary_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["scan", MINIMAL_REPO])

    captured = capsys.readouterr()
    assert exit_code == 0
    document = json.loads(captured.out)
    assert document["specVersion"] == "1.6"
    assert len(document["components"]) == MINIMAL_COMPONENTS
    # The summary goes to stderr so `ecdat scan . > cbom.json` stays usable.
    assert f"component_count={MINIMAL_COMPONENTS}" in captured.err
    scan_id = store.list_scans()[0].id
    assert scan_id in captured.err


def test_the_default_scan_finds_real_crypto(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Running every registered scanner is a real detection, not a placeholder."""
    cli.main(["scan", MINIMAL_REPO])

    document = json.loads(capsys.readouterr().out)
    names = {component["name"] for component in document["components"]}

    assert names == {"RSA-2048", "SHA-256"}


def test_scan_writes_to_a_file_with_dash_o(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "cbom.json"

    exit_code = cli.main(["scan", MINIMAL_REPO, "-o", str(out)])

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    stored = store.get_scan(store.list_scans()[0].id)
    assert stored is not None
    assert out.read_text(encoding="utf-8") == stored.cbom_json


def test_scan_records_the_kind_and_system(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["scan", "quantumbank:1.4", "--kind", "image", "--system", "ledger"])

    capsys.readouterr()
    scan = store.list_scans()[0]
    assert scan.target_kind == "image"
    assert scan.target_ref == "quantumbank:1.4"
    assert scan.target_system == "ledger"


def test_an_unknown_kind_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.main(["scan", "/srv/x", "--kind", "teapot"])


# --------------------------------------------------------------------------
# scanner selection
# --------------------------------------------------------------------------


def test_list_scanners_prints_the_registered_ids(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["--list-scanners"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.split() == ["container", "source"]
    # Nothing was scanned.
    assert store.list_scans() == []


def test_scanner_flag_selects_a_subset(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["scan", MINIMAL_REPO, "--scanner", "source"])

    document = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(document["components"]) == MINIMAL_COMPONENTS


def test_scanner_flag_is_repeatable(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(
        ["scan", MINIMAL_REPO, "--scanner", "source", "--scanner", "source"]
    )

    document = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    # Asking twice must not scan twice.
    assert len(document["components"]) == MINIMAL_COMPONENTS


def test_an_unknown_scanner_id_fails_with_a_useful_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["scan", MINIMAL_REPO, "--scanner", "nope"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "nope" in captured.err
    assert "source" in captured.err
    assert store.list_scans() == []


def test_no_command_and_no_flag_is_a_usage_error() -> None:
    with pytest.raises(SystemExit):
        cli.main([])
