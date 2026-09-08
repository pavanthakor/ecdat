"""CLI tests: `ecdat scan <ref>`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cli
from core import store


def test_scan_writes_the_cbom_to_stdout_and_the_summary_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["scan", "/srv/quantumbank"])

    captured = capsys.readouterr()
    assert exit_code == 0
    document = json.loads(captured.out)
    assert document["specVersion"] == "1.6"
    assert len(document["components"]) == 1
    # The summary goes to stderr so `ecdat scan . > cbom.json` stays usable.
    assert "component_count=1" in captured.err
    scan_id = store.list_scans()[0].id
    assert scan_id in captured.err


def test_scan_writes_to_a_file_with_dash_o(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "cbom.json"

    exit_code = cli.main(["scan", "/srv/quantumbank", "-o", str(out)])

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
