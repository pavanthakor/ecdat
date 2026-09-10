"""Three views into ONE CBOM, so drift is a product feature (ADR-0019).

Until now `run_scan` took one target of one kind, and the correlator -- the
whole of Pillar 2 -- only ever saw one view at a time. Drift existed solely in
`kpi/harness.py`, which merged three separate scans by hand to make the
comparison possible. The dashboard's drift column was therefore always empty,
not because the estate agreed but because nothing ever put the views in the
same document.

`scan_system` is that missing entry point. A manifest names one system's
targets; every applicable scanner runs over every target; the findings become
ONE CBOM; and the correlator runs over it with all three views present.

The cross-view non-merge from ADR-0002 still holds and is asserted here: a
declared X25519MLKEM768 and an observed x25519 stay two components. Merging
them would destroy exactly the disagreement drift detection exists to find.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

import cli
from api.app import app
from core import store
from core.scanner import ScanContext
from core.system import (
    ManifestError,
    TargetUnreadableError,
    load_manifest,
    parse_manifest,
    scan_system,
)

MANIFEST = Path("testdata/quantumbank/system.yaml")
SPOOL = Path("testdata/quantumbank/spool")
KNOWLEDGE = Path("knowledge")


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path / "scratch")


def stored(scan_id: str) -> dict[str, Any]:
    record = store.get_scan(scan_id)
    assert record is not None
    document: dict[str, Any] = json.loads(record.cbom_json)
    return document


def views_in(document: dict[str, Any]) -> set[str]:
    return {
        prop["value"]
        for component in document["components"]
        for prop in component.get("properties", [])
        if prop["name"] == "ecdat:view"
    }


def drifts_in(document: dict[str, Any]) -> list[dict[str, str]]:
    """Every drift on every component, flattened, in document order."""
    found: list[dict[str, str]] = []
    for component in document["components"]:
        values: dict[str, list[str]] = {}
        for prop in component.get("properties", []):
            values.setdefault(prop["name"], []).append(prop["value"])
        for index, kind in enumerate(values.get("ecdat:drift:kind", [])):
            found.append(
                {
                    "kind": kind,
                    "component": component["name"],
                    "declared": values.get("ecdat:drift:declared", [""])[index],
                    "observed": values.get("ecdat:drift:observed", [""])[index],
                    "endpoint": next(
                        (
                            p["value"]
                            for p in component["properties"]
                            if p["name"] == "ecdat:param:endpoint"
                        ),
                        "",
                    ),
                }
            )
    return found


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


def test_the_committed_manifest_describes_the_quantumbank_system() -> None:
    manifest = load_manifest(MANIFEST)

    assert manifest.system == "quantumbank"
    assert manifest.sector == "bfsi"
    assert manifest.exposure == "internet"
    assert manifest.data_class == "Personal"
    assert {t.kind for t in manifest.targets} == {"repo", "image", "spool"}


def test_an_unknown_target_kind_is_refused_and_the_error_names_the_target() -> None:
    """A typo'd kind must not silently drop a whole view from the scan."""
    body = {
        "system": "x",
        "targets": [{"kind": "repo", "ref": "a"}, {"kind": "contianer", "ref": "b"}],
    }

    with pytest.raises(ManifestError) as raised:
        parse_manifest(body, source=Path("m.yaml"))

    assert "contianer" in str(raised.value)
    assert "b" in str(raised.value)


def test_a_target_without_a_ref_is_refused_naming_its_position() -> None:
    body = {"system": "x", "targets": [{"kind": "repo"}]}

    with pytest.raises(ManifestError) as raised:
        parse_manifest(body, source=Path("m.yaml"))

    assert "ref" in str(raised.value)


def test_a_manifest_with_no_targets_is_refused() -> None:
    with pytest.raises(ManifestError, match="targets"):
        parse_manifest({"system": "x", "targets": []}, source=Path("m.yaml"))


def test_a_manifest_without_a_system_name_is_refused() -> None:
    with pytest.raises(ManifestError, match="system"):
        parse_manifest(
            {"targets": [{"kind": "repo", "ref": "a"}]}, source=Path("m.yaml")
        )


def test_an_unknown_sector_is_refused_rather_than_defaulted() -> None:
    """Silently falling back to `other` would under-score a CII estate."""
    body = {
        "system": "x",
        "sector": "banking",
        "targets": [{"kind": "repo", "ref": "a"}],
    }

    with pytest.raises(ManifestError, match="sector"):
        parse_manifest(body, source=Path("m.yaml"))


# ---------------------------------------------------------------------------
# One CBOM, three views
# ---------------------------------------------------------------------------


def test_scan_system_produces_one_cbom_carrying_all_three_views(
    context: ScanContext,
) -> None:
    document = stored(scan_system(load_manifest(MANIFEST), context))

    assert views_in(document) == {"declared", "shipped", "observed"}


def test_the_three_views_stay_distinct_components(context: ScanContext) -> None:
    """ADR-0002: merging the views would destroy the disagreement.

    The declared hybrid group and the observed classical one are the same
    endpoint's key agreement seen from two sides. They must remain two
    components, or there is nothing left for the correlator to compare.
    """
    document = stored(scan_system(load_manifest(MANIFEST), context))

    by_name: dict[str, set[str]] = {}
    for component in document["components"]:
        view = next(
            p["value"] for p in component["properties"] if p["name"] == "ecdat:view"
        )
        by_name.setdefault(component["name"], set()).add(view)

    assert "X25519MLKEM768" in by_name
    assert "x25519" in by_name
    assert by_name["X25519MLKEM768"] == {"declared"}
    assert by_name["x25519"] == {"observed"}

    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs)), "a merged document must not repeat a bom-ref"


def test_the_unified_document_is_still_a_valid_cbom(context: ScanContext) -> None:
    from core.normalise import validate_cbom_json

    record = store.get_scan(scan_system(load_manifest(MANIFEST), context))
    assert record is not None

    validate_cbom_json(record.cbom_json)


@pytest.mark.validation
def test_the_document_names_the_system_it_describes(context: ScanContext) -> None:
    document = stored(scan_system(load_manifest(MANIFEST), context))

    assert document["metadata"]["component"]["name"] == "quantumbank"


# ---------------------------------------------------------------------------
# THE POINT: drift, in a stored scan
# ---------------------------------------------------------------------------


def test_r1_shipped_cannot_do_declared_drift_appears(context: ScanContext) -> None:
    """The headline: the config promises a hybrid group the image cannot do.

    payments:443 declares X25519MLKEM768; the shipped image carries OpenSSL
    3.0.2, whose PQC floor (knowledge/libraries.yaml, verified) is 3.5.0. A
    single-target scan can never see this -- it needs the declared and shipped
    views in one document.
    """
    document = stored(scan_system(load_manifest(MANIFEST), context))

    r1 = [d for d in drifts_in(document) if d["kind"] == "shipped-cannot-do-declared"]

    assert r1, f"no R1 drift; found {[d['kind'] for d in drifts_in(document)]}"
    payments = [d for d in r1 if "payments" in d["endpoint"]]
    assert payments, f"R1 fired but not on payments: {r1}"
    assert payments[0]["declared"] == "X25519MLKEM768"
    assert "3.0.2" in payments[0]["observed"]


def test_r2_declared_pqc_observed_classical_drift_appears(
    context: ScanContext,
) -> None:
    """The committed spool carries an observed x25519 on the payments nginx."""
    document = stored(scan_system(load_manifest(MANIFEST), context))

    r2 = [
        d for d in drifts_in(document) if d["kind"] == "declared-pqc-observed-classical"
    ]

    assert r2, f"no R2 drift; found {[d['kind'] for d in drifts_in(document)]}"
    assert any(d["declared"] == "X25519MLKEM768" for d in r2)
    assert any("x25519" in d["observed"] for d in r2)


def test_a_single_target_scan_still_finds_no_drift(context: ScanContext) -> None:
    """The control. Drift is a property of the UNION, not of the scanner.

    If this ever starts passing with drift, the correlator has begun inventing
    comparisons out of one view.
    """
    from core import registry
    from core.orchestrator import run_scan
    from core.scanner import Target

    target = Target(
        kind="repo",
        ref="testdata/quantumbank",
        system="quantumbank",
        data_class="Personal",
        sector="bfsi",
        exposure="internet",
    )
    document = stored(run_scan(target, registry.get_scanners(["config"]), context))

    assert drifts_in(document) == []


# ---------------------------------------------------------------------------
# The scan row
# ---------------------------------------------------------------------------


def test_the_scan_row_records_every_scanner_that_ran_across_the_targets(
    context: ScanContext,
) -> None:
    record = store.get_scan(scan_system(load_manifest(MANIFEST), context))

    assert record is not None
    assert record.scanners_ran is not None
    # `deps` is here because it supports repo targets and therefore RAN --
    # QuantumBank simply declares no dependency manifests, so it found nothing.
    # "Ran and found nothing" and "never looked" are different answers, and
    # scanners_ran is the column that keeps them apart (ADR-0016).
    assert {entry["id"] for entry in record.scanners_ran} == {
        "config",
        "container",
        "deps",
        "runtime-spool",
        "source",
    }


def test_the_scan_row_carries_the_system_context(context: ScanContext) -> None:
    record = store.get_scan(scan_system(load_manifest(MANIFEST), context))

    assert record is not None
    assert record.kind == store.KIND_SCAN
    assert record.parent_scan_id is None
    assert record.target_system == "quantumbank"
    assert record.sector == "bfsi"
    assert record.exposure == "internet"
    assert record.target_data_class == "Personal"


def test_the_summary_row_reports_the_drift_the_dashboard_will_show(
    context: ScanContext,
) -> None:
    """The end the whole slice exists for: a non-empty DRIFT metric."""
    record = store.get_scan(scan_system(load_manifest(MANIFEST), context))

    assert record is not None
    assert record.drift_counts
    assert sum(record.drift_counts.values()) > 0


# ---------------------------------------------------------------------------
# Failure discipline
# ---------------------------------------------------------------------------


def test_an_unreadable_target_fails_loud_and_names_it(
    tmp_path: Path, context: ScanContext
) -> None:
    """A missing target is an operator error, not a thinner inventory.

    Degrading to "we scanned what we could" would produce a CBOM that looks
    like an inventory and is missing a whole view, with nothing in the document
    to say so.
    """
    body = {
        "system": "quantumbank",
        "targets": [
            {"kind": "repo", "ref": "testdata/quantumbank"},
            {"kind": "image", "ref": "testdata/quantumbank/images/nope.tar"},
        ],
    }
    manifest = parse_manifest(body, source=tmp_path / "m.yaml")

    with pytest.raises(TargetUnreadableError) as raised:
        scan_system(manifest, context)

    assert "nope.tar" in str(raised.value)


def test_a_scanner_finding_nothing_on_one_target_does_not_abort_the_others(
    tmp_path: Path, context: ScanContext
) -> None:
    """An empty directory contributes nothing and stops nothing."""
    empty = tmp_path / "empty-service"
    empty.mkdir()
    body = {
        "system": "quantumbank",
        "sector": "bfsi",
        "exposure": "internet",
        "data_class": "Personal",
        "targets": [
            {"kind": "directory", "ref": str(empty)},
            {"kind": "repo", "ref": "testdata/quantumbank"},
            {"kind": "image", "ref": "testdata/quantumbank/images/payments.tar"},
            {"kind": "spool", "ref": "testdata/quantumbank/spool"},
        ],
    }

    manifest = parse_manifest(body, source=tmp_path / "m.yaml")
    document = stored(scan_system(manifest, context))

    assert views_in(document) == {"declared", "shipped", "observed"}
    assert drifts_in(document)


def test_a_broken_scanner_degrades_the_scan_rather_than_ending_it(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same plugin-isolation discipline as the orchestrator (ADR-0003)."""
    from scanners.container import ContainerScanner

    def explode(_self: ContainerScanner, _target: Any, _ctx: Any) -> Any:
        raise RuntimeError("simulated container scanner failure")

    monkeypatch.setattr(ContainerScanner, "scan", explode)

    document = stored(scan_system(load_manifest(MANIFEST), context))

    # The shipped view is gone -- that scanner produced nothing -- but the
    # declared and observed views still landed.
    assert "declared" in views_in(document)
    assert "observed" in views_in(document)


# ---------------------------------------------------------------------------
# Determinism, and the committed fixture
# ---------------------------------------------------------------------------


def test_the_same_manifest_produces_a_byte_identical_cbom(
    context: ScanContext, tmp_path: Path
) -> None:
    manifest = load_manifest(MANIFEST)
    second = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path / "scratch-2")

    first = store.get_scan(scan_system(manifest, context))
    again = store.get_scan(scan_system(manifest, second))

    assert first is not None
    assert again is not None
    assert first.cbom_json == again.cbom_json
    assert first.id != again.id


def test_the_committed_spool_fixture_is_never_consumed(context: ScanContext) -> None:
    """The spool scanner MOVES what it ingests (ADR-0010). Not our fixture.

    A system scan that ate its own committed evidence would work exactly once,
    and the second run would silently lose the observed view.
    """
    before = sorted(p.name for p in SPOOL.iterdir())

    scan_system(load_manifest(MANIFEST), context)

    assert sorted(p.name for p in SPOOL.iterdir()) == before
    assert not (SPOOL / "consumed").exists()


# ---------------------------------------------------------------------------
# CLI and API
# ---------------------------------------------------------------------------


def test_ecdat_scan_system_prints_the_scan_id_and_the_drift_count(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))

    exit_code = cli.main(["scan-system", str(MANIFEST)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "scan_id=" in captured.err or "scan_id=" in captured.out
    output = captured.out + captured.err
    assert "drift_count=" in output
    assert "drift_count=0" not in output


def test_ecdat_scan_system_on_a_missing_manifest_fails_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["scan-system", "no/such/manifest.yaml"]) == 2
    assert "no/such/manifest.yaml" in capsys.readouterr().err


def test_post_systems_scan_stores_a_three_view_scan_with_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    body = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    with TestClient(app) as client:
        created = client.post("/systems/scan", json=body)
        assert created.status_code == 201, created.text
        scan_id = created.json()["scan_id"]

        summary = client.get(f"/scans/{scan_id}").json()

    # THE END-TO-END CLAIM: the dashboard's DRIFT metric is non-empty and its
    # "Drift only" filter has something to show.
    assert sum(summary["drift_counts"].values()) > 0
    assert summary["component_count"] > 20
    assert summary["sector"] == "bfsi"
    assert {e["id"] for e in summary["scanners_ran"]} == {
        "config",
        "container",
        "deps",
        "runtime-spool",
        "source",
    }


def test_post_systems_scan_rejects_a_bad_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))

    with TestClient(app) as client:
        response = client.post(
            "/systems/scan",
            json={"system": "x", "targets": [{"kind": "nope", "ref": "a"}]},
        )

    assert response.status_code == 400
    assert "nope" in response.text
