"""Tests for the SQLite scan store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import store
from core.scanner import Target
from tests.factories import golden_findings, golden_target

CBOM = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}\n'


def test_save_scan_then_get_scan_returns_the_same_cbom() -> None:
    target = golden_target()

    scan_id = store.save_scan(target, CBOM)
    scan = store.get_scan(scan_id)

    assert scan is not None
    assert scan.id == scan_id
    assert scan.cbom_json == CBOM
    assert scan.target_kind == target.kind
    assert scan.target_ref == target.ref
    assert scan.target_system == target.system
    assert scan.target_data_class == target.data_class


def test_component_count_is_derived_from_the_stored_document() -> None:
    findings_count = len(json.loads(CBOM)["components"])

    scan = store.get_scan(store.save_scan(golden_target(), CBOM))

    assert scan is not None
    assert scan.component_count == findings_count


def test_get_scan_of_an_unknown_id_is_none() -> None:
    assert store.get_scan("no-such-scan") is None


def test_scan_ids_are_unique_per_save() -> None:
    first = store.save_scan(golden_target(), CBOM)
    second = store.save_scan(golden_target(), CBOM)

    assert first != second


def test_list_scans_is_newest_first() -> None:
    ids = [store.save_scan(golden_target(), CBOM) for _ in range(3)]

    listed = [s.id for s in store.list_scans()]

    assert listed == list(reversed(ids))


def test_list_scans_is_empty_on_a_fresh_database() -> None:
    assert store.list_scans() == []


def test_created_at_is_timezone_aware_utc() -> None:
    scan = store.get_scan(store.save_scan(golden_target(), CBOM))

    assert scan is not None
    assert scan.created_at.tzinfo is not None
    assert scan.created_at.utcoffset() is not None
    assert scan.created_at.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def test_the_store_writes_where_ecdat_db_points(isolated_database: Path) -> None:
    store.save_scan(golden_target(), CBOM)

    assert isolated_database.exists()
    assert not Path("ecdat.db").exists()


def test_a_target_without_optional_tags_round_trips() -> None:
    target = Target(kind="image", ref="quantumbank:1.4")

    scan = store.get_scan(store.save_scan(target, CBOM))

    assert scan is not None
    assert scan.target_system is None
    assert scan.target_data_class is None


def test_a_real_cbom_survives_the_round_trip_byte_for_byte() -> None:
    from core.normalise import normalise

    _, cbom_json = normalise(golden_findings(), golden_target())

    scan = store.get_scan(store.save_scan(golden_target(), cbom_json))

    assert scan is not None
    assert scan.cbom_json == cbom_json


def test_saving_a_document_that_is_not_json_is_rejected() -> None:
    # component_count is derived from the document, so a non-document is a bug
    # in the caller, not something to persist with a made-up count.
    with pytest.raises(ValueError):
        store.save_scan(golden_target(), "not json at all")
