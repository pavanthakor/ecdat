"""Self-describing, re-runnable scan rows (ADR-0016).

Three things the store could not previously say, each of which made a stored
scan un-reproducible:

* **what ran** -- ``scanners_ran``. "Was this estate ever scanned for binaries,
  or does it just have no binary findings?" was unanswerable from the database,
  and the two states looked identical in the dashboard. The distinction that
  carries the answer is NULL (we do not know) versus ``[]`` (we know: nothing),
  and it is tested here because a column that collapses them is worse than no
  column at all -- it looks like an answer.
* **in what context** -- ``sector``, ``exposure``, ``z_years``. Without these a
  fix pass fell back to ``other``/``unknown``, which is the PERMISSIVE
  direction: a fix would be judged more leniently than the scan that found the
  problem, and a fix introducing a Critical could be accepted because the
  context that made it Critical was forgotten.
* **what the verdict was** -- ``band_counts``/``max_score`` and friends, so a
  scan list does not re-parse every stored document to draw a bar chart.

And one thing it must never do: **amend history.** A fix pass and a rescore
write NEW rows linked by ``parent_scan_id``; the parent's bytes are immutable.
That is the same refusal ADR-0015 makes about the filesystem, applied to the
database.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

import cli
from core import registry, store
from core.orchestrator import run_fix, run_rescore, run_scan
from core.scanner import Exposure, ScanContext, Sector, Target
from scanners.config import ConfigScanner

KNOWLEDGE_DIR = Path("knowledge")
FIXTURE = Path("testdata/fixit_fixtures/nginx_weak")

CBOM = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}\n'

#: The scan context the parent row must hand down. Deliberately NOT the
#: permissive defaults, so a fallback to `other`/`unknown` is visible.
PARENT_SECTOR: Sector = "bfsi"
PARENT_EXPOSURE: Exposure = "internet"
PARENT_Z_YEARS = 7


@pytest.fixture(autouse=True)
def _isolated_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    yield


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path / "scratch")


def fixture_target(root: Path | str = FIXTURE) -> Target:
    return Target(
        kind="repo",
        ref=str(root),
        system="quantumbank",
        data_class="pii",
        sector=PARENT_SECTOR,
        exposure=PARENT_EXPOSURE,
    )


def parent_scan(context: ScanContext) -> str:
    """A real, fully-contextualised scan of the nginx fixture."""
    return run_scan(
        fixture_target(),
        [ConfigScanner()],
        context,
        z_years=PARENT_Z_YEARS,
    )


def scores_of(cbom_json: str) -> dict[str, str]:
    """``component name -> ecdat:score``, for comparing two scorings."""
    scores = {}
    for component in json.loads(cbom_json).get("components", []):
        for prop in component.get("properties", []):
            if prop["name"] == "ecdat:score":
                scores[component["name"]] = prop["value"]
    return scores


# ---------------------------------------------------------------------------
# scanners_ran: the NULL / empty distinction
# ---------------------------------------------------------------------------


def test_scanners_ran_round_trips() -> None:
    ran = [{"id": "config"}, {"id": "source", "version": "1.176.1"}]

    scan = store.get_scan(store.save_scan(fixture_target(), CBOM, scanners_ran=ran))

    assert scan is not None
    assert scan.scanners_ran == ran


def test_an_unknown_scanner_set_and_a_known_empty_one_are_distinguishable() -> None:
    """NULL means "we cannot say"; [] means "we can, and it was none".

    Collapsing these is the specific failure this column exists to prevent: an
    estate never scanned for binaries and an estate with no binary findings are
    different facts, and a dashboard that renders them the same is lying.
    """
    unknown = store.get_scan(store.save_scan(fixture_target(), CBOM))
    known_empty = store.get_scan(
        store.save_scan(fixture_target(), CBOM, scanners_ran=[])
    )

    assert unknown is not None
    assert known_empty is not None
    assert unknown.scanners_ran is None
    assert known_empty.scanners_ran == []
    assert unknown.scanners_ran != known_empty.scanners_ran


def test_a_real_scan_records_which_scanners_ran(context: ScanContext) -> None:
    scan = store.get_scan(parent_scan(context))

    assert scan is not None
    assert scan.scanners_ran is not None
    assert [entry["id"] for entry in scan.scanners_ran] == ["config"]
    # The question the punch-list asked: was this ever scanned for source?
    assert "source" not in [entry["id"] for entry in scan.scanners_ran]


# ---------------------------------------------------------------------------
# The scoring context on the row
# ---------------------------------------------------------------------------


def test_sector_exposure_and_z_years_round_trip(context: ScanContext) -> None:
    scan = store.get_scan(parent_scan(context))

    assert scan is not None
    assert scan.sector == PARENT_SECTOR
    assert scan.exposure == PARENT_EXPOSURE
    assert scan.z_years == PARENT_Z_YEARS


def test_the_denormalised_summary_matches_the_stored_document(
    context: ScanContext,
) -> None:
    from core.summary import summarise

    scan = store.get_scan(parent_scan(context))

    assert scan is not None
    expected = summarise(json.loads(scan.cbom_json))
    assert scan.band_counts == expected.band_counts
    assert scan.max_score == expected.max_score
    assert scan.drift_counts == expected.drift_counts
    assert scan.coverage_gaps == expected.coverage_gaps


# ---------------------------------------------------------------------------
# FIX-BACK: a new linked row, and an immutable parent
# ---------------------------------------------------------------------------


def test_a_fix_pass_creates_a_linked_row_and_leaves_the_parent_untouched(
    context: ScanContext,
) -> None:
    parent_id = parent_scan(context)
    before = store.get_scan(parent_id)
    assert before is not None
    parent_bytes = before.cbom_json

    result = run_fix(parent_id, [ConfigScanner()], context)

    child = store.get_scan(result.scan_id)
    assert child is not None
    assert child.kind == store.KIND_FIX
    assert child.parent_scan_id == parent_id
    assert child.id != parent_id

    after = store.get_scan(parent_id)
    assert after is not None
    # Byte-identical: the same refusal ADR-0015 makes about the filesystem.
    assert after.cbom_json == parent_bytes
    assert after.kind == store.KIND_SCAN
    assert after.parent_scan_id is None


def test_the_fix_row_carries_the_verified_diff(context: ScanContext) -> None:
    parent_id = parent_scan(context)

    result = run_fix(parent_id, [ConfigScanner()], context)
    child = store.get_scan(result.scan_id)

    assert child is not None
    properties = [
        prop
        for component in json.loads(child.cbom_json)["components"]
        for prop in component.get("properties", [])
    ]
    names = {p["name"] for p in properties}
    assert "ecdat:fix:template" in names
    assert "ecdat:fix:diff" in names
    diff = next(p["value"] for p in properties if p["name"] == "ecdat:fix:diff")
    assert "ssl_protocols       TLSv1.3;" in diff


def test_a_fix_pass_records_that_no_new_scan_context_was_invented(
    context: ScanContext,
) -> None:
    """The fix row inherits the parent's context, so it is reproducible too."""
    parent_id = parent_scan(context)

    result = run_fix(parent_id, [ConfigScanner()], context)
    child = store.get_scan(result.scan_id)

    assert child is not None
    assert child.sector == PARENT_SECTOR
    assert child.exposure == PARENT_EXPOSURE
    assert child.z_years == PARENT_Z_YEARS


def test_ecdat_fix_with_no_flags_reads_the_context_from_the_parent_row(
    context: ScanContext, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE gap this slice closes: no flags must not mean permissive defaults.

    `other`/`unknown` score lower than `bfsi`/`internet`, so a fix run that
    quietly fell back to them would judge an introduced finding more leniently
    than the scan that found the original problem.
    """
    parent_id = parent_scan(context)
    capsys.readouterr()

    exit_code = cli.main(["fix", parent_id, "--scanner", "config"])
    capsys.readouterr()

    assert exit_code == 0
    (child,) = [s for s in store.list_scans() if s.parent_scan_id == parent_id]
    assert child.sector == PARENT_SECTOR, "fell back to the permissive default"
    assert child.exposure == PARENT_EXPOSURE, "fell back to the permissive default"
    assert child.z_years == PARENT_Z_YEARS


def test_ecdat_fix_scores_with_the_parents_context_not_the_flag_default(
    context: ScanContext,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stronger than the row check: the TARGET handed to the fix engine."""
    import core.orchestrator as orchestrator

    parent_id = parent_scan(context)
    capsys.readouterr()

    seen: list[Target] = []
    real = orchestrator.propose_fixes

    def spy(findings: Any, target: Target, **kwargs: Any) -> Any:
        seen.append(target)
        return real(findings, target, **kwargs)

    monkeypatch.setattr(orchestrator, "propose_fixes", spy)
    cli.main(["fix", parent_id, "--scanner", "config"])
    capsys.readouterr()

    assert len(seen) == 1
    assert seen[0].sector == PARENT_SECTOR
    assert seen[0].exposure == PARENT_EXPOSURE


def test_an_explicit_flag_still_overrides_the_parents_context(
    context: ScanContext, capsys: pytest.CaptureFixture[str]
) -> None:
    parent_id = parent_scan(context)
    capsys.readouterr()

    cli.main(["fix", parent_id, "--scanner", "config", "--sector", "power"])
    capsys.readouterr()

    (child,) = [s for s in store.list_scans() if s.parent_scan_id == parent_id]
    assert child.sector == "power"
    # ... and the one that was NOT overridden still comes from the parent.
    assert child.exposure == PARENT_EXPOSURE


def test_a_fix_pass_on_an_old_row_without_context_uses_the_flag_defaults(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A row that genuinely has no context is the only time defaults apply."""
    parent_id = store.save_scan(Target(kind="repo", ref=str(FIXTURE)), CBOM)
    capsys.readouterr()

    cli.main(["fix", parent_id, "--scanner", "config"])
    capsys.readouterr()

    (child,) = [s for s in store.list_scans() if s.parent_scan_id == parent_id]
    assert child.sector == "other"
    assert child.exposure == "unknown"


# ---------------------------------------------------------------------------
# RESCORE: new scores over the same bytes, without re-scanning
# ---------------------------------------------------------------------------


def test_rescore_changes_scores_without_running_any_scanner(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Mosca slider: a different CRQC horizon over the SAME stored CBOM."""
    from core.normalise import normalise
    from tests.factories import golden_findings

    target = Target(
        kind="repo",
        ref="/srv/quantumbank",
        system="quantumbank",
        data_class="pii",
        sector=PARENT_SECTOR,
        exposure=PARENT_EXPOSURE,
    )
    _, cbom = normalise(golden_findings(), target)
    parent_id = store.save_scan(target, cbom, z_years=3)

    ran: list[str] = []

    def spy(self: Any, target_: Target, context_: ScanContext) -> Any:  # noqa: ARG001
        ran.append(self.id)
        return iter(())

    for scanner in registry.get_scanners():
        monkeypatch.setattr(type(scanner), "scan", spy)

    parent = store.get_scan(parent_id)
    assert parent is not None
    rescored_id = run_rescore(parent_id, context, z_years=30)
    rescored = store.get_scan(rescored_id)

    assert rescored is not None
    assert ran == [], "a rescore must not re-run any scanner"
    assert rescored.kind == store.KIND_RESCORE
    assert rescored.parent_scan_id == parent_id
    assert rescored.z_years == 30
    assert scores_of(rescored.cbom_json) != scores_of(parent.cbom_json)


def test_rescore_leaves_the_parent_row_byte_identical(context: ScanContext) -> None:
    parent_id = parent_scan(context)
    before = store.get_scan(parent_id)
    assert before is not None
    parent_bytes = before.cbom_json

    run_rescore(parent_id, context, z_years=30)

    after = store.get_scan(parent_id)
    assert after is not None
    assert after.cbom_json == parent_bytes
    assert after.z_years == PARENT_Z_YEARS


def test_rescore_records_that_no_scanner_ran(context: ScanContext) -> None:
    """`[]`, not NULL: we know exactly what ran, and it was nothing."""
    rescored_id = run_rescore(parent_scan(context), context)
    rescored = store.get_scan(rescored_id)

    assert rescored is not None
    assert rescored.scanners_ran == []


def test_rescore_without_z_years_reuses_the_parents_horizon(
    context: ScanContext,
) -> None:
    rescored = store.get_scan(run_rescore(parent_scan(context), context))

    assert rescored is not None
    assert rescored.z_years == PARENT_Z_YEARS


def test_ecdat_rescore_writes_a_linked_row(
    context: ScanContext, capsys: pytest.CaptureFixture[str]
) -> None:
    parent_id = parent_scan(context)
    capsys.readouterr()

    exit_code = cli.main(["rescore", parent_id, "--z-years", "30"])
    captured = capsys.readouterr()

    assert exit_code == 0
    (child,) = [s for s in store.list_scans() if s.parent_scan_id == parent_id]
    assert child.kind == store.KIND_RESCORE
    assert child.z_years == 30
    assert child.id in captured.out


def test_ecdat_rescore_on_an_unknown_scan_fails_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["rescore", "no-such-scan"]) == 2
    assert "no-such-scan" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# ADDITIVE MIGRATION
# ---------------------------------------------------------------------------

OLD_SCHEMA = """
CREATE TABLE scans (
    id VARCHAR(36) NOT NULL,
    target_kind VARCHAR(32) NOT NULL,
    target_ref VARCHAR(2048) NOT NULL,
    target_system VARCHAR(255),
    target_data_class VARCHAR(255),
    created_at DATETIME NOT NULL,
    cbom_json TEXT NOT NULL,
    component_count INTEGER NOT NULL,
    PRIMARY KEY (id)
)
"""


def build_old_database(path: Path, cbom: str = CBOM) -> None:
    """A database written by the PREVIOUS schema, with a row in it."""
    connection = sqlite3.connect(path)
    with connection:
        connection.execute(OLD_SCHEMA)
        connection.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "old-row-1",
                "repo",
                "/srv/legacy",
                "legacy",
                "pii",
                "2026-01-01 00:00:00.000000",
                cbom,
                len(json.loads(cbom).get("components", [])),
            ),
        )
    connection.close()


def test_an_old_schema_database_gains_the_new_columns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "old.db"
    build_old_database(database)
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()

    store.init_db()

    with store.get_engine().connect() as connection:
        columns = {
            row[1] for row in connection.execute(text("PRAGMA table_info(scans)"))
        }
    for column in (
        "scanners_ran",
        "sector",
        "exposure",
        "z_years",
        "band_counts",
        "max_score",
        "drift_counts",
        "coverage_gaps",
        "parent_scan_id",
        "kind",
    ):
        assert column in columns, f"{column} was not added by the migration"


def test_an_old_row_survives_the_migration_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "old.db"
    build_old_database(database)
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()

    scan = store.get_scan("old-row-1")

    assert scan is not None
    assert scan.cbom_json == CBOM  # byte-identical, no data loss
    assert scan.target_ref == "/srv/legacy"
    assert scan.target_system == "legacy"
    assert scan.component_count == 1
    # A migrated row is an ordinary scan, not an orphaned fix.
    assert scan.kind == store.KIND_SCAN
    assert scan.parent_scan_id is None
    # And it honestly reports that it does not know what ran.
    assert scan.scanners_ran is None
    assert scan.sector is None
    assert scan.exposure is None
    assert scan.z_years is None


def test_the_migration_backfills_the_verdict_summary_for_old_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The summary is derivable from the stored bytes, so it is filled in.

    The scan CONTEXT is not derivable and stays NULL -- the migration
    reconstructs what it can prove and refuses to invent the rest.
    """
    from core.summary import summarise

    scored = (
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":['
        '{"name":"RSA-2048","properties":['
        '{"name":"ecdat:band","value":"Critical"},'
        '{"name":"ecdat:score","value":"98"}]}]}\n'
    )
    database = tmp_path / "old.db"
    build_old_database(database, cbom=scored)
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()

    scan = store.get_scan("old-row-1")

    assert scan is not None
    expected = summarise(json.loads(scored))
    assert scan.band_counts == expected.band_counts
    assert scan.max_score == 98
    assert scan.sector is None  # not derivable, not invented


def test_the_migration_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "old.db"
    build_old_database(database)
    monkeypatch.setenv(store.ENV_DB_PATH, str(database))
    store.reset_engines()

    store.init_db()
    store.init_db()
    store.reset_engines()
    store.init_db()

    scan = store.get_scan("old-row-1")
    assert scan is not None
    assert scan.cbom_json == CBOM


# ---------------------------------------------------------------------------
# Determinism through the new paths
# ---------------------------------------------------------------------------


def test_a_rescore_is_byte_identical_when_repeated(context: ScanContext) -> None:
    parent_id = parent_scan(context)

    first = store.get_scan(run_rescore(parent_id, context, z_years=30))
    second = store.get_scan(run_rescore(parent_id, context, z_years=30))

    assert first is not None
    assert second is not None
    assert first.cbom_json == second.cbom_json
    assert first.id != second.id


def test_a_fix_pass_is_byte_identical_when_repeated(context: ScanContext) -> None:
    parent_id = parent_scan(context)

    first = store.get_scan(run_fix(parent_id, [ConfigScanner()], context).scan_id)
    second = store.get_scan(run_fix(parent_id, [ConfigScanner()], context).scan_id)

    assert first is not None
    assert second is not None
    assert first.cbom_json == second.cbom_json


# ---------------------------------------------------------------------------
# MUTATION-STYLE NEGATIVES
# ---------------------------------------------------------------------------


def test_mutation_amending_the_parent_row_instead_of_linking_is_caught(
    context: ScanContext,
) -> None:
    """Prove the immutability test would fail if save_fix_result amended.

    Written as the mutation itself rather than a monkeypatch, because the
    thing being defended is a WRITE, and the honest way to show a guard is
    load-bearing is to perform the write the guard prevents.
    """
    parent_id = parent_scan(context)
    before = store.get_scan(parent_id)
    assert before is not None
    parent_bytes = before.cbom_json

    # The mutation: amend the parent in place, exactly as a naive fix-back
    # would have done.
    with store.get_engine().begin() as connection:
        connection.execute(
            text("UPDATE scans SET cbom_json = :doc WHERE id = :id"),
            {"doc": parent_bytes + " ", "id": parent_id},
        )

    after = store.get_scan(parent_id)
    assert after is not None
    assert after.cbom_json != parent_bytes, (
        "if this passes, the immutability assertion in the fix-back test is "
        "genuinely detecting a rewritten parent rather than always passing"
    )


def test_mutation_ignoring_the_parent_context_reintroduces_the_lenient_default(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disable the inheritance and the permissive default comes straight back."""
    parent_id = parent_scan(context)

    def forget_the_parent(
        scan: store.Scan,  # noqa: ARG001
        sector: str | None,
        exposure: str | None,
        z_years: int | None,
    ) -> store.StoredContext:
        return store.StoredContext(
            sector=sector or "other",
            exposure=exposure or "unknown",
            z_years=z_years or 11,
        )

    monkeypatch.setattr(cli, "_inherited_context", forget_the_parent)
    cli.main(["fix", parent_id, "--scanner", "config"])

    (child,) = [s for s in store.list_scans() if s.parent_scan_id == parent_id]
    assert child.sector == "other", (
        "context inheritance is the ONLY thing keeping a fix from being judged "
        "more leniently than the scan that found the problem"
    )
    assert child.exposure == "unknown"
