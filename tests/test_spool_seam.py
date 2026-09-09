"""The spool seam: observed findings reach the store (ADR-0010).

The runtime agent runs as root and attaches eBPF. The scan path deliberately
does not. Between them sits a directory: the agent writes JSON lines into it and
never speaks to the API, and a scanner reads them back as ordinary Findings.
The filesystem is the trust boundary, and it is the only thing the two
processes share.

What these tests pin:

* **Atomicity.** A half-written file must never be readable as a spool line, so
  the consumer ignores ``.tmp-*`` and reads only completed renames.
* **Garbage does not stop ingest.** The producer is a root process parsing
  kernel buffers; a truncated or malformed line is a question of when, not if.
  One bad line costs one line.
* **Idempotency.** Ingested files move to ``consumed/``; a second scan of the
  same directory finds nothing new. Double-counting an estate's crypto is
  worse than missing it, because it looks like growth.
* **Bad producers stay visible.** A file that yields nothing valid moves to
  ``rejected/`` rather than being deleted -- a silently discarded producer is
  a blind spot nobody knows they have.
* **Three views coexist.** This is the whole point of the seam: it is the
  precondition for the correlator, and ADR-0002's cross-view non-merge has to
  hold once all three views are really in one document.

Root-free throughout: the consumer never probes and never needs privileges.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from core import registry, store
from core.normalise import normalise, validate_cbom_json
from core.orchestrator import run_scan
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from scanners.runtime_spool import (
    CONSUMED_DIR,
    REJECTED_DIR,
    SPOOL_SUFFIXES,
    TEMP_PREFIX,
    RuntimeSpoolScanner,
)


def observed_event(**overrides: Any) -> dict[str, Any]:
    """One line as the agent writes it -- the same dict ``--json`` prints."""
    event: dict[str, Any] = {
        "comm": "openssl",
        "libssl_path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "observed_cipher": None,
        "observed_version": None,
        "phase": "return",
        "pid": 48231,
        "probe": "SSL_do_handshake",
        "retval": 1,
        "timestamp": 68421339115523,
        "tid": 48231,
    }
    event.update(overrides)
    return event


def write_spool_file(directory: Path, name: str, *lines: dict[str, Any] | str) -> Path:
    """Write a completed (already-renamed) spool file."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    body = "\n".join(
        line if isinstance(line, str) else json.dumps(line, sort_keys=True)
        for line in lines
    )
    path.write_text(body + "\n", encoding="utf-8")
    return path


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        knowledge_dir=Path("knowledge"), scratch_dir=tmp_path / "scratch"
    )


def scan_spool(directory: Path, context: ScanContext) -> list[Finding]:
    target = Target(kind="spool", ref=str(directory), system="runtime")
    return list(RuntimeSpoolScanner().scan(target, context))


# --------------------------------------------------------------------------
# Plugin contract and routing
# --------------------------------------------------------------------------


def test_satisfies_the_scanner_protocol() -> None:
    assert isinstance(RuntimeSpoolScanner(), Scanner)


def test_identity_and_view() -> None:
    scanner = RuntimeSpoolScanner()
    assert scanner.id == "runtime-spool"
    assert scanner.view == "observed"


def test_supports_only_spool_targets() -> None:
    scanner = RuntimeSpoolScanner()
    assert scanner.supports(Target(kind="spool", ref="spool-dir"))
    for kind in ("repo", "directory", "image", "host", "endpoint"):
        assert not scanner.supports(Target(kind=kind, ref="x"))


def test_the_other_scanners_decline_a_spool_target() -> None:
    """Routing must be exclusive in both directions, or a spool directory gets
    walked as source code."""
    from scanners.container import ContainerScanner
    from scanners.source import SourceScanner

    spool = Target(kind="spool", ref="spool-dir")
    assert not SourceScanner().supports(spool)
    assert not ContainerScanner().supports(spool)


def test_registered_in_the_registry() -> None:
    assert registry.available_ids() == ["container", "runtime-spool", "source"]
    (scanner,) = registry.get_scanners(["runtime-spool"])
    assert isinstance(scanner, RuntimeSpoolScanner)


# --------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------


def test_a_spooled_event_round_trips_into_an_observed_finding(
    tmp_path: Path, context: ScanContext
) -> None:
    write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())

    (finding,) = scan_spool(tmp_path, context)

    assert finding.view == "observed"
    assert finding.scanner_id == "runtime-spool"
    assert finding.asset_type == "protocol"
    assert finding.algorithm == "TLS"
    assert "pid48231" in finding.evidence.occurrences[0].locator
    assert "probe=SSL_do_handshake" in finding.evidence.occurrences[0].detail


def test_an_enriched_event_round_trips_with_its_cipher(
    tmp_path: Path, context: ScanContext
) -> None:
    """One enriched line yields several artefacts -- see ADR-0011."""
    write_spool_file(
        tmp_path,
        "host-1-2-0.jsonl",
        observed_event(
            observed_version="TLSv1.3",
            observed_cipher="TLS_AES_256_GCM_SHA384",
            observed_group="X25519MLKEM768",
        ),
    )

    findings = scan_spool(tmp_path, context)
    by_algorithm = {f.algorithm: f for f in findings}

    assert by_algorithm["TLS"].params["version"] == "TLSv1.3"
    assert by_algorithm["TLS_AES_256_GCM_SHA384"].primitive == "block-cipher"
    assert by_algorithm["X25519MLKEM768"].primitive == "key-agreement"
    assert by_algorithm["X25519MLKEM768"].params["hybrid"] is True
    assert all(f.scanner_id == "runtime-spool" for f in findings)


def test_several_lines_in_one_file_all_ingest(
    tmp_path: Path, context: ScanContext
) -> None:
    write_spool_file(
        tmp_path,
        "host-1-2-0.jsonl",
        observed_event(pid=1),
        observed_event(pid=2),
        observed_event(pid=3),
    )

    findings = scan_spool(tmp_path, context)

    assert len(findings) == 3
    seen = {f.evidence.occurrences[0].locator.rsplit("pid", 1)[1] for f in findings}
    assert seen == {
        "1",
        "2",
        "3",
    }


def test_blank_lines_are_not_errors(tmp_path: Path, context: ScanContext) -> None:
    path = write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())
    path.write_text("\n" + path.read_text(encoding="utf-8") + "\n\n", encoding="utf-8")

    assert len(scan_spool(tmp_path, context)) == 1


def test_ingest_order_is_deterministic(tmp_path: Path, context: ScanContext) -> None:
    for index in range(5):
        write_spool_file(
            tmp_path, f"host-1-{index}-0.jsonl", observed_event(pid=100 + index)
        )

    first = [f.model_dump() for f in scan_spool(tmp_path, context)]

    for index in range(5):
        write_spool_file(
            tmp_path, f"host-1-{index}-0.jsonl", observed_event(pid=100 + index)
        )
    second = [f.model_dump() for f in scan_spool(tmp_path, context)]

    assert first == second


# --------------------------------------------------------------------------
# Atomicity
# --------------------------------------------------------------------------


def test_a_partial_temp_file_is_not_read(tmp_path: Path, context: ScanContext) -> None:
    """The producer writes .tmp-* then renames. A half-written file must never
    be readable as a spool line."""
    write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event(pid=111))
    partial = tmp_path / f"{TEMP_PREFIX}half-written.jsonl"
    partial.write_text('{"pid": 222, "comm": "openss', encoding="utf-8")

    findings = scan_spool(tmp_path, context)

    assert len(findings) == 1
    assert "pid111" in findings[0].evidence.occurrences[0].locator
    assert partial.exists(), "a temp file must be left alone, not consumed"


def test_only_spool_suffixes_are_read(tmp_path: Path, context: ScanContext) -> None:
    write_spool_file(tmp_path, "good.jsonl", observed_event())
    (tmp_path / "notes.txt").write_text("not a spool file", encoding="utf-8")
    (tmp_path / "archive.tar").write_bytes(b"\x00")

    assert len(scan_spool(tmp_path, context)) == 1
    assert ".jsonl" in SPOOL_SUFFIXES


# --------------------------------------------------------------------------
# Garbage that parses, and garbage that does not
# --------------------------------------------------------------------------


def test_a_truncated_json_line_is_skipped_with_a_reason(
    tmp_path: Path, context: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    write_spool_file(
        tmp_path,
        "mixed.jsonl",
        observed_event(pid=1),
        '{"pid": 2, "comm": "openss',
        observed_event(pid=3),
    )

    findings = scan_spool(tmp_path, context)

    assert len(findings) == 2, "the good lines must still ingest"
    assert caplog.records
    assert any("mixed.jsonl" in r.getMessage() for r in caplog.records)


def test_a_wrong_fields_line_is_skipped(
    tmp_path: Path, context: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    write_spool_file(
        tmp_path,
        "mixed.jsonl",
        observed_event(pid=1),
        observed_event(pid="not-a-pid"),
        {"totally": "unrelated"},
        json.dumps(["a", "list", "not", "an", "object"]),
    )

    findings = scan_spool(tmp_path, context)

    assert len(findings) == 1
    assert caplog.records


def test_a_file_that_yields_nothing_valid_is_rejected_not_deleted(
    tmp_path: Path, context: ScanContext
) -> None:
    """A bad producer must stay visible as evidence."""
    write_spool_file(tmp_path, "all-bad.jsonl", "{not json", '{"nope": 1}')

    assert scan_spool(tmp_path, context) == []

    assert not (tmp_path / "all-bad.jsonl").exists()
    assert (tmp_path / REJECTED_DIR / "all-bad.jsonl").exists()
    assert not (tmp_path / CONSUMED_DIR / "all-bad.jsonl").exists()


def test_a_partly_bad_file_is_still_consumed(
    tmp_path: Path, context: ScanContext
) -> None:
    """One valid line is evidence; the file has done its job."""
    write_spool_file(tmp_path, "mixed.jsonl", observed_event(), "{not json")

    assert len(scan_spool(tmp_path, context)) == 1
    assert (tmp_path / CONSUMED_DIR / "mixed.jsonl").exists()


def test_an_empty_spool_directory_is_not_an_error(
    tmp_path: Path, context: ScanContext
) -> None:
    assert scan_spool(tmp_path, context) == []


def test_a_missing_spool_directory_fails_loudly(context: ScanContext) -> None:
    import scanners.runtime_spool as spool

    with pytest.raises(spool.SpoolUnreadableError, match="does not exist"):
        scan_spool(Path("/no/such/spool/directory"), context)


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------


def test_an_ingested_file_moves_to_consumed(
    tmp_path: Path, context: ScanContext
) -> None:
    write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())

    scan_spool(tmp_path, context)

    assert not (tmp_path / "host-1-2-0.jsonl").exists()
    assert (tmp_path / CONSUMED_DIR / "host-1-2-0.jsonl").exists()


def test_a_second_scan_finds_nothing_new(tmp_path: Path, context: ScanContext) -> None:
    """Double-counting an estate's crypto looks like growth. It must not
    happen."""
    write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())

    assert len(scan_spool(tmp_path, context)) == 1
    assert scan_spool(tmp_path, context) == []


def test_consumed_evidence_is_retained_not_destroyed(
    tmp_path: Path, context: ScanContext
) -> None:
    original = write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())
    body = original.read_text(encoding="utf-8")

    scan_spool(tmp_path, context)

    assert (tmp_path / CONSUMED_DIR / "host-1-2-0.jsonl").read_text(
        encoding="utf-8"
    ) == body


def test_a_name_collision_in_consumed_does_not_lose_a_file(
    tmp_path: Path, context: ScanContext
) -> None:
    """Two runs can produce the same filename; neither may overwrite the other."""
    write_spool_file(tmp_path, "same.jsonl", observed_event(pid=1))
    scan_spool(tmp_path, context)
    write_spool_file(tmp_path, "same.jsonl", observed_event(pid=2))
    scan_spool(tmp_path, context)

    consumed = sorted((tmp_path / CONSUMED_DIR).iterdir())
    assert len(consumed) == 2, f"a file was overwritten: {consumed}"


def test_consumed_and_rejected_files_are_not_re_ingested(
    tmp_path: Path, context: ScanContext
) -> None:
    write_spool_file(tmp_path / CONSUMED_DIR, "old.jsonl", observed_event())
    write_spool_file(tmp_path / REJECTED_DIR, "bad.jsonl", observed_event())

    assert scan_spool(tmp_path, context) == []


# --------------------------------------------------------------------------
# End to end, through the orchestrator and the store
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_end_to_end_a_spool_scan_stores_an_observed_cbom(
    tmp_path: Path, context: ScanContext
) -> None:
    spool = tmp_path / "spool"
    write_spool_file(
        spool,
        "host-1-2-0.jsonl",
        observed_event(observed_version="TLSv1.3"),
    )
    target = Target(kind="spool", ref=str(spool), system="quantumbank")

    scan_id = run_scan(target, registry.get_scanners(None), context)

    record = store.get_scan(scan_id)
    assert record is not None
    validate_cbom_json(record.cbom_json)

    document = json.loads(record.cbom_json)
    assert document["components"], "no observed component reached the store"
    for component in document["components"]:
        views = [
            p["value"] for p in component["properties"] if p["name"] == "ecdat:view"
        ]
        assert views == ["observed"]


# --------------------------------------------------------------------------
# THREE-VIEW COEXISTENCE -- the reason this seam exists
# --------------------------------------------------------------------------


def test_three_views_of_one_algorithm_stay_three_components(
    tmp_path: Path, context: ScanContext
) -> None:
    """ADR-0002's cross-view non-merge, proved with all three views for real.

    Merging these would destroy exactly the signal drift detection exists to
    find: a repo that DECLARES RSA, an image that SHIPS it, and a host
    OBSERVED using it are three facts, and their disagreement is the product.
    """
    from tests.factories import finding as make_finding
    from tests.factories import occurrence

    declared = make_finding(
        scanner_id="source",
        view="declared",
        algorithm="RSA",
        params={"key_size": 2048},
        occurrences=[occurrence(view="declared", locator="app/tls.py:13")],
    )
    shipped = make_finding(
        scanner_id="container",
        view="shipped",
        algorithm="RSA",
        params={"key_size": 2048},
        occurrences=[occurrence(view="shipped", locator="sha256:abc/etc/ssl/api.pem")],
    )
    write_spool_file(
        tmp_path,
        "host-1-2-0.jsonl",
        observed_event(observed_cipher="RSA", observed_version="TLSv1.2"),
    )
    (observed,) = [f for f in scan_spool(tmp_path, context) if f.algorithm == "RSA"]

    target = Target(kind="spool", ref=str(tmp_path), system="quantumbank")
    bom, cbom_json = normalise([declared, shipped, observed], target)

    assert len(bom.components) == 3, "views merged; drift signal destroyed"

    document = json.loads(cbom_json)
    views = sorted(
        p["value"]
        for component in document["components"]
        for p in component["properties"]
        if p["name"] == "ecdat:view"
    )
    assert views == ["declared", "observed", "shipped"]

    refs = {component.bom_ref.value for component in bom.components}
    assert len(refs) == 3


@pytest.mark.validation
def test_all_three_scanners_produce_findings_that_coexist(
    tmp_path: Path, context: ScanContext
) -> None:
    """The correlator's future input, assembled from three real scanners."""
    from scanners.container import ContainerScanner
    from scanners.source import SourceScanner

    source_findings = list(
        SourceScanner().scan(Target(kind="repo", ref="testdata/minimal_repo"), context)
    )
    container_findings = list(
        ContainerScanner().scan(
            Target(
                kind="image",
                ref="testdata/images/synthetic/dpkg-openssl302.tar",
            ),
            context,
        )
    )
    write_spool_file(tmp_path, "host-1-2-0.jsonl", observed_event())
    spool_findings = scan_spool(tmp_path, context)

    assert source_findings and container_findings and spool_findings

    target = Target(kind="repo", ref="quantumbank", system="quantumbank")
    _bom, cbom_json = normalise(
        [*source_findings, *container_findings, *spool_findings], target
    )
    validate_cbom_json(cbom_json)

    document = json.loads(cbom_json)
    views = {
        p["value"]
        for component in document["components"]
        for p in component["properties"]
        if p["name"] == "ecdat:view"
    }
    assert views == {"declared", "shipped", "observed"}
