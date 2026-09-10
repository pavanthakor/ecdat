"""API tests: the pipe as the dashboard will drive it.

Scans run the real source scanner over ``testdata/minimal_repo``, which holds
exactly two crypto call sites (an RSA-2048 keygen and a SHA-256 digest). That
keeps the component counts below exact rather than approximate, while still
proving a real detection reached the CBOM.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from fastapi.testclient import TestClient

from api.app import app

#: Two crypto call sites -> two components. See the module docstring.
MINIMAL_REPO = "testdata/minimal_repo"
MINIMAL_COMPONENTS = 2


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def post_scan(client: TestClient, **body: object) -> dict[str, object]:
    payload = {"kind": "repo", "ref": MINIMAL_REPO, **body}
    response = client.post("/scans", json=payload)
    assert response.status_code == 201, response.text
    return dict(response.json())


def post_scan_id(client: TestClient, **body: object) -> str:
    """`post_scan` narrowed to the id, which is a str by the API contract."""
    scan_id = post_scan(client, **body)["scan_id"]
    assert isinstance(scan_id, str)
    return scan_id


def test_health_is_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_post_scans_defaults_to_every_registered_scanner(
    client: TestClient,
) -> None:
    body = post_scan(client)

    assert isinstance(body["scan_id"], str)
    assert body["scan_id"]
    assert body["component_count"] == MINIMAL_COMPONENTS


def test_post_scans_finds_real_crypto(client: TestClient) -> None:
    """The default scan is a real detection, not a fixed placeholder finding."""
    scan_id = post_scan(client)["scan_id"]

    document = json.loads(client.get(f"/scans/{scan_id}/cbom").text)
    names = {component["name"] for component in document["components"]}

    assert names == {"RSA-2048", "SHA-256"}


def test_post_scans_accepts_an_explicit_scanner_subset(client: TestClient) -> None:
    # The container scanner declines a repo target, so selecting just the
    # source scanner must give the same result as running both.
    body = post_scan(client, scanners=["source"])

    assert body["component_count"] == MINIMAL_COMPONENTS


def test_post_scans_with_an_empty_scanner_list_runs_nothing(
    client: TestClient,
) -> None:
    body = post_scan(client, scanners=[])

    assert body["component_count"] == 0


def test_post_scans_rejects_an_unknown_scanner_id(client: TestClient) -> None:
    response = client.post(
        "/scans", json={"kind": "repo", "ref": MINIMAL_REPO, "scanners": ["nope"]}
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "nope" in detail
    assert "source" in detail


def test_get_scanners_lists_the_registered_ids(client: TestClient) -> None:
    response = client.get("/scanners")

    assert response.status_code == 200
    assert response.json() == ["config", "container", "deps", "runtime-spool", "source"]


def test_post_scans_rejects_an_unknown_target_kind(client: TestClient) -> None:
    response = client.post("/scans", json={"kind": "teapot", "ref": "/srv/x"})

    assert response.status_code == 422


def test_post_scans_requires_a_ref(client: TestClient) -> None:
    assert client.post("/scans", json={"kind": "repo"}).status_code == 422


@pytest.mark.validation
def test_get_cbom_returns_the_stored_document(client: TestClient) -> None:
    scan_id = post_scan(client, system="quantumbank")["scan_id"]

    response = client.get(f"/scans/{scan_id}/cbom")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(response.text) is None
    assert json.loads(response.text)["specVersion"] == "1.6"


def test_get_cbom_returns_the_bytes_that_were_stored(client: TestClient) -> None:
    from core import store

    scan_id = str(post_scan(client)["scan_id"])
    stored = store.get_scan(scan_id)
    assert stored is not None

    response = client.get(f"/scans/{scan_id}/cbom")

    # Served verbatim: re-encoding would break the determinism guarantee.
    assert response.text == stored.cbom_json


def test_get_cbom_of_an_unknown_scan_is_404(client: TestClient) -> None:
    response = client.get("/scans/does-not-exist/cbom")

    assert response.status_code == 404
    assert "does-not-exist" in response.json()["detail"]


def test_list_scans_summarises_newest_first(client: TestClient) -> None:
    first = post_scan(client, system="auth")["scan_id"]
    second = post_scan(client, system="ledger")["scan_id"]

    response = client.get("/scans")

    assert response.status_code == 200
    summaries = response.json()
    assert [s["id"] for s in summaries] == [second, first]
    assert summaries[0]["target"] == {
        "kind": "repo",
        "ref": MINIMAL_REPO,
        "system": "ledger",
        "data_class": None,
    }
    assert summaries[0]["component_count"] == MINIMAL_COMPONENTS
    assert (
        summaries[0]["created_at"].endswith("Z")
        or "+00:00" in (summaries[0]["created_at"])
    )


def test_list_scans_is_empty_before_any_scan(client: TestClient) -> None:
    assert client.get("/scans").json() == []


def test_cors_allows_the_local_dashboard(client: TestClient) -> None:
    response = client.options(
        "/scans",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_scan_summary_carries_policy_bands(client: TestClient) -> None:
    """The dashboard reads bands off the summary rather than scoring itself."""
    post_scan(client)

    (summary,) = client.get("/scans").json()

    assert set(summary["band_counts"]) == {"Critical", "High", "Medium", "Low"}
    # RSA-2048 is Shor-broken (Medium at the quantum cap); SHA-256 is Low.
    assert summary["band_counts"]["Medium"] == 1
    assert summary["band_counts"]["Low"] == 1
    assert summary["max_score"] == 40


def test_the_stored_cbom_carries_verdicts(client: TestClient) -> None:
    scan_id = post_scan(client)["scan_id"]

    document = json.loads(client.get(f"/scans/{scan_id}/cbom").text)
    rsa = next(c for c in document["components"] if c["name"] == "RSA-2048")
    values = {p["name"]: p["value"] for p in rsa["properties"]}

    assert values["ecdat:band"] == "Medium"
    assert values["ecdat:quantum_status"] == "broken"
    assert "quantum-shor-broken-asymmetric" in values["ecdat:fired_rules"]


# ---------------------------------------------------------------------------
# The denormalised scan list (ADR-0016)
#
# The summary used to be recomputed by parsing every stored CBOM on every list
# call -- O(scans x document size) per request. It now comes off columns, and
# these tests are arranged so that a regression to parsing CANNOT pass: the
# stored document is deliberately corrupted after the scan, so any code path
# that reads it will either crash or return zeros.
# ---------------------------------------------------------------------------


def corrupt_stored_cbom(scan_id: str) -> None:
    """Replace a stored CBOM with something unparseable.

    Nothing in production does this. It is the only way to prove a summary was
    NOT derived from the document, rather than merely that it happens to agree.
    """
    from sqlalchemy import text

    from core import store

    with store.get_engine().begin() as connection:
        connection.execute(
            text("UPDATE scans SET cbom_json = :doc WHERE id = :id"),
            {"doc": "}{ not a document", "id": scan_id},
        )


def test_list_scans_summary_matches_a_full_cbom_parse(client: TestClient) -> None:
    """Denormalisation correctness: the columns say what the document says."""
    from core import store
    from core.summary import summarise

    scan_id = post_scan_id(client)
    stored = store.get_scan(scan_id)
    assert stored is not None
    expected = summarise(json.loads(stored.cbom_json))

    (summary,) = client.get("/scans").json()

    assert summary["band_counts"] == expected.band_counts
    assert summary["max_score"] == expected.max_score
    assert summary["drift_counts"] == expected.drift_counts
    assert summary["coverage_gaps"] == expected.coverage_gaps


def test_list_scans_does_not_parse_the_stored_cbom(client: TestClient) -> None:
    """The load-bearing assertion: corrupt the document, summary unchanged."""
    scan_id = post_scan_id(client)
    (before,) = client.get("/scans").json()

    corrupt_stored_cbom(scan_id)

    (after,) = client.get("/scans").json()
    assert after == before


def test_mutation_summarising_from_the_cbom_breaks_the_corrupted_row(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reintroduce the parse and the corrupted-row test stops holding."""
    import api.app as api_app
    from core import store
    from core.summary import summarise

    scan_id = post_scan_id(client)
    (before,) = client.get("/scans").json()
    corrupt_stored_cbom(scan_id)

    def parse_the_document(scan: store.Scan) -> object:
        return summarise(json.loads(scan.cbom_json))

    monkeypatch.setattr(api_app, "_summary_for", parse_the_document)

    with pytest.raises(json.JSONDecodeError):
        client.get("/scans")
    assert before["max_score"] >= 0


def test_list_scans_reports_which_scanners_ran(client: TestClient) -> None:
    post_scan(client, scanners=["source"])

    (summary,) = client.get("/scans").json()

    assert [entry["id"] for entry in summary["scanners_ran"]] == ["source"]


def test_list_scans_distinguishes_an_unknown_scanner_set_from_an_empty_one(
    client: TestClient,
) -> None:
    from core import store
    from core.scanner import Target

    post_scan(client, scanners=[])  # ran nothing, and we know it
    unknown_id = store.save_scan(
        Target(kind="repo", ref="/legacy"), '{"components":[]}'
    )

    summaries = {s["id"]: s for s in client.get("/scans").json()}

    assert summaries[unknown_id]["scanners_ran"] is None
    empty = next(s for i, s in summaries.items() if i != unknown_id)
    assert empty["scanners_ran"] == []


# ---------------------------------------------------------------------------
# Fix and rescore routes
# ---------------------------------------------------------------------------


def test_post_fix_creates_a_linked_fix_row_and_leaves_the_parent_alone(
    client: TestClient,
) -> None:
    from core import store

    scan_id = post_scan_id(client, sector="bfsi", exposure="internet")
    parent_before = client.get(f"/scans/{scan_id}/cbom").text

    response = client.post(f"/scans/{scan_id}/fix", json={"scanners": ["source"]})

    assert response.status_code == 201, response.text
    fix_scan_id = response.json()["scan_id"]
    assert fix_scan_id != scan_id
    fix_row = store.get_scan(fix_scan_id)
    assert fix_row is not None
    assert fix_row.kind == store.KIND_FIX
    assert fix_row.parent_scan_id == scan_id
    # The parent is byte-identical.
    assert client.get(f"/scans/{scan_id}/cbom").text == parent_before


def test_post_fix_inherits_the_parents_scoring_context(client: TestClient) -> None:
    from core import store

    scan_id = post_scan_id(client, sector="bfsi", exposure="internet", z_years=7)

    fix_id = client.post(f"/scans/{scan_id}/fix", json={}).json()["scan_id"]

    fix_row = store.get_scan(fix_id)
    assert fix_row is not None
    assert fix_row.sector == "bfsi"
    assert fix_row.exposure == "internet"
    assert fix_row.z_years == 7


def test_get_fixes_returns_nothing_before_a_fix_pass(client: TestClient) -> None:
    scan_id = post_scan_id(client)

    body = client.get(f"/scans/{scan_id}/fixes").json()

    assert body["fix_scan_id"] is None
    assert body["fixes"] == []


def test_get_fixes_returns_the_fix_results(client: TestClient) -> None:
    scan_id = post_scan_id(client)
    fix_id = client.post(f"/scans/{scan_id}/fix", json={}).json()["scan_id"]

    body = client.get(f"/scans/{scan_id}/fixes").json()

    assert body["fix_scan_id"] == fix_id
    assert body["parent_scan_id"] == scan_id
    # minimal_repo has no fixable finding, but the contract must still hold.
    assert isinstance(body["fixes"], list)
    for entry in body["fixes"]:
        assert entry["verified"] is (entry["diff"] is not None)


def test_post_rescore_writes_a_linked_row_with_new_scores(client: TestClient) -> None:
    from core import store

    scan_id = post_scan_id(client, data_class="Sovereign", z_years=3)
    before = client.get(f"/scans/{scan_id}/cbom").text

    response = client.post(f"/scans/{scan_id}/rescore", params={"z_years": 30})

    assert response.status_code == 201, response.text
    rescored_id = response.json()["scan_id"]
    row = store.get_scan(rescored_id)
    assert row is not None
    assert row.kind == store.KIND_RESCORE
    assert row.parent_scan_id == scan_id
    assert row.z_years == 30
    assert row.scanners_ran == []
    assert client.get(f"/scans/{scan_id}/cbom").text == before


def test_post_fix_on_an_unknown_scan_is_404(client: TestClient) -> None:
    assert client.post("/scans/nope/fix", json={}).status_code == 404


def test_post_rescore_on_an_unknown_scan_is_404(client: TestClient) -> None:
    assert client.post("/scans/nope/rescore").status_code == 404


def test_get_fixes_on_an_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get("/scans/nope/fixes").status_code == 404


def test_scan_summaries_carry_their_kind_and_parent(client: TestClient) -> None:
    """Derived rows are listed, not hidden -- nothing silently dropped."""
    scan_id = post_scan_id(client)
    client.post(f"/scans/{scan_id}/rescore", params={"z_years": 30})

    summaries = client.get("/scans").json()
    kinds = {s["kind"] for s in summaries}

    assert kinds == {"scan", "rescore"}
    scans_only = client.get("/scans", params={"kind": "scan"}).json()
    assert [s["id"] for s in scans_only] == [scan_id]


# ---------------------------------------------------------------------------
# The console mount (ADR-0018)
# ---------------------------------------------------------------------------


def test_the_api_is_served_under_api_as_well_as_bare(client: TestClient) -> None:
    """One router, two mounts -- the SPA fetches `/api`, the docs say `/scans`."""
    scan_id = post_scan_id(client)

    bare = client.get("/scans").json()
    prefixed = client.get("/api/scans").json()

    assert bare == prefixed
    assert client.get(f"/api/scans/{scan_id}/cbom").text == (
        client.get(f"/scans/{scan_id}/cbom").text
    )


def test_get_one_scan_returns_its_denormalised_summary(client: TestClient) -> None:
    scan_id = post_scan_id(client)

    body = client.get(f"/scans/{scan_id}").json()

    assert body["id"] == scan_id
    assert body["component_count"] == MINIMAL_COMPONENTS
    assert set(body["band_counts"]) == {"Critical", "High", "Medium", "Low"}


def test_get_one_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get("/scans/no-such-scan").status_code == 404


def test_an_unknown_api_path_404s_instead_of_returning_html(
    client: TestClient,
) -> None:
    """The catch-all must not turn a mistyped endpoint into an HTML 200.

    That failure surfaces as a JSON.parse error three frames from the mistake,
    which is a bad afternoon.
    """
    for path in ("/api/nope", "/scans/x/nope", "/scanners/nope"):
        assert client.get(path).status_code == 404, path


def test_the_spa_route_reports_a_missing_build_rather_than_404ing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.app as api_app

    monkeypatch.setattr(api_app, "WEB_DIST", Path("/nonexistent/web/dist"))

    response = client.get("/")

    assert response.status_code == 503
    assert "make web" in response.json()["detail"]


def test_the_scan_summary_carries_the_engine_that_produced_it(
    client: TestClient,
) -> None:
    """The console footer says which engine a reader is looking at (ADR-0017)."""
    scan_id = post_scan_id(client, scanners=["source"])

    body = client.get(f"/scans/{scan_id}").json()

    assert body["engine_versions"]["ecdat"]
    assert body["engine_versions"]["source"]["pinned"]
    assert body["engine_warning"] is None
