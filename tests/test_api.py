"""API tests: the pipe as the dashboard will drive it."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from fastapi.testclient import TestClient

from api.app import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def post_scan(client: TestClient, **body: object) -> dict[str, object]:
    payload = {"kind": "repo", "ref": "/srv/quantumbank", **body}
    response = client.post("/scans", json=payload)
    assert response.status_code == 201, response.text
    return dict(response.json())


def test_health_is_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_post_scans_runs_the_stub_and_returns_a_scan_id(client: TestClient) -> None:
    body = post_scan(client)

    assert isinstance(body["scan_id"], str)
    assert body["scan_id"]
    assert body["component_count"] == 1


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
        "ref": "/srv/quantumbank",
        "system": "ledger",
        "data_class": None,
    }
    assert summaries[0]["component_count"] == 1
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
