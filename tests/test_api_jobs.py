"""ADR-0035 PART B -- a scan is a JOB: accepted at once, run in the background.

`POST /scans`, `POST /systems/scan` and `POST /scans/{id}/fix` used to hold the
request open until the whole run was stored -- the caller froze for as long as
the scan took. Now each answers **202** with a job id immediately, a worker
thread in the same process runs it, and `GET /jobs/{id}` says pending ->
running -> done (with the scan id) or failed (with the reason).

The line between "refused now" and "failed later": the REQUEST is validated
before anything is queued (schema, scanner ids, manifest, the parent row), so a
bad request is still a 400/404 at once. Reading the TARGET is the job's work,
so a target that cannot be read fails the job, with the reason.

No queue broker: a thread pool and a `jobs` table beside `scans`. `?wait=true`
keeps the synchronous path for tools and tests, and still records the job.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import api.app as api_app
from api.app import app
from core import orchestrator, store
from core.scanner import Target
from tests.conftest import ApiTokens

REPO_ROOT = Path(__file__).resolve().parent.parent
MINIMAL = {"kind": "repo", "ref": "testdata/minimal_repo", "scanners": ["source"]}

#: Valid as a manifest -- it parses -- but its image does not exist. Only the
#: job, reading the targets, can find that out.
UNREADABLE_SYSTEM = {
    "system": "mini",
    "targets": [
        {"kind": "repo", "ref": "testdata/minimal_repo"},
        {"kind": "image", "ref": "testdata/no-such-image.tar"},
    ],
}


@pytest.fixture
def client(api_keys: ApiTokens) -> Iterator[TestClient]:
    with TestClient(app, headers=api_keys.headers("admin")) as test_client:
        yield test_client


def wait_for(
    client: TestClient, job_id: str, *, timeout: float = 60.0
) -> dict[str, Any]:
    """Poll a job the way the console does, until it stops moving."""
    deadline = time.monotonic() + timeout
    while True:
        job: dict[str, Any] = client.get(f"/jobs/{job_id}").json()
        if job["status"] in ("done", "failed"):
            return job
        assert time.monotonic() < deadline, f"job never finished: {job}"
        time.sleep(0.05)


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Hold every scan job at its first line until the test lets it go.

    The proof of "non-blocking" cannot be a fast scan finishing quickly -- that
    proves nothing. It is a scan that CANNOT finish until released, and a
    request that has already answered.
    """
    release = threading.Event()
    started = threading.Event()
    real = orchestrator.run_scan

    def held(*args: Any, **kwargs: Any) -> str:
        started.set()
        assert release.wait(timeout=30), "the test never released the job"
        return real(*args, **kwargs)

    monkeypatch.setattr(api_app, "run_scan", held)
    yield SimpleNamespace(release=release, started=started)
    release.set()  # never leave a worker parked when a test fails early


def explode(*_args: Any, **_kwargs: Any) -> str:
    raise RuntimeError("the scanner exploded mid-run")


def teapot_scan() -> str:
    """A stored row whose target kind ECDAT cannot classify."""
    scan_id = store.save_scan(Target(kind="repo", ref="/nowhere"), '{"components":[]}')
    with store.get_engine().begin() as connection:
        connection.execute(
            text("UPDATE scans SET target_kind = 'teapot' WHERE id = :id"),
            {"id": scan_id},
        )
    return scan_id


# ---------------------------------------------------------------------------
# 202 + a job id, immediately
# ---------------------------------------------------------------------------


def test_post_scans_answers_202_with_a_job_id_before_the_scan_can_run(
    client: TestClient, gate: SimpleNamespace
) -> None:
    started_at = time.monotonic()
    response = client.post("/scans", json=MINIMAL)
    elapsed = time.monotonic() - started_at

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["kind"] == "scan"
    assert body["status"] == "pending"
    assert body["job_id"]
    assert response.headers["location"].endswith(f"/jobs/{body['job_id']}")
    # The scan is parked until released, so a request that waited for it could
    # never have answered at all -- let alone inside a second.
    assert elapsed < 1.0, f"POST /scans took {elapsed:.2f}s"

    assert gate.started.wait(timeout=5), "no worker picked the job up"
    running = client.get(f"/jobs/{body['job_id']}").json()
    assert running["status"] == "running"
    assert running["scan_id"] is None

    gate.release.set()
    done = wait_for(client, body["job_id"])
    assert done["status"] == "done"
    assert done["scan_id"]
    assert client.get(f"/scans/{done['scan_id']}").status_code == 200


def test_a_job_waits_pending_while_every_worker_is_busy(
    api_keys: ApiTokens, gate: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECDAT_API_WORKERS", "1")
    with TestClient(app, headers=api_keys.headers("admin")) as client:
        first = client.post("/scans", json=MINIMAL).json()["job_id"]
        assert gate.started.wait(timeout=5)
        second = client.post("/scans", json=MINIMAL).json()["job_id"]

        assert client.get(f"/jobs/{second}").json()["status"] == "pending"

        gate.release.set()
        first_done = wait_for(client, first)
        second_done = wait_for(client, second)

    assert first_done["status"] == second_done["status"] == "done"
    assert first_done["scan_id"] != second_done["scan_id"]


def test_a_job_records_its_times_and_who_asked(client: TestClient) -> None:
    job_id = client.post("/scans", json=MINIMAL).json()["job_id"]

    job = wait_for(client, job_id)

    assert job["requested_by"] == "test-admin"
    assert job["subject"] == "repo testdata/minimal_repo"
    created, started, finished = (
        datetime.fromisoformat(job[field])
        for field in ("created_at", "started_at", "finished_at")
    )
    assert created <= started <= finished


def test_a_system_scan_is_a_job_too(client: TestClient) -> None:
    response = client.post(
        "/systems/scan",
        json={
            "system": "mini",
            "targets": [{"kind": "repo", "ref": "testdata/minimal_repo"}],
        },
    )

    assert response.status_code == 202, response.text
    assert response.json()["kind"] == "system-scan"
    job = wait_for(client, response.json()["job_id"])
    assert job["status"] == "done", job
    assert client.get(f"/scans/{job['scan_id']}").json()["target"]["system"] == "mini"


def test_a_fix_pass_is_a_job_too(client: TestClient) -> None:
    scan_id = client.post("/scans", params={"wait": "true"}, json=MINIMAL).json()[
        "scan_id"
    ]

    response = client.post(f"/scans/{scan_id}/fix", json={"scanners": ["source"]})

    assert response.status_code == 202, response.text
    assert response.json()["kind"] == "fix"
    job = wait_for(client, response.json()["job_id"])
    assert job["status"] == "done", job
    assert job["parent_scan_id"] == scan_id
    assert client.get(f"/scans/{scan_id}/fixes").json()["fix_scan_id"] == job["scan_id"]


# ---------------------------------------------------------------------------
# failed, with the reason
# ---------------------------------------------------------------------------


def test_a_failing_scan_is_failed_with_its_reason(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api_app, "run_scan", explode)

    job_id = client.post("/scans", json=MINIMAL).json()["job_id"]
    job = wait_for(client, job_id)

    assert job["status"] == "failed"
    assert job["scan_id"] is None
    assert "RuntimeError" in job["error"]
    assert "the scanner exploded mid-run" in job["error"]
    assert job["finished_at"] is not None


def test_a_system_scan_whose_target_cannot_be_read_fails_with_the_reason(
    client: TestClient,
) -> None:
    """A real failure, not a patched one: the manifest is valid, so the request
    is accepted; the job reads the targets, and fails naming the one it could
    not read -- rather than storing an inventory missing a whole view."""
    response = client.post("/systems/scan", json=UNREADABLE_SYSTEM)

    assert response.status_code == 202, response.text
    job = wait_for(client, response.json()["job_id"])
    assert job["status"] == "failed"
    assert "TargetUnreadableError" in job["error"]
    assert "no-such-image.tar" in job["error"]
    assert job["scan_id"] is None
    assert store.list_scans() == [], "a failed job must not leave a partial scan behind"


def test_a_request_the_server_can_refuse_now_is_refused_now_not_queued(
    client: TestClient,
) -> None:
    assert (
        client.post("/scans", json={**MINIMAL, "scanners": ["nope"]}).status_code == 400
    )
    assert client.post("/scans/no-such-scan/fix", json={}).status_code == 404
    bad_manifest = {"system": "x", "targets": [{"kind": "nope", "ref": "a"}]}
    assert client.post("/systems/scan", json=bad_manifest).status_code == 400
    # The parent row names a kind ECDAT cannot classify: a fact about the
    # stored ROW, known before any target is read.
    teapot = client.post(f"/scans/{teapot_scan()}/fix", json={})
    assert teapot.status_code == 400
    assert "teapot" in teapot.json()["detail"]

    assert client.get("/jobs").json()["total"] == 0


def test_an_unknown_job_is_404(client: TestClient) -> None:
    response = client.get("/jobs/no-such-job")

    assert response.status_code == 404
    assert "no-such-job" in response.json()["detail"]


def test_a_job_orphaned_by_a_restart_is_failed_not_left_running(
    api_keys: ApiTokens,
) -> None:
    """A job the process was running when it died must not say "running" forever."""
    running = store.create_job("scan", subject="repo testdata/minimal_repo")
    store.mark_job_running(running)
    queued = store.create_job("scan", subject="repo testdata/minimal_repo")

    with TestClient(app, headers=api_keys.headers("viewer")) as client:
        was_running = client.get(f"/jobs/{running}").json()
        was_queued = client.get(f"/jobs/{queued}").json()

    for job in (was_running, was_queued):
        assert job["status"] == "failed"
        assert "interrupted" in job["error"]
        assert job["finished_at"] is not None


# ---------------------------------------------------------------------------
# The synchronous path, kept
# ---------------------------------------------------------------------------


def test_wait_true_still_answers_with_the_scan_and_records_the_job(
    client: TestClient,
) -> None:
    response = client.post("/scans", params={"wait": "true"}, json=MINIMAL)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["component_count"] == 2
    job = client.get(f"/jobs/{body['job_id']}").json()
    assert job["status"] == "done"
    assert job["scan_id"] == body["scan_id"]


def test_a_synchronous_failure_is_an_error_and_a_failed_job(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api_app, "run_scan", explode)

    response = client.post("/scans", params={"wait": "true"}, json=MINIMAL)

    assert response.status_code == 500
    assert "the scanner exploded mid-run" in response.json()["detail"]
    (job,) = client.get("/jobs").json()["items"]
    assert job["status"] == "failed"


def test_a_synchronous_unreadable_target_is_still_a_400(client: TestClient) -> None:
    """The operator's mistake, as before the job model: 400, naming the target."""
    response = client.post(
        "/systems/scan", params={"wait": "true"}, json=UNREADABLE_SYSTEM
    )

    assert response.status_code == 400
    assert "no-such-image.tar" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Roles, and no broker
# ---------------------------------------------------------------------------


def test_a_viewer_can_watch_a_job_but_not_start_one(
    client: TestClient, api_keys: ApiTokens
) -> None:
    job_id = client.post("/scans", json=MINIMAL).json()["job_id"]
    viewer = api_keys.headers("viewer")

    assert client.get(f"/jobs/{job_id}", headers=viewer).status_code == 200
    assert client.post("/scans", json=MINIMAL, headers=viewer).status_code == 403
    wait_for(client, job_id)


def test_the_runner_is_in_process_with_no_queue_broker() -> None:
    lines: list[str] = []
    for manifest in ("requirements.txt", "requirements-dev.txt"):
        lines += (REPO_ROOT / manifest).read_text(encoding="utf-8").lower().splitlines()
    packages = {
        re.split(r"[\s=<>~!\[;]", line.strip(), maxsplit=1)[0]
        for line in lines
        if line.strip() and not line.lstrip().startswith(("#", "-"))
    }

    assert "fastapi" in packages, "the requirements parse found nothing real"
    assert packages.isdisjoint(
        {"celery", "redis", "rq", "dramatiq", "huey", "kombu", "arq"}
    )
