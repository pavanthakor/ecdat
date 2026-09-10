"""ADR-0035 PART A -- the API refuses a request it cannot attribute.

Before this slice every route answered anyone who could reach the port,
including `GET /scans/{id}/fixes` -- verified migration patches for an estate's
weakest cryptography. Now:

* **401** -- no credential, a malformed one, or one no configured key matches;
* **403** -- a real key whose ROLE does not allow the route;
* ``/health`` and the console's static files stay open.

Keys are bearer tokens. The server holds only their SHA-256 digests, in a file
named by ``ECDAT_API_KEYS`` (default: outside the repository). The check is a
local digest comparison: no identity provider, no network call.
"""

from __future__ import annotations

import ast
import hmac
import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from api import auth
from api.app import app
from api.app import router as api_router
from core import store
from core.scanner import Target
from tests.conftest import ApiTokens

REPO_ROOT = Path(__file__).resolve().parent.parent
MINIMAL = {"kind": "repo", "ref": "testdata/minimal_repo", "scanners": []}

#: The routes an ADMIN key is needed for. Everything else behind auth is open
#: to a viewer. Pinned here so a change to the policy is a change to a test.
ADMIN_ROUTES = {
    ("POST", "/scans"),
    ("POST", "/systems/scan"),
    ("POST", "/scans/{scan_id}/fix"),
    ("GET", "/scans/{scan_id}/fixes"),
}

#: Routes that answer without a credential: liveness, and the console itself
#: (it must load to show its sign-in prompt; it holds no data).
OPEN_ROUTES = {("GET", "/health"), ("GET", "/{full_path:path}")}


@pytest.fixture
def raw(api_keys: ApiTokens) -> Iterator[TestClient]:
    """A client that sends NO credential unless a test hands it one."""
    del api_keys  # requested so the keys file exists; this client does not use it
    with TestClient(app) as client:
        yield client


@pytest.fixture
def scan_id() -> str:
    """A stored scan for the read routes to point at, written to the store."""
    return store.save_scan(
        Target(kind="repo", ref="testdata/minimal_repo"), '{"components":[]}'
    )


# ---------------------------------------------------------------------------
# 401 -- nobody, or a credential nobody issued
# ---------------------------------------------------------------------------


def test_health_needs_no_token(raw: TestClient) -> None:
    response = raw.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "path", ["/scans", "/api/scans", "/scanners", "/jobs", "/auth/whoami"]
)
def test_a_request_with_no_token_is_401(raw: TestClient, path: str) -> None:
    response = raw.get(path)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "Authorization: Bearer" in response.json()["detail"]


def test_a_trigger_with_no_token_is_401_and_runs_nothing(raw: TestClient) -> None:
    response = raw.post("/scans", json=MINIMAL)

    assert response.status_code == 401
    assert store.count_jobs() == 0
    assert store.list_scans() == []


@pytest.mark.parametrize(
    "header",
    [
        "Bearer not-a-real-key",
        "Bearer ",
        "Bearer",
        "Basic dXNlcjpwYXNz",
        "not-even-a-scheme",
        f"Bearer ecdat_{'x' * 43}",
    ],
)
def test_an_invalid_or_malformed_token_is_401(raw: TestClient, header: str) -> None:
    response = raw.get("/scans", headers={"Authorization": header})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"]


def test_the_prefixed_mount_is_guarded_exactly_like_the_bare_one(
    raw: TestClient, api_keys: ApiTokens
) -> None:
    assert raw.get("/api/scans").status_code == 401
    assert raw.get("/api/scans", headers=api_keys.headers("viewer")).status_code == 200


# ---------------------------------------------------------------------------
# 403 -- a real key, the wrong role
# ---------------------------------------------------------------------------


def test_a_viewer_can_read(raw: TestClient, api_keys: ApiTokens, scan_id: str) -> None:
    headers = api_keys.headers("viewer")
    for path in (
        "/scans",
        f"/scans/{scan_id}",
        f"/scans/{scan_id}/cbom",
        f"/scans/{scan_id}/compare/{scan_id}",
        "/scanners",
        "/jobs",
        "/auth/whoami",
    ):
        assert raw.get(path, headers=headers).status_code == 200, path


def test_a_viewer_may_rescore(raw: TestClient, api_keys: ApiTokens) -> None:
    """The Mosca slider. It runs no scanner and reads no target -- see ADR-0035."""
    created = raw.post(
        "/scans",
        params={"wait": "true"},
        json=MINIMAL,
        headers=api_keys.headers("admin"),
    )
    response = raw.post(
        f"/scans/{created.json()['scan_id']}/rescore",
        params={"z_years": 20},
        headers=api_keys.headers("viewer"),
    )

    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/scans", MINIMAL),
        (
            "POST",
            "/systems/scan",
            {"system": "x", "targets": [{"kind": "repo", "ref": "a"}]},
        ),
        ("POST", "/scans/{scan_id}/fix", {}),
        ("GET", "/scans/{scan_id}/fixes", None),
    ],
)
def test_a_viewer_is_403_on_every_admin_route(
    raw: TestClient,
    api_keys: ApiTokens,
    scan_id: str,
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    response = raw.request(
        method,
        path.format(scan_id=scan_id),
        json=body,
        headers=api_keys.headers("viewer"),
    )

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert "admin" in detail
    assert "test-viewer" in detail
    assert "viewer" in detail
    assert store.count_jobs() == 0, "a forbidden trigger must not queue anything"


def test_the_fixes_endpoint_requires_admin(
    raw: TestClient, api_keys: ApiTokens, scan_id: str
) -> None:
    """Verified patches for the estate's weakest crypto: admin only."""
    as_viewer = raw.get(f"/scans/{scan_id}/fixes", headers=api_keys.headers("viewer"))
    as_admin = raw.get(f"/scans/{scan_id}/fixes", headers=api_keys.headers("admin"))

    assert as_viewer.status_code == 403
    assert as_admin.status_code == 200
    assert as_admin.json()["parent_scan_id"] == scan_id


def test_an_admin_may_trigger_a_scan(raw: TestClient, api_keys: ApiTokens) -> None:
    response = raw.post(
        "/scans",
        params={"wait": "true"},
        json=MINIMAL,
        headers=api_keys.headers("admin"),
    )

    assert response.status_code == 201, response.text


def test_whoami_names_the_key_and_its_role(
    raw: TestClient, api_keys: ApiTokens
) -> None:
    viewer = raw.get("/auth/whoami", headers=api_keys.headers("viewer")).json()
    admin = raw.get("/auth/whoami", headers=api_keys.headers("admin")).json()

    assert viewer == {"name": "test-viewer", "role": "viewer"}
    assert admin == {"name": "test-admin", "role": "admin"}


def test_every_route_is_guarded_and_admin_is_exactly_the_trigger_set() -> None:
    """Structural. A route added tomorrow without a guard fails HERE.

    Reads each route's own dependencies, so it cannot be satisfied by a test
    that merely happens not to call the new route. The shared router is read
    directly: FastAPI mounts it -- bare and under /api -- without copying its
    routes into ``app.routes``, so one set of route objects serves both mounts
    (and the behavioural /api test above holds the two to the same answers).
    """
    routes = [r for r in (*api_router.routes, *app.routes) if isinstance(r, APIRoute)]
    assert len(routes) > 15, "the route walk found suspiciously few routes"
    admin: set[tuple[str, str]] = set()
    viewer: set[tuple[str, str]] = set()
    unguarded: set[tuple[str, str]] = set()
    for route in routes:
        calls = {dependency.call for dependency in route.dependant.dependencies}
        for method in route.methods or ():
            key = (method, route.path)
            if auth.require_admin in calls:
                admin.add(key)
            elif auth.require_viewer in calls:
                viewer.add(key)
            else:
                unguarded.add(key)

    assert unguarded == OPEN_ROUTES
    assert admin == ADMIN_ROUTES
    assert ("GET", "/scans") in viewer
    assert ("GET", "/jobs/{job_id}") in viewer


# ---------------------------------------------------------------------------
# Configuration: fail closed, and say how to fix it
# ---------------------------------------------------------------------------


def test_with_no_keys_configured_nobody_gets_in_and_the_remedy_is_named(
    raw: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(auth.ENV_API_KEYS, str(tmp_path / "absent.json"))

    response = raw.get("/scans", headers={"Authorization": "Bearer anything"})

    assert response.status_code == 401
    assert "ecdat api-key create" in response.json()["detail"]


def test_a_malformed_keys_file_fails_closed(
    raw: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = tmp_path / "keys.json"
    broken.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv(auth.ENV_API_KEYS, str(broken))

    response = raw.get("/scans", headers={"Authorization": "Bearer anything"})

    assert response.status_code == 503
    assert str(broken) in response.json()["detail"]


def test_the_conftest_env_name_is_the_real_one() -> None:
    """tests/conftest.py isolates every test with its own copy of this name."""
    from tests.conftest import ENV_API_KEYS

    assert auth.ENV_API_KEYS == ENV_API_KEYS == "ECDAT_API_KEYS"


# ---------------------------------------------------------------------------
# THE SECRET IS NOT A COMMITTED LITERAL
# ---------------------------------------------------------------------------


def _source_literals() -> set[str]:
    files = [*sorted((REPO_ROOT / "api").glob("*.py")), REPO_ROOT / "cli.py"]
    found: set[str] = set()
    for path in files:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                # A header value must be ASCII; nothing else could be sent as a key.
                if value.isascii() and value.isprintable() and len(value) < 256:
                    found.add(value)
    return found


def test_no_key_file_is_tracked_and_git_ignores_one() -> None:
    tracked = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - the developer's own git, from PATH
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    assert [p for p in tracked if "api-keys" in Path(p).name] == []
    assert "api-keys*.json" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")


def test_the_default_key_file_lives_outside_the_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(auth.ENV_API_KEYS, raising=False)

    default = auth.keys_path().resolve()

    assert REPO_ROOT not in default.parents
    assert default.name == "api-keys.json"


def test_there_is_no_built_in_credential(
    raw: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With an EMPTY key file, nothing in the source -- and no usual default --
    authenticates. So no literal in the code is a working secret."""
    empty = tmp_path / "empty.json"
    empty.write_text('{"version": 1, "keys": []}', encoding="utf-8")
    monkeypatch.setenv(auth.ENV_API_KEYS, str(empty))

    guesses = _source_literals() | {
        "admin",
        "viewer",
        "ecdat",
        "changeme",
        "secret",
        "token",
    }
    assert len(guesses) > 50, "the literal harvest found suspiciously little source"
    for guess in sorted(guesses):
        response = raw.get("/scans", headers={"Authorization": f"Bearer {guess}"})
        assert response.status_code == 401, guess


def test_the_key_file_holds_a_digest_never_the_token(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"

    token = auth.add_key("ops", "admin", path)
    text = path.read_text(encoding="utf-8")

    assert token not in text
    assert auth.digest(token) in text
    assert path.stat().st_mode & 0o077 == 0, (
        "the key file must not be group/world readable"
    )


# ---------------------------------------------------------------------------
# Offline, and constant-time
# ---------------------------------------------------------------------------


def test_authentication_makes_no_network_call(
    raw: TestClient, api_keys: ApiTokens, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("authentication tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    assert raw.get("/scans", headers=api_keys.headers("viewer")).status_code == 200


def test_every_configured_key_is_compared_in_constant_time(
    raw: TestClient, api_keys: ApiTokens, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No early exit on the first match: the time taken says nothing about WHICH
    key matched, or how far a guess got."""
    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return bool(real(a, b))

    # api.auth calls hmac.compare_digest through the module, so this is its call.
    monkeypatch.setattr(hmac, "compare_digest", spy)

    raw.get("/scans", headers=api_keys.headers("admin"))

    assert len(calls) == len(auth.load_keys())


# ---------------------------------------------------------------------------
# Provisioning: `ecdat api-key`
# ---------------------------------------------------------------------------


def test_the_cli_creates_lists_and_revokes_a_key(
    raw: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import cli

    path = tmp_path / "keys.json"
    monkeypatch.setenv(auth.ENV_API_KEYS, str(path))

    assert cli.main(["api-key", "create", "--name", "ops", "--role", "admin"]) == 0
    token = capsys.readouterr().out.strip()
    assert token
    assert token not in path.read_text(encoding="utf-8")
    whoami = raw.get("/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert whoami.json() == {"name": "ops", "role": "admin"}

    assert cli.main(["api-key", "list"]) == 0
    listing = capsys.readouterr().out
    assert "ops" in listing
    assert "admin" in listing
    assert token not in listing

    assert cli.main(["api-key", "create", "--name", "ops", "--role", "viewer"]) == 2
    assert "ops" in capsys.readouterr().err

    assert cli.main(["api-key", "revoke", "--name", "ops"]) == 0
    assert (
        raw.get("/scans", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


def test_the_cli_refuses_a_role_that_does_not_exist(tmp_path: Path) -> None:
    import cli

    with pytest.raises(SystemExit):
        cli.main(
            [
                "api-key",
                "create",
                "--name",
                "x",
                "--role",
                "root",
                "--file",
                str(tmp_path / "k.json"),
            ]
        )
