"""Test-wide safety nets: no test may ever touch the real ecdat.db -- or the
operator's real API keys.

Both fixtures are autouse on purpose. Pointing ECDAT_DB at a tmp file per test
is the sort of thing that is easy to forget in one new test module, and the
cost of forgetting is writing into the developer's actual scan history. The
same holds for ECDAT_API_KEYS (ADR-0035): a test that read the default key file
would pass or fail depending on what the developer happens to have issued.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from core import store

#: ``api.auth.ENV_API_KEYS``, spelled out so this safety net does not import
#: the API. tests/test_api_auth.py asserts the two agree.
ENV_API_KEYS = "ECDAT_API_KEYS"


@pytest.fixture(autouse=True)
def isolated_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    db_path = tmp_path / "ecdat-test.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(db_path))
    store.reset_engines()
    yield db_path
    store.reset_engines()


@pytest.fixture(autouse=True)
def isolated_api_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """This test's key file. It does not exist until a test asks for keys.

    So an API test that forgot to authenticate gets a 401 -- never the
    developer's own keys, and never a pass that depends on them.
    """
    path = tmp_path / "api-keys.json"
    monkeypatch.setenv(ENV_API_KEYS, str(path))
    return path


@dataclass(frozen=True, slots=True)
class ApiTokens:
    """One viewer key and one admin key, issued into this test's key file."""

    viewer: str
    admin: str
    path: Path

    def headers(self, role: Literal["viewer", "admin"]) -> dict[str, str]:
        token = self.admin if role == "admin" else self.viewer
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def api_keys(isolated_api_keys: Path) -> ApiTokens:
    """Issue ``test-viewer`` and ``test-admin`` the way ``ecdat api-key`` does."""
    from api import auth

    return ApiTokens(
        viewer=auth.add_key("test-viewer", "viewer", isolated_api_keys),
        admin=auth.add_key("test-admin", "admin", isolated_api_keys),
        path=isolated_api_keys,
    )


@pytest.fixture
def admin_headers(api_keys: ApiTokens) -> dict[str, str]:
    return api_keys.headers("admin")


@pytest.fixture
def viewer_headers(api_keys: ApiTokens) -> dict[str, str]:
    return api_keys.headers("viewer")
