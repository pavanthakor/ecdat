"""Test-wide safety net: no test may ever touch the real ecdat.db.

The fixture is autouse on purpose. Pointing ECDAT_DB at a tmp file per test is
the sort of thing that is easy to forget in one new test module, and the cost
of forgetting is writing into the developer's actual scan history.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from core import store


@pytest.fixture(autouse=True)
def isolated_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    db_path = tmp_path / "ecdat-test.db"
    monkeypatch.setenv(store.ENV_DB_PATH, str(db_path))
    store.reset_engines()
    yield db_path
    store.reset_engines()
