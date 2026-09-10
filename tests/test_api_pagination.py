"""ADR-0035 PART C -- a list that grows with use is paginated.

`GET /scans` returned every row the store had ever written, rescores included
-- and every Mosca slider settle writes one. It now answers one page:
``{"items": [...], "total": N, "limit": L, "offset": O}``, newest first, with a
default page size and a ceiling. `GET /jobs` pages the same way.

A list bounded by one document (a scan's fixes, a compare) or by a fixed
registry (the scanner ids) is not paginated: it cannot grow with use.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from api.app import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, app
from core import store
from core.scanner import Target
from tests.conftest import ApiTokens


@pytest.fixture
def client(api_keys: ApiTokens) -> Iterator[TestClient]:
    with TestClient(app, headers=api_keys.headers("viewer")) as test_client:
        yield test_client


def seed(count: int) -> list[str]:
    return [
        store.save_scan(Target(kind="repo", ref=f"/repo/{index}"), '{"components":[]}')
        for index in range(count)
    ]


def ids(page: dict[str, object]) -> list[str]:
    items = page["items"]
    assert isinstance(items, list)
    return [str(item["id"]) for item in items]


def test_limit_returns_that_many_items_and_the_total(client: TestClient) -> None:
    seed(5)

    page = client.get("/scans", params={"limit": 2}).json()

    assert len(page["items"]) == 2
    assert page["total"] == 5
    assert page["limit"] == 2
    assert page["offset"] == 0


def test_offset_advances_through_the_list_without_overlap_or_gap(
    client: TestClient,
) -> None:
    seed(5)
    everything = ids(client.get("/scans", params={"limit": 100}).json())

    pages = [
        ids(client.get("/scans", params={"limit": 2, "offset": offset}).json())
        for offset in (0, 2, 4)
    ]

    assert pages == [everything[0:2], everything[2:4], everything[4:5]]
    assert len(everything) == 5


def test_the_newest_row_is_first(client: TestClient) -> None:
    seed(3)
    newest = store.save_scan(
        Target(kind="repo", ref="/repo/newest"), '{"components":[]}'
    )

    page = client.get("/scans", params={"limit": 1}).json()

    assert ids(page) == [newest]


def test_the_default_page_size_is_applied(client: TestClient) -> None:
    seed(DEFAULT_PAGE_SIZE + 3)

    page = client.get("/scans").json()

    assert len(page["items"]) == DEFAULT_PAGE_SIZE
    assert page["limit"] == DEFAULT_PAGE_SIZE
    assert page["total"] == DEFAULT_PAGE_SIZE + 3


def test_an_offset_past_the_end_is_an_empty_page_not_an_error(
    client: TestClient,
) -> None:
    seed(2)

    page = client.get("/scans", params={"offset": 10}).json()

    assert page["items"] == []
    assert page["total"] == 2


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": -1}, {"limit": MAX_PAGE_SIZE + 1}, {"offset": -1}],
)
def test_a_page_outside_the_bounds_is_refused(
    client: TestClient, params: dict[str, int]
) -> None:
    assert client.get("/scans", params=params).status_code == 422


def test_the_total_counts_only_the_requested_kind(client: TestClient) -> None:
    (parent,) = seed(1)
    store.save_rescore(parent, '{"components":[]}')

    scans = client.get("/scans", params={"kind": "scan"}).json()
    everything = client.get("/scans").json()

    assert scans["total"] == 1
    assert everything["total"] == 2


def test_jobs_are_paginated_the_same_way(client: TestClient) -> None:
    for index in range(3):
        store.create_job("scan", subject=f"repo /repo/{index}")

    page = client.get("/jobs", params={"limit": 2}).json()

    assert len(page["items"]) == 2
    assert page["total"] == 3
    assert client.get("/jobs", params={"limit": 2, "offset": 2}).json()["items"][0][
        "id"
    ]
