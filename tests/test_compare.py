"""Compare two stored scans (ADR-0031).

The console's Compare Scans screen reads this endpoint rather than diffing two
CBOMs in the browser. The console reads, it does not compute (ADR-0018), and a
diff is a computation whose join rule -- the bom-ref -- belongs with the code
that minted it.

The join is the content-addressed bom-ref (ADR-0002), which makes the buckets
exact rather than heuristic:

* NEW       -- a bom-ref only the head scan has
* RESOLVED  -- a bom-ref only the base scan has
* CHANGED   -- the same bom-ref with a different verdict or different evidence
* DRIFT INTRODUCED / RESOLVED -- a drift record on one side and not the other

It is also the stated limit. The bom-ref hashes the set of PLACES an artefact
was seen, so an artefact that gained or lost a sighting place reports as
resolved + new, never as "changed". A moved LINE keeps its bom-ref (ADR-0002
drops positions from the locus) and reports as changed evidence.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.app import app
from core.compare import compare_documents

MINIMAL_REPO = "testdata/minimal_repo"
MINIMAL_COMPONENTS = 2


def component(
    ref: str,
    name: str = "RSA",
    *,
    band: str = "Low",
    score: int = 10,
    deadline: str | None = None,
    occurrences: tuple[str, ...] = ("declared|app/keys.py:3|source|rule=py-rsa",),
    drift: tuple[tuple[str, str, str], ...] = (),
) -> dict[str, Any]:
    properties = [
        {"name": "ecdat:band", "value": band},
        {"name": "ecdat:score", "value": str(score)},
    ]
    if deadline is not None:
        properties.append({"name": "ecdat:deadline", "value": deadline})
    properties.extend({"name": "ecdat:occurrence", "value": o} for o in occurrences)
    for kind, declared, observed in drift:
        properties.extend(
            [
                {"name": "ecdat:drift:kind", "value": kind},
                {"name": "ecdat:drift:declared", "value": declared},
                {"name": "ecdat:drift:observed", "value": observed},
                {"name": "ecdat:drift:cause", "value": f"{declared} vs {observed}"},
            ]
        )
    return {"bom-ref": ref, "name": name, "properties": properties}


def document(*components: dict[str, Any]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": list(components),
    }


# ---------------------------------------------------------------------------
# The buckets
# ---------------------------------------------------------------------------


def test_identical_documents_have_no_differences() -> None:
    doc = document(component("a"), component("b", "MD5"))
    result = compare_documents(doc, doc)

    assert result.new == []
    assert result.resolved == []
    assert result.changed == []
    assert result.drift_introduced == []
    assert result.drift_resolved == []
    assert result.unchanged == 2


def test_a_component_only_in_the_head_is_new() -> None:
    result = compare_documents(
        document(component("a")), document(component("a"), component("b", "MD5"))
    )
    assert [entry.bom_ref for entry in result.new] == ["b"]
    assert result.new[0].name == "MD5"
    assert result.resolved == []


def test_a_component_only_in_the_base_is_resolved() -> None:
    result = compare_documents(
        document(component("a"), component("b", "MD5")), document(component("a"))
    )
    assert [entry.bom_ref for entry in result.resolved] == ["b"]
    assert result.new == []


def test_a_new_verdict_on_the_same_artefact_is_changed_with_both_sides() -> None:
    """A rescore moves verdicts and keeps bom-refs -- the Mosca slider's diff."""
    result = compare_documents(
        document(component("a", band="High", score=65)),
        document(component("a", band="Critical", score=81)),
    )

    assert len(result.changed) == 1
    change = result.changed[0]
    assert change.fields == ["band", "score"]
    assert (change.before.band, change.before.score) == ("High", 65)
    assert (change.after.band, change.after.score) == ("Critical", 81)
    assert result.new == [] and result.resolved == []


def test_a_new_deadline_is_a_change() -> None:
    result = compare_documents(
        document(component("a")), document(component("a", deadline="2027-12-31"))
    )
    assert result.changed[0].fields == ["deadline"]
    assert result.changed[0].after.deadline == "2027-12-31"


def test_a_moved_line_is_changed_evidence_not_new_and_resolved() -> None:
    """Same bom-ref, different sighting: the changed-evidence list."""
    result = compare_documents(
        document(component("a", occurrences=("declared|app/keys.py:3|source|r",))),
        document(component("a", occurrences=("declared|app/keys.py:9|source|r",))),
    )

    assert result.new == [] and result.resolved == []
    change = result.changed[0]
    assert change.fields == ["evidence"]
    assert change.evidence_added == ["declared|app/keys.py:9|source|r"]
    assert change.evidence_removed == ["declared|app/keys.py:3|source|r"]


def test_drift_only_in_the_head_is_introduced() -> None:
    drift = (("declared-pqc-observed-classical", "X25519MLKEM768", "x25519"),)
    result = compare_documents(
        document(component("a")), document(component("a", drift=drift))
    )

    assert len(result.drift_introduced) == 1
    introduced = result.drift_introduced[0]
    assert introduced.kind == "declared-pqc-observed-classical"
    assert (introduced.declared, introduced.observed) == ("X25519MLKEM768", "x25519")
    assert introduced.cause == "X25519MLKEM768 vs x25519"
    assert result.drift_resolved == []


def test_drift_only_in_the_base_is_resolved() -> None:
    drift = (("protocol-downgrade", "TLSv1.3", "TLSv1.2"),)
    result = compare_documents(
        document(component("a", drift=drift)), document(component("a"))
    )
    assert [d.kind for d in result.drift_resolved] == ["protocol-downgrade"]
    assert result.drift_introduced == []


def test_drift_on_a_new_component_counts_as_introduced() -> None:
    """A new artefact that arrives already drifting introduced that drift."""
    drift = (("cipher-outside-declared-set", "AES128-SHA", "TLS_AES_256_GCM_SHA384"),)
    result = compare_documents(document(), document(component("n", drift=drift)))
    assert [d.bom_ref for d in result.drift_introduced] == ["n"]
    assert [e.bom_ref for e in result.new] == ["n"]


def test_duplicate_drift_records_are_one_drift() -> None:
    """The correlator writes one record per PEER; a diff counts the drift once."""
    drift = (
        ("cipher-outside-declared-set", "AES128-SHA", "TLS_AES_256_GCM_SHA384"),
        ("cipher-outside-declared-set", "AES128-SHA", "TLS_AES_256_GCM_SHA384"),
    )
    result = compare_documents(
        document(component("a")), document(component("a", drift=drift))
    )
    assert len(result.drift_introduced) == 1


def test_the_comparison_is_deterministic_under_component_order() -> None:
    base = [component(r, f"n{r}", score=i) for i, r in enumerate("abcdef")]
    head = [component(r, f"n{r}", score=i + 1) for i, r in enumerate("cdefgh")]
    expected = compare_documents(document(*base), document(*head))

    shuffler = random.Random(7)
    for _ in range(5):
        shuffler.shuffle(base)
        shuffler.shuffle(head)
        assert compare_documents(document(*base), document(*head)) == expected


# ---------------------------------------------------------------------------
# The endpoint, against real stored scans
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def post_scan_id(client: TestClient, **body: object) -> str:
    response = client.post("/scans", json={"kind": "repo", "ref": MINIMAL_REPO, **body})
    assert response.status_code == 201, response.text
    scan_id = response.json()["scan_id"]
    assert isinstance(scan_id, str)
    return scan_id


def test_a_scan_against_its_own_rescore_changes_verdicts_and_nothing_else(
    client: TestClient,
) -> None:
    # pii (x = 25y): moving the horizon from 5y to 20y takes the Mosca term from
    # 30 to 15, so verdicts move. (Sovereign data, x = 50y, is exposed at BOTH 3y
    # and 30y -- that rescore is a genuine no-op, and compare reports it as one.)
    scan_id = post_scan_id(client, data_class="pii", z_years=5)
    rescored = client.post(f"/scans/{scan_id}/rescore", params={"z_years": 20})
    rescored_id = rescored.json()["scan_id"]

    response = client.get(f"/scans/{scan_id}/compare/{rescored_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["base"]["id"] == scan_id
    assert body["head"]["id"] == rescored_id
    assert body["head"]["kind"] == "rescore"
    # Nothing was re-scanned, so nothing can have appeared or disappeared.
    assert body["new"] == [] and body["resolved"] == []
    assert body["changed"], "a 5y -> 20y horizon moved no verdict at all"
    assert len(body["changed"]) + body["unchanged"] == MINIMAL_COMPONENTS
    for change in body["changed"]:
        assert "evidence" not in change["fields"]
        for field in change["fields"]:
            assert change["before"][field] != change["after"][field]


def test_two_scans_of_the_same_target_join_on_bom_ref(client: TestClient) -> None:
    first = post_scan_id(client)
    second = post_scan_id(client)

    body = client.get(f"/scans/{first}/compare/{second}").json()

    assert body["new"] == [] and body["resolved"] == [] and body["changed"] == []
    assert body["unchanged"] == MINIMAL_COMPONENTS


def test_compare_with_an_unknown_scan_is_404_on_either_side(client: TestClient) -> None:
    known = post_scan_id(client)
    assert client.get(f"/scans/nope/compare/{known}").status_code == 404
    assert client.get(f"/scans/{known}/compare/nope").status_code == 404


def test_compare_is_served_under_the_console_prefix(client: TestClient) -> None:
    known = post_scan_id(client)
    assert client.get(f"/api/scans/{known}/compare/{known}").status_code == 200
