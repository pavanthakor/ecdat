"""Tests for the content-addressed Finding identity (PUNCHLIST #1).

Identity is what makes dedup and the deterministic CBOM possible, so it is
tested as a pair of opposing obligations:

  * two findings that MEAN the same artefact in the same place must hash equal,
    however they were found (different scanner, view, line, pid, confidence);
  * any change to an identifying field must change the hash.
"""

from __future__ import annotations

import pytest

from core.identity import artefact_locus, finding_identity
from core.scanner import Target
from tests.factories import finding, occurrence, repo_target

# --------------------------------------------------------------------------
# shape
# --------------------------------------------------------------------------


def test_identity_is_a_lowercase_hex_digest() -> None:
    identity = finding_identity(finding(), repo_target())

    assert len(identity) == 32
    assert identity == identity.lower()
    assert all(c in "0123456789abcdef" for c in identity)


def test_identity_is_stable_across_calls() -> None:
    target = repo_target()
    assert finding_identity(finding(), target) == finding_identity(finding(), target)


# --------------------------------------------------------------------------
# things that must NOT change identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"scanner_id": "source.treesitter"}, id="scanner_id"),
        pytest.param({"confidence": 0.4}, id="confidence"),
        pytest.param({"configurable": True}, id="configurable"),
        pytest.param({"raw": {"anything": "else"}}, id="raw"),
        pytest.param({"view": "shipped"}, id="view"),
    ],
)
def test_non_identifying_fields_do_not_change_identity(
    overrides: dict[str, object],
) -> None:
    target = repo_target()
    assert finding_identity(finding(**overrides), target) == finding_identity(
        finding(), target
    )


def test_line_number_pid_and_snippet_do_not_change_identity() -> None:
    target = repo_target()
    base = finding()

    same_file_other_line = finding(
        occurrences=[occurrence(locator="services/auth/jwt.py:411", snippet=None)]
    )
    same_file_at_runtime = finding(
        view="observed",
        occurrences=[
            occurrence(
                view="observed",
                locator="services/auth/jwt.py:pid2231",
                detail="probe=RSA_sign",
                snippet=None,
            )
        ],
    )

    assert finding_identity(same_file_other_line, target) == finding_identity(
        base, target
    )
    assert finding_identity(same_file_at_runtime, target) == finding_identity(
        base, target
    )


def test_param_key_order_does_not_change_identity() -> None:
    target = repo_target()
    a = finding(params={"key_size": 2048, "padding": "PKCS1v15"})
    b = finding(params={"padding": "PKCS1v15", "key_size": 2048})

    assert finding_identity(a, target) == finding_identity(b, target)


# --------------------------------------------------------------------------
# things that MUST change identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"asset_type": "key"}, id="asset_type"),
        pytest.param({"primitive": "pke"}, id="primitive"),
        pytest.param({"algorithm": "DSA"}, id="algorithm"),
        pytest.param({"params": {"key_size": 4096, "padding": "PKCS1v15"}}, id="param"),
        pytest.param({"params": {"key_size": 2048}}, id="param-dropped"),
        pytest.param({"usage": "verify"}, id="usage"),
        pytest.param(
            {"occurrences": [occurrence(locator="services/pay/card.py:9")]},
            id="path",
        ),
    ],
)
def test_identifying_fields_change_identity(overrides: dict[str, object]) -> None:
    target = repo_target()
    assert finding_identity(finding(**overrides), target) != finding_identity(
        finding(), target
    )


def test_same_artefact_in_different_systems_has_different_identity() -> None:
    f = finding()
    auth = Target(kind="repo", ref="/srv/quantumbank", system="auth")
    ledger = Target(kind="repo", ref="/srv/quantumbank", system="ledger")

    assert finding_identity(f, auth) != finding_identity(f, ledger)


def test_locus_prefers_system_over_ref() -> None:
    f = finding()
    tagged = Target(kind="repo", ref="/srv/quantumbank", system="auth")
    other_checkout = Target(kind="repo", ref="/home/dev/quantumbank", system="auth")

    # The same service checked out in two places is the same artefact.
    assert finding_identity(f, tagged) == finding_identity(f, other_checkout)


# --------------------------------------------------------------------------
# locus normalisation rules
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("view", "locator", "expected"),
    [
        # declared/shipped: a trailing :<n> is a line number or offset -> dropped
        ("declared", "services/auth/jwt.py:42", "services/auth/jwt.py"),
        ("shipped", "sha256:9f3a/layer/4", "sha256:9f3a/layer/4"),
        (
            "shipped",
            "sha256:9f3a/etc/ssl/certs/api.pem:3",
            "sha256:9f3a/etc/ssl/certs/api.pem",
        ),
        # observed: a pid is not part of the artefact, a port is
        ("observed", "host-07:pid2231", "host-07"),
        ("observed", "api.quantumbank.in:443", "api.quantumbank.in:443"),
        # repo-relative and absolute paths for the same file agree
        (
            "declared",
            "/srv/quantumbank/services/auth/jwt.py:42",
            "services/auth/jwt.py",
        ),
        ("declared", "./services/auth/jwt.py", "services/auth/jwt.py"),
    ],
)
def test_locator_normalisation(view: str, locator: str, expected: str) -> None:
    f = finding(view=view, occurrences=[occurrence(view=view, locator=locator)])

    assert artefact_locus(f, repo_target()) == f"quantumbank\x1f{expected}"


def test_observed_port_is_part_of_the_locus() -> None:
    target = repo_target()
    a = finding(
        view="observed", occurrences=[occurrence(view="observed", locator="h:443")]
    )
    b = finding(
        view="observed", occurrences=[occurrence(view="observed", locator="h:8443")]
    )

    assert finding_identity(a, target) != finding_identity(b, target)


def test_locus_of_a_multi_occurrence_finding_covers_every_place() -> None:
    target = repo_target()
    one = finding(occurrences=[occurrence(locator="a.py:1")])
    two = finding(
        occurrences=[occurrence(locator="a.py:1"), occurrence(locator="b.py:2")]
    )

    assert finding_identity(one, target) != finding_identity(two, target)
    # ... and the order the occurrences arrive in must not matter.
    two_reversed = finding(
        occurrences=[occurrence(locator="b.py:2"), occurrence(locator="a.py:1")]
    )
    assert finding_identity(two, target) == finding_identity(two_reversed, target)
