"""Three-view drift detection (ADR-0012). Pillar 2's payoff.

Every previous slice was building toward one question: **does what a system
declares match what it ships and what it actually does?** All three views now
land in one CBOM, and this is where they are joined.

The rules are ordered by how much they need to be true. R1 needs nothing
running -- a config that asks for a post-quantum group against a shipped
OpenSSL that has no ML-KEM in it is a defect you can prove from the image
alone. R2 is the headline and needs a live handshake.

Two failure modes matter more than any detection here, and most of this file is
about them:

* **Drift must never be invented from absence.** A missing view is a COVERAGE
  GAP, reported as such. Telling an operator their config disagrees with
  runtime, when there is no runtime observation at all, is the fastest way to
  make the whole tool ignorable.
* **A partial observation must not become a hard claim.** When the process
  never asked libssl for its group (ADR-0011), the honest finding is "declared
  hybrid, observed UNCONFIRMED" -- a real signal that does not overclaim.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from correlate.apply import DRIFT_FLOOR_BAND, DRIFT_RISK_MULTIPLIER, apply_drift
from correlate.drift import (
    KIND_CIPHER_OUTSIDE_SET,
    KIND_DECLARED_PQC_OBSERVED_CLASSICAL,
    KIND_DECLARED_PQC_UNCONFIRMED,
    KIND_PROTOCOL_DOWNGRADE,
    KIND_SHIPPED_CANNOT_DO_DECLARED,
    detect,
)
from correlate.identity import group_components

SYSTEM = "quantumbank"


def component(
    name: str,
    view: str,
    *,
    asset_type: str = "algorithm",
    primitive: str = "unknown",
    params: dict[str, Any] | None = None,
    locator: str = "somewhere",
    score: int = 20,
    band: str = "Low",
) -> dict[str, Any]:
    properties = [
        {"name": "ecdat:view", "value": view},
        {"name": "ecdat:asset_type", "value": asset_type},
        {"name": "ecdat:score", "value": str(score)},
        {"name": "ecdat:band", "value": band},
    ]
    for key, value in sorted((params or {}).items()):
        properties.append({"name": f"ecdat:param:{key}", "value": str(value)})
    crypto: dict[str, Any] = {"assetType": asset_type}
    if asset_type == "algorithm":
        crypto["algorithmProperties"] = {"primitive": primitive}
    return {
        "bom-ref": f"{name}-{view}-{locator}",
        "name": name,
        "type": "cryptographic-asset",
        "cryptoProperties": crypto,
        "properties": sorted(properties, key=lambda p: p["name"]),
        "evidence": {"occurrences": [{"location": locator}]},
    }


# --- the three views of one endpoint, as the demo case has them --------------


def declared_hybrid_group(
    *, score: int = 20, band: str = "Low", **overrides: Any
) -> dict[str, Any]:
    """What nginx.conf asks for: a hybrid post-quantum key exchange."""
    params = {
        "group": "X25519MLKEM768",
        "hybrid": "True",
        "endpoint": "0.0.0.0:443",
        "role": "tls-server",
    }
    params.update(overrides)
    return component(
        str(params["group"]),
        "declared",
        primitive="key-agreement",
        params=params,
        locator="etc/nginx/nginx.conf:18",
        score=score,
        band=band,
    )


def shipped_openssl(version: str = "3.0.2", pqc: str = "False") -> dict[str, Any]:
    """The real ubuntu:22.04 fact from ADR-0006: libssl3 3.0.2, no ML-KEM."""
    return component(
        "OpenSSL",
        "shipped",
        asset_type="library",
        params={"version": version, "package": "libssl3", "pqc_capable": pqc},
        locator="sha256:e1c8/var/lib/dpkg/status",
        score=40,
        band="Medium",
    )


def observed_group(group: str = "x25519", **overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"group": group, "enrichment": "full"}
    params.update(overrides)
    return component(
        group,
        "observed",
        primitive="key-agreement",
        params=params,
        locator="host:api-07:pid2231",
    )


def cbom(*components: dict[str, Any]) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": SYSTEM, "type": "application"}},
            "components": list(components),
        }
    )


def drifts(*components: dict[str, Any]) -> list[Any]:
    document = json.loads(cbom(*components))
    found = []
    for group in group_components(document["components"], SYSTEM):
        found.extend(detect(group))
    return found


def drift_properties(scored: str) -> list[dict[str, list[str]]]:
    out = []
    for comp in json.loads(scored)["components"]:
        collected: dict[str, list[str]] = {}
        for prop in comp["properties"]:
            collected.setdefault(prop["name"], []).append(prop["value"])
        if any(k.startswith("ecdat:drift:") for k in collected):
            out.append(collected)
    return out


# --------------------------------------------------------------------------
# R1 -- SHIPPED CANNOT DO DECLARED. Leads, because it needs nothing running.
# --------------------------------------------------------------------------


def test_r1_shipped_libssl_cannot_do_the_declared_hybrid_group() -> None:
    """The most reliable drift there is: provable from the image alone.

    ubuntu:22.04 ships libssl3 3.0.2; ML-KEM arrived in OpenSSL 3.5.0. A config
    asking for X25519MLKEM768 against that library cannot work, and no handshake
    has to happen for us to know it.
    """
    found = drifts(declared_hybrid_group(), shipped_openssl("3.0.2", "False"))

    hits = [d for d in found if d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED]
    assert len(hits) == 1
    assert hits[0].declared == "X25519MLKEM768"
    assert "3.0.2" in hits[0].observed


def test_r1_names_the_missing_capability_as_the_cause() -> None:
    (hit,) = [
        d
        for d in drifts(declared_hybrid_group(), shipped_openssl("3.0.2", "False"))
        if d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED
    ]

    assert "ML-KEM" in hit.cause
    assert "3.0.2" in hit.cause


def test_r1_needs_no_observed_view_at_all() -> None:
    """The point of leading with R1: it works on a repo and an image."""
    found = drifts(declared_hybrid_group(), shipped_openssl("3.0.2", "False"))
    assert any(d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED for d in found)


def test_r1_is_silent_when_the_shipped_library_can_do_it() -> None:
    """alpine:3.22 ships 3.5.7, which has ML-KEM. No drift."""
    found = drifts(declared_hybrid_group(), shipped_openssl("3.5.7", "True"))
    assert [d for d in found if d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED] == []


def test_r1_is_silent_when_the_declaration_is_not_hybrid() -> None:
    found = drifts(
        declared_hybrid_group(group="x25519", hybrid="False"),
        shipped_openssl("3.0.2", "False"),
    )
    assert [d for d in found if d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED] == []


def test_r1_does_not_fire_when_pqc_capability_is_unknown() -> None:
    """knowledge/libraries.yaml leaves pqc_capable ABSENT where it does not
    know (ADR-0006). Unknown must not be read as incapable."""
    shipped = shipped_openssl("3.8.0")
    shipped["properties"] = [
        p for p in shipped["properties"] if p["name"] != "ecdat:param:pqc_capable"
    ]

    found = drifts(declared_hybrid_group(), shipped)
    assert [d for d in found if d.kind == KIND_SHIPPED_CANNOT_DO_DECLARED] == []


# --------------------------------------------------------------------------
# R2 -- the headline, and the honesty case beside it
# --------------------------------------------------------------------------


def test_r2_declared_hybrid_versus_observed_classical_is_drift() -> None:
    found = drifts(declared_hybrid_group(), observed_group("x25519"))

    (hit,) = [d for d in found if d.kind == KIND_DECLARED_PQC_OBSERVED_CLASSICAL]
    assert hit.declared == "X25519MLKEM768"
    assert hit.observed == "x25519"


def test_r2_is_silent_when_the_observed_group_is_also_hybrid() -> None:
    found = drifts(
        declared_hybrid_group(),
        observed_group("X25519MLKEM768", hybrid="True"),
    )
    assert [
        d
        for d in found
        if d.kind
        in (KIND_DECLARED_PQC_OBSERVED_CLASSICAL, KIND_DECLARED_PQC_UNCONFIRMED)
    ] == []


def test_a_partial_observation_yields_the_weaker_unconfirmed_signal() -> None:
    """ADR-0011: the process never asked libssl for its group.

    "Declared hybrid, observed unconfirmed" is a real finding. Calling it a
    downgrade would be a false positive, and one false positive of this kind
    teaches an operator to disbelieve the whole report.
    """
    partial = observed_group("x25519")
    partial["properties"] = [
        p for p in partial["properties"] if p["name"] != "ecdat:param:group"
    ] + [
        {"name": "ecdat:param:enrichment", "value": "partial"},
        {"name": "ecdat:param:enrichment_reason", "value": "group not read"},
    ]

    found = drifts(declared_hybrid_group(), partial)

    kinds = {d.kind for d in found}
    assert KIND_DECLARED_PQC_UNCONFIRMED in kinds
    assert KIND_DECLARED_PQC_OBSERVED_CLASSICAL not in kinds, (
        "a partial observation must never become a hard downgrade claim"
    )


def test_the_unconfirmed_signal_says_it_is_unconfirmed() -> None:
    partial = observed_group("x25519")
    partial["properties"] = [
        p for p in partial["properties"] if p["name"] != "ecdat:param:group"
    ] + [{"name": "ecdat:param:enrichment", "value": "partial"}]

    (hit,) = [
        d
        for d in drifts(declared_hybrid_group(), partial)
        if d.kind == KIND_DECLARED_PQC_UNCONFIRMED
    ]
    assert "unconfirmed" in hit.observed.lower()
    assert hit.cause


def test_the_unconfirmed_signal_is_weaker_than_a_hard_drift() -> None:
    partial = observed_group("x25519")
    partial["properties"] = [
        p for p in partial["properties"] if p["name"] != "ecdat:param:group"
    ] + [{"name": "ecdat:param:enrichment", "value": "partial"}]

    (soft,) = [
        d
        for d in drifts(declared_hybrid_group(), partial)
        if d.kind == KIND_DECLARED_PQC_UNCONFIRMED
    ]
    (hard,) = [
        d
        for d in drifts(declared_hybrid_group(), observed_group("x25519"))
        if d.kind == KIND_DECLARED_PQC_OBSERVED_CLASSICAL
    ]

    assert soft.confidence < hard.confidence


# --------------------------------------------------------------------------
# R3 protocol, R4 cipher
# --------------------------------------------------------------------------


def test_r3_declared_tls13_only_versus_observed_tls12_is_drift() -> None:
    declared = component(
        "TLS",
        "declared",
        asset_type="protocol",
        params={
            "version": "TLSv1.3",
            "min_version": "TLSv1.3",
            "endpoint": "0.0.0.0:443",
        },
        locator="etc/nginx/nginx.conf:12",
    )
    observed = component(
        "TLS",
        "observed",
        asset_type="protocol",
        params={"version": "TLSv1.2"},
        locator="host:api-07:pid2231",
    )

    (hit,) = [
        d for d in drifts(declared, observed) if d.kind == KIND_PROTOCOL_DOWNGRADE
    ]
    assert hit.declared == "TLSv1.3"
    assert hit.observed == "TLSv1.2"


def test_r3_is_silent_when_the_observed_version_meets_the_declaration() -> None:
    declared = component(
        "TLS",
        "declared",
        asset_type="protocol",
        params={"min_version": "TLSv1.2", "endpoint": "0.0.0.0:443"},
    )
    observed = component(
        "TLS", "observed", asset_type="protocol", params={"version": "TLSv1.3"}
    )
    assert [
        d for d in drifts(declared, observed) if d.kind == KIND_PROTOCOL_DOWNGRADE
    ] == []


def test_r4_observed_suite_outside_the_declared_set_is_drift() -> None:
    declared = component(
        "TLS",
        "declared",
        asset_type="protocol",
        params={
            "cipher_suites": "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256",
            "endpoint": "0.0.0.0:443",
        },
        locator="etc/nginx/nginx.conf:14",
    )
    observed = component(
        "TLS_AES_128_GCM_SHA256",
        "observed",
        primitive="block-cipher",
        params={"cipher_suite": "TLS_AES_128_GCM_SHA256", "enrichment": "full"},
        locator="host:api-07:pid2231",
    )

    (hit,) = [
        d for d in drifts(declared, observed) if d.kind == KIND_CIPHER_OUTSIDE_SET
    ]
    assert hit.observed == "TLS_AES_128_GCM_SHA256"


def test_r4_is_silent_when_the_observed_suite_is_in_the_set() -> None:
    declared = component(
        "TLS",
        "declared",
        asset_type="protocol",
        params={"cipher_suites": "TLS_AES_256_GCM_SHA384", "endpoint": "0.0.0.0:443"},
    )
    observed = component(
        "TLS_AES_256_GCM_SHA384",
        "observed",
        primitive="block-cipher",
        params={"cipher_suite": "TLS_AES_256_GCM_SHA384", "enrichment": "full"},
    )
    assert [
        d for d in drifts(declared, observed) if d.kind == KIND_CIPHER_OUTSIDE_SET
    ] == []


# --------------------------------------------------------------------------
# Agreement, and absence. The two ways to get this wrong.
# --------------------------------------------------------------------------


def test_full_agreement_produces_no_drift_at_all() -> None:
    declared = component(
        "TLS",
        "declared",
        asset_type="protocol",
        params={
            "min_version": "TLSv1.3",
            "cipher_suites": "TLS_AES_256_GCM_SHA384",
            "endpoint": "0.0.0.0:443",
        },
    )
    observed_protocol = component(
        "TLS", "observed", asset_type="protocol", params={"version": "TLSv1.3"}
    )
    observed_suite = component(
        "TLS_AES_256_GCM_SHA384",
        "observed",
        primitive="block-cipher",
        params={"cipher_suite": "TLS_AES_256_GCM_SHA384", "enrichment": "full"},
    )

    assert drifts(declared, observed_protocol, observed_suite) == []


@pytest.mark.parametrize(
    ("description", "present"),
    [
        ("declared only", ("declared",)),
        ("shipped only", ("shipped",)),
        ("observed only", ("observed",)),
        ("declared + nothing to compare", ("declared",)),
    ],
)
def test_a_missing_view_is_a_gap_and_never_a_drift(
    description: str, present: tuple[str, ...]
) -> None:
    """Never invent drift from absence.

    Telling an operator their config disagrees with runtime when there IS no
    runtime observation is the fastest way to make the whole report ignorable.
    """
    available = {
        "declared": declared_hybrid_group(),
        "shipped": shipped_openssl(),
        "observed": observed_group(),
    }
    found = drifts(*[available[view] for view in present])

    assert found == [], f"{description} invented drift from absence"


def test_a_missing_view_is_reported_as_coverage() -> None:
    document = json.loads(cbom(declared_hybrid_group()))
    (group,) = group_components(document["components"], SYSTEM)

    assert group.views == {"declared"}
    assert group.missing_views == {"shipped", "observed"}
    assert not group.is_complete


def test_uncorrelated_components_are_never_forced_together() -> None:
    """Two endpoints must not be joined just because they are in one system."""
    a = declared_hybrid_group(endpoint="0.0.0.0:443")
    b = component(
        "x25519",
        "declared",
        primitive="key-agreement",
        params={"group": "x25519", "endpoint": "0.0.0.0:8443"},
    )
    document = json.loads(cbom(a, b))

    groups = group_components(document["components"], SYSTEM)
    endpoints = {g.key.endpoint for g in groups}
    assert endpoints == {"0.0.0.0:443", "0.0.0.0:8443"}


# --------------------------------------------------------------------------
# Peer attribution comes from the occurrence, not the identity
# --------------------------------------------------------------------------


def test_peer_attribution_is_read_from_the_occurrence_detail() -> None:
    """_drop_position folds client and server into one component (ADR-0002),
    so which PEER drifted has to come from the evidence."""
    observed = observed_group("x25519")
    observed["evidence"] = {
        "occurrences": [
            {
                "location": "host:api-07:pid2231",
                "additionalContext": "probe=SSL_do_handshake :: nginx via libssl",
            },
            {
                "location": "host:api-07:pid2240",
                "additionalContext": "probe=SSL_do_handshake :: curl via libssl",
            },
        ]
    }

    (hit,) = [
        d
        for d in drifts(declared_hybrid_group(), observed)
        if d.kind == KIND_DECLARED_PQC_OBSERVED_CLASSICAL
    ]

    peers = " ".join(hit.peers)
    assert "nginx" in peers
    assert "curl" in peers


# --------------------------------------------------------------------------
# The drift effect
# --------------------------------------------------------------------------


def test_a_drifted_component_is_floored_to_high() -> None:
    """An inventory ERROR is worse than a known weakness: you cannot plan
    around a system that is not doing what it says."""
    scored = apply_drift(cbom(declared_hybrid_group(), shipped_openssl("3.0.2")))

    (drifted,) = drift_properties(scored)
    assert drifted["ecdat:band"][0] in ("High", "Critical")


def test_the_drift_multiplier_is_applied_over_the_pre_drift_score() -> None:
    before = 40
    scored = apply_drift(
        cbom(declared_hybrid_group(score=before), shipped_openssl("3.0.2"))
    )

    (drifted,) = drift_properties(scored)
    assert int(drifted["ecdat:score"][0]) >= int(before * DRIFT_RISK_MULTIPLIER)
    assert drifted["ecdat:drift:pre_drift_score"] == [str(before)]


def test_the_floor_is_load_bearing() -> None:
    """A low-scoring component that drifts must still surface.

    If this passes with the floor removed, the floor is doing nothing.
    """
    scored = apply_drift(
        cbom(declared_hybrid_group(score=4, band="Low"), shipped_openssl("3.0.2"))
    )

    (drifted,) = drift_properties(scored)
    assert drifted["ecdat:band"][0] == DRIFT_FLOOR_BAND
    assert int(drifted["ecdat:score"][0]) > 4


def test_an_undrifted_component_keeps_its_score() -> None:
    scored = apply_drift(
        cbom(declared_hybrid_group(), shipped_openssl("3.5.7", "True"))
    )

    assert drift_properties(scored) == []
    for comp in json.loads(scored)["components"]:
        values = {p["name"]: p["value"] for p in comp["properties"]}
        assert "ecdat:drift:kind" not in values


def test_drift_properties_name_both_sides_and_the_cause() -> None:
    scored = apply_drift(cbom(declared_hybrid_group(), shipped_openssl("3.0.2")))

    (drifted,) = drift_properties(scored)
    assert drifted["ecdat:drift:kind"] == [KIND_SHIPPED_CANNOT_DO_DECLARED]
    assert drifted["ecdat:drift:declared"] == ["X25519MLKEM768"]
    assert "3.0.2" in drifted["ecdat:drift:observed"][0]
    assert "ML-KEM" in drifted["ecdat:drift:cause"][0]
    assert len(drifted["ecdat:drift:evidence"]) >= 2, "each view must be cited"


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_correlation_is_byte_stable() -> None:
    document = cbom(declared_hybrid_group(), shipped_openssl("3.0.2"), observed_group())

    assert apply_drift(document) == apply_drift(document)


def test_component_order_does_not_change_the_output() -> None:
    parts = [declared_hybrid_group(), shipped_openssl("3.0.2"), observed_group()]
    baseline = apply_drift(cbom(*parts))
    rng = random.Random(20260909)

    for _ in range(8):
        shuffled = list(parts)
        rng.shuffle(shuffled)
        assert apply_drift(cbom(*shuffled)) == baseline


def test_applying_drift_twice_is_idempotent() -> None:
    once = apply_drift(cbom(declared_hybrid_group(), shipped_openssl("3.0.2")))
    assert apply_drift(once) == once


# --------------------------------------------------------------------------
# The demo case, end to end
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_the_demo_case_produces_named_high_drift() -> None:
    """Declared hybrid + shipped 3.0.2 + observed classical, one endpoint."""
    scored = apply_drift(
        cbom(
            declared_hybrid_group(),
            shipped_openssl("3.0.2", "False"),
            observed_group("x25519"),
            component(
                "TLS",
                "observed",
                asset_type="protocol",
                params={"version": "TLSv1.3"},
                locator="host:api-07:pid2231",
            ),
        )
    )

    drifted = drift_properties(scored)
    assert drifted, "the demo case produced no drift"

    kinds = {k for d in drifted for k in d["ecdat:drift:kind"]}
    assert KIND_SHIPPED_CANNOT_DO_DECLARED in kinds
    assert KIND_DECLARED_PQC_OBSERVED_CLASSICAL in kinds

    for entry in drifted:
        assert entry["ecdat:band"][0] in ("High", "Critical")
        assert entry["ecdat:drift:cause"][0]
