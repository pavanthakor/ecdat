"""Enrichment: the observed view names what actually ran (ADR-0011).

Before this, an observed TLS handshake produced a finding that said "TLS,
pending". Useful as proof the probe works, useless for drift: the whole point
of the observed view is catching a repo that DECLARES a hybrid post-quantum
group while the process NEGOTIATES a classical one.

The values are read via uretprobes on libssl's public accessors, which return
``const char *`` -- so there are no struct offsets anywhere in this design and
nothing here can drift with an OpenSSL point release. The cost is coverage: an
application that never asks libssl for its own version or cipher gives us
nothing to read, and that case must be reported as UNREADABLE with a reason,
never guessed.

Root-free: this is all mapping, no kernel.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent.to_finding import (
    ENRICHMENT_FULL,
    ENRICHMENT_NONE,
    ENRICHMENT_PARTIAL,
    event_to_finding,
    event_to_findings,
)


def handshake_event(**overrides: Any) -> dict[str, Any]:
    """A successful handshake return, with everything read."""
    event: dict[str, Any] = {
        "comm": "openssl",
        "libssl_path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "phase": "return",
        "pid": 48231,
        "tid": 48231,
        "probe": "SSL_do_handshake",
        "retval": 1,
        "timestamp": 68421339115523,
        "observed_version": "TLSv1.3",
        "observed_cipher": "TLS_AES_256_GCM_SHA384",
        "observed_group": "X25519MLKEM768",
    }
    event.update(overrides)
    return event


def by_type(findings: list[Any]) -> dict[str, Any]:
    return {f"{f.asset_type}:{f.primitive}": f for f in findings}


# --------------------------------------------------------------------------
# The enriched case -- three artefacts from one handshake
# --------------------------------------------------------------------------


def test_an_enriched_event_yields_protocol_cipher_and_group() -> None:
    findings = event_to_findings(handshake_event())

    kinds = by_type(findings)
    assert "protocol:unknown" in kinds, "the negotiated VERSION is a protocol"
    assert "algorithm:block-cipher" in kinds, "the negotiated CIPHER is symmetric"
    assert "algorithm:key-agreement" in kinds, "the negotiated GROUP is key agreement"


def test_the_protocol_artefact_carries_the_real_version() -> None:
    (protocol,) = [
        f for f in event_to_findings(handshake_event()) if f.asset_type == "protocol"
    ]

    assert protocol.algorithm == "TLS"
    assert protocol.params["version"] == "TLSv1.3"
    assert protocol.view == "observed"
    assert protocol.params.get("pending_enrichment") is not True


def test_the_cipher_artefact_names_the_negotiated_suite() -> None:
    (cipher,) = [
        f for f in event_to_findings(handshake_event()) if f.primitive == "block-cipher"
    ]

    assert cipher.algorithm == "TLS_AES_256_GCM_SHA384"
    assert cipher.params["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert cipher.params["version"] == "TLSv1.3"
    assert cipher.usage == "encrypt"


def test_the_group_artefact_names_the_negotiated_key_exchange() -> None:
    """The drift beat: this is what a declared hybrid gets compared against."""
    (group,) = [
        f
        for f in event_to_findings(handshake_event())
        if f.primitive == "key-agreement"
    ]

    assert group.algorithm == "X25519MLKEM768"
    assert group.params["group"] == "X25519MLKEM768"
    assert group.usage == "key-exchange"


def test_a_hybrid_group_is_flagged_as_hybrid() -> None:
    (group,) = [
        f
        for f in event_to_findings(handshake_event())
        if f.primitive == "key-agreement"
    ]
    assert group.params.get("hybrid") is True

    (classical,) = [
        f
        for f in event_to_findings(handshake_event(observed_group="x25519"))
        if f.primitive == "key-agreement"
    ]
    assert classical.params.get("hybrid") is not True


def test_a_chacha_suite_is_a_stream_cipher() -> None:
    findings = event_to_findings(
        handshake_event(observed_cipher="TLS_CHACHA20_POLY1305_SHA256")
    )
    assert "algorithm:stream-cipher" in by_type(findings)


def test_an_enriched_event_is_marked_full() -> None:
    for finding in event_to_findings(handshake_event()):
        assert finding.params["enrichment"] == ENRICHMENT_FULL


# --------------------------------------------------------------------------
# Honest partial: unreadable is not a guess
# --------------------------------------------------------------------------


def test_a_partial_event_is_marked_and_carries_a_reason() -> None:
    findings = event_to_findings(
        handshake_event(observed_cipher=None, observed_group=None)
    )

    assert findings
    for finding in findings:
        assert finding.params["enrichment"] == ENRICHMENT_PARTIAL
        assert finding.params["enrichment_reason"]


def test_a_partial_event_invents_no_cipher() -> None:
    """The failure this whole design exists to avoid."""
    findings = event_to_findings(
        handshake_event(observed_cipher=None, observed_group=None)
    )

    blob = json.dumps([f.model_dump() for f in findings], default=str)
    assert "AES" not in blob
    assert "cipher_suite" not in blob
    assert all(f.primitive != "block-cipher" for f in findings)
    # ... but the version we DID read is still reported.
    assert any(f.params.get("version") == "TLSv1.3" for f in findings)


def test_an_explicit_unreadable_marker_is_honoured() -> None:
    findings = event_to_findings(
        handshake_event(
            observed_cipher=None,
            observed_group=None,
            enrichment_reason="accessor-not-called",
        )
    )

    assert findings[0].params["enrichment_reason"] == "accessor-not-called"


def test_an_unenriched_event_is_marked_none_not_partial() -> None:
    findings = event_to_findings(
        handshake_event(
            observed_version=None, observed_cipher=None, observed_group=None
        )
    )

    assert len(findings) == 1
    assert findings[0].params["enrichment"] == ENRICHMENT_NONE
    assert findings[0].params["pending_enrichment"] is True


# --------------------------------------------------------------------------
# Nothing is negotiated yet at entry, or on failure
# --------------------------------------------------------------------------


def test_an_entry_phase_event_carries_no_negotiated_values() -> None:
    findings = event_to_findings(
        handshake_event(
            phase="entry",
            retval=0,
            observed_version=None,
            observed_cipher=None,
            observed_group=None,
        )
    )

    assert len(findings) == 1
    assert findings[0].asset_type == "protocol"
    assert "cipher_suite" not in findings[0].params


def test_a_failed_handshake_yields_no_negotiated_values() -> None:
    """retval != 1 means nothing was agreed. Reporting a suite would be a lie."""
    findings = event_to_findings(handshake_event(retval=-1))

    assert all(f.primitive != "block-cipher" for f in findings)
    assert all("cipher_suite" not in f.params for f in findings)
    assert findings[0].params["enrichment_reason"]


def test_a_failed_handshake_still_records_the_attempt() -> None:
    findings = event_to_findings(handshake_event(retval=0))
    assert findings, "a failed handshake is still an observation"
    assert findings[0].view == "observed"


# --------------------------------------------------------------------------
# Garbage that parses
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("description", "overrides"),
    [
        ("cipher is a dict", {"observed_cipher": {"nope": 1}}),
        ("group is a list", {"observed_group": ["x"]}),
        ("version is an int", {"observed_version": 771}),
    ],
)
def test_wrong_typed_enrichment_is_skipped_not_crashed(
    description: str, overrides: dict[str, Any]
) -> None:
    assert event_to_findings(handshake_event(**overrides)) == [], description


def test_an_oversized_enrichment_value_is_refused() -> None:
    """A bad read yields a long run of bytes, not a cipher name."""
    findings = event_to_findings(handshake_event(observed_cipher="A" * 5000))

    assert all(f.primitive != "block-cipher" for f in findings)
    assert findings[0].params["enrichment"] != ENRICHMENT_FULL


def test_a_non_printable_enrichment_value_is_refused() -> None:
    """Reading the wrong address gives bytes, and bytes are not a suite name."""
    findings = event_to_findings(handshake_event(observed_cipher="\x01\x02\x03\xff"))

    assert all(f.primitive != "block-cipher" for f in findings)


def test_an_empty_enrichment_value_is_absence_not_a_name() -> None:
    findings = event_to_findings(handshake_event(observed_cipher=""))

    assert all(f.primitive != "block-cipher" for f in findings)
    assert findings[0].params["enrichment"] == ENRICHMENT_PARTIAL


def test_all_enriched_findings_share_one_locator() -> None:
    """Three artefacts, one sighting: they must agree about where they were."""
    findings = event_to_findings(handshake_event(), hostname="host-07")

    locators = {f.evidence.occurrences[0].locator for f in findings}
    assert locators == {"host:host-07:pid48231"}


def test_the_single_finding_helper_still_returns_the_principal_artefact() -> None:
    finding = event_to_finding(handshake_event())

    assert finding is not None
    assert finding.asset_type == "protocol"
    assert finding.params["version"] == "TLSv1.3"


def test_mapping_is_deterministic() -> None:
    event = handshake_event()
    first = [f.model_dump() for f in event_to_findings(event, hostname="h")]
    second = [f.model_dump() for f in event_to_findings(event, hostname="h")]
    assert first == second
