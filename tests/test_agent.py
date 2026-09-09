"""Runtime agent, slice 1: the parts that need neither root nor bcc.

The probe itself can only be proved by a human with sudo on a real handshake
(ADR-0009), so this suite deliberately covers everything *around* it:

* ``event_to_finding`` is a pure mapping from a probe event to a Finding, and
  is where a malformed event has to die quietly rather than take the agent
  down. A runtime agent that crashes on one odd event stops observing, and an
  agent that has stopped observing looks exactly like a host with no crypto.
* ``agent.py`` must import, parse arguments and print help on a machine with no
  bcc and no privileges -- which is every CI runner, and this repo's venv.

If any test here needs root or bcc, the lazy-import boundary has been broken.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from agent.to_finding import PENDING_ENRICHMENT, event_to_finding
from core.schema import Finding


def full_event(**overrides: Any) -> dict[str, Any]:
    """An event with everything the probe could hope to capture."""
    event: dict[str, Any] = {
        "probe": "SSL_do_handshake",
        "phase": "return",
        "pid": 2231,
        "tid": 2231,
        "comm": "openssl",
        "timestamp_ns": 1_726_000_000_000_000_000,
        "retval": 1,
        "libssl_path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "observed_version": "TLSv1.3",
        "observed_cipher": "TLS_AES_256_GCM_SHA384",
    }
    event.update(overrides)
    return event


def minimal_event(**overrides: Any) -> dict[str, Any]:
    """What slice 1 actually expects: the handshake fact and nothing more."""
    event = full_event(observed_version=None, observed_cipher=None)
    event.update(overrides)
    return event


# --------------------------------------------------------------------------
# The enriched case
# --------------------------------------------------------------------------


def test_a_full_event_maps_to_an_observed_finding() -> None:
    finding = event_to_finding(full_event())

    assert finding is not None
    assert isinstance(finding, Finding)
    assert finding.scanner_id == "runtime"
    assert finding.view == "observed"


def test_a_cipher_makes_it_an_algorithm_asset() -> None:
    finding = event_to_finding(full_event())

    assert finding is not None
    assert finding.asset_type == "algorithm"
    assert finding.algorithm == "TLS_AES_256_GCM_SHA384"
    assert finding.params["version"] == "TLSv1.3"
    assert finding.params["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert finding.params.get("pending_enrichment") is not True


def test_the_locator_carries_the_host_and_pid() -> None:
    finding = event_to_finding(full_event(), hostname="host-07")

    assert finding is not None
    (occurrence,) = finding.evidence.occurrences
    assert occurrence.view == "observed"
    assert occurrence.locator == "host:host-07:pid2231"


def test_the_detail_carries_the_probe_and_observed_fields() -> None:
    finding = event_to_finding(full_event())

    assert finding is not None
    detail = finding.evidence.occurrences[0].detail
    assert "probe=SSL_do_handshake" in detail
    assert "observed_version=TLSv1.3" in detail
    assert "observed_cipher=TLS_AES_256_GCM_SHA384" in detail


def test_no_payload_bytes_reach_the_finding() -> None:
    """The probe reads no payload; the mapping must not invent a channel for it."""
    event = full_event()
    event["payload"] = "SECRETPAYLOADMUSTNOTAPPEAR"

    finding = event_to_finding(event)

    assert finding is not None
    assert "SECRETPAYLOADMUSTNOTAPPEAR" not in json.dumps(
        finding.model_dump(), default=str
    )


# --------------------------------------------------------------------------
# The slice-1 case: handshake fact only
# --------------------------------------------------------------------------


def test_a_minimal_event_is_still_a_valid_finding() -> None:
    finding = event_to_finding(minimal_event())

    assert finding is not None
    assert finding.asset_type == "protocol"
    assert finding.algorithm == "TLS"
    assert finding.view == "observed"


def test_a_minimal_event_is_marked_pending_enrichment() -> None:
    """Absent version/cipher must be visibly UNREAD, not silently unknown."""
    finding = event_to_finding(minimal_event())

    assert finding is not None
    assert finding.params[PENDING_ENRICHMENT] is True
    assert "version" not in finding.params
    assert "cipher_suite" not in finding.params

    detail = finding.evidence.occurrences[0].detail
    assert "observed_version=pending" in detail
    assert "observed_cipher=pending" in detail


def test_an_empty_string_counts_as_unread_not_as_a_value() -> None:
    """The probe zero-fills the char arrays, so "" is absence, not a version."""
    finding = event_to_finding(minimal_event(observed_version="", observed_cipher=""))

    assert finding is not None
    assert finding.params[PENDING_ENRICHMENT] is True


def test_a_version_without_a_cipher_stays_a_protocol() -> None:
    finding = event_to_finding(minimal_event(observed_version="TLSv1.2"))

    assert finding is not None
    assert finding.asset_type == "protocol"
    assert finding.algorithm == "TLS"
    assert finding.params["version"] == "TLSv1.2"
    assert finding.params.get(PENDING_ENRICHMENT) is not True


def test_the_handshake_fact_is_observed_with_full_confidence() -> None:
    """What was seen is certain; only what was NOT read is uncertain."""
    finding = event_to_finding(minimal_event())

    assert finding is not None
    assert finding.confidence == 1.0


# --------------------------------------------------------------------------
# Garbage that parses -- the defence CLAUDE.md asks for
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("description", "event"),
    [
        ("missing pid", {k: v for k, v in full_event().items() if k != "pid"}),
        ("pid is a string", full_event(pid="not-a-pid")),
        ("pid is negative", full_event(pid=-1)),
        ("pid is a float", full_event(pid=12.5)),
        ("pid is a bool", full_event(pid=True)),
        ("comm is bytes", full_event(comm=b"\xff\xfe")),
        ("comm is missing", {k: v for k, v in full_event().items() if k != "comm"}),
        ("version is a dict", full_event(observed_version={"nope": 1})),
        ("empty dict", {}),
    ],
)
def test_garbage_events_are_skipped_not_crashed(
    description: str, event: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)

    result = event_to_finding(event)

    assert result is None, f"{description} should have been skipped"
    assert caplog.records, f"{description} was skipped without a logged reason"


def test_a_skipped_event_says_why(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)

    event_to_finding(full_event(pid="not-a-pid"))

    message = " ".join(r.getMessage() for r in caplog.records)
    assert "pid" in message.lower()


def test_a_non_dict_event_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)

    assert event_to_finding(None) is None
    assert event_to_finding("not an event") is None
    assert caplog.records


def test_mapping_is_deterministic() -> None:
    event = full_event()
    assert event_to_finding(event, hostname="h") == event_to_finding(
        event, hostname="h"
    )


def test_mapping_does_not_mutate_its_input() -> None:
    event = full_event()
    before = json.dumps(event, sort_keys=True, default=str)

    event_to_finding(event)

    assert json.dumps(event, sort_keys=True, default=str) == before


# --------------------------------------------------------------------------
# The loader must be importable without bcc and without root
# --------------------------------------------------------------------------


def test_the_agent_imports_without_bcc() -> None:
    """bcc lives in system python, not this venv. Importing must still work.

    If this fails, the bcc import has escaped to module scope and every test in
    this file becomes root-and-bcc-only.
    """
    import agent.agent as agent_module

    assert agent_module is not None


def test_bcc_is_not_imported_at_module_scope() -> None:
    import sys

    import agent.agent  # noqa: F401

    assert "bcc" not in sys.modules, (
        "importing agent.agent pulled in bcc; the import must be lazy so the "
        "pure mapping stays testable without root"
    )


def test_the_parser_accepts_the_documented_invocation() -> None:
    from agent.agent import build_parser

    args = build_parser().parse_args(
        ["--libssl-path", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "--once"]
    )

    assert args.libssl_path == "/usr/lib/x86_64-linux-gnu/libssl.so.3"
    assert args.once is True
    assert args.json is True, "JSON output is the documented default"
    assert args.target_pid is None


def test_the_parser_accepts_a_target_pid() -> None:
    from agent.agent import build_parser

    args = build_parser().parse_args(
        ["--libssl-path", "/lib/libssl.so.3", "--target-pid", "2231"]
    )

    assert args.target_pid == 2231


def test_the_parser_requires_a_libssl_path() -> None:
    from agent.agent import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_the_probe_source_is_readable_without_bcc() -> None:
    """The BPF C is a plain string; reading it must not need the toolchain."""
    from agent.probe_ssl import PROBE_SOURCE, SYMBOL

    assert SYMBOL == "SSL_do_handshake"
    assert "SSL_do_handshake" in PROBE_SOURCE or "handshake" in PROBE_SOURCE
    assert "bpf_get_current_pid_tgid" in PROBE_SOURCE


def test_the_probe_is_read_only() -> None:
    """No helper that writes to, blocks, or overrides the observed process."""
    from agent.probe_ssl import PROBE_SOURCE

    forbidden = (
        "bpf_probe_write_user",
        "bpf_override_return",
        "bpf_send_signal",
        "bpf_skb_store_bytes",
    )
    for helper in forbidden:
        assert helper not in PROBE_SOURCE, f"{helper} is not read-only"


def test_missing_libssl_is_reported_not_traced_back() -> None:
    """Fail loud, in words, with something the operator can act on."""
    from agent.agent import AgentError, resolve_libssl

    with pytest.raises(AgentError) as caught:
        resolve_libssl("/no/such/libssl.so.3")

    message = str(caught.value)
    assert "/no/such/libssl.so.3" in message
    assert "libssl" in message.lower()


def test_a_versioned_symbol_is_recognised() -> None:
    """`nm` prints `SSL_do_handshake@@OPENSSL_3.0.0` for a real distro libssl.

    An exact-suffix match reports every one of them as missing the symbol,
    which would make the agent refuse to attach to the only libraries it is
    ever pointed at.
    """
    from agent.agent import check_symbol

    # The real one on this host, if present: must NOT raise.
    real = Path("/usr/lib/x86_64-linux-gnu/libssl.so.3")
    if real.exists():
        check_symbol(real)


def test_a_library_without_the_symbol_is_rejected() -> None:
    from agent.agent import AgentError, check_symbol

    libc = Path("/lib/x86_64-linux-gnu/libc.so.6")
    if not libc.exists():
        pytest.skip("no libc at the expected path")

    with pytest.raises(AgentError, match="SSL_do_handshake"):
        check_symbol(libc)
