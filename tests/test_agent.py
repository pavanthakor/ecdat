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
import os
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


def test_libssl_path_defaults_so_self_test_is_one_flag() -> None:
    """`sudo python3 -m agent.agent --self-test` must need nothing else.

    The whole point of --self-test is collapsing a three-terminal race into one
    command; making the operator also supply a path they have to look up first
    would put half the race back.
    """
    from agent.agent import DEFAULT_LIBSSL, build_parser

    args = build_parser().parse_args(["--self-test"])

    assert args.self_test is True
    assert args.libssl_path == DEFAULT_LIBSSL


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


# --------------------------------------------------------------------------
# Regressions from the first manual attach proof on the real VM.
# kernel 7.0 / bcc 0.35 -- see ADR-0009.
# --------------------------------------------------------------------------


def test_the_probe_does_not_name_task_comm_len() -> None:
    """bcc 0.35 on kernel 7.0 does not predefine TASK_COMM_LEN.

    The first attach proof died here:
        /virtual/main.c:17:15: error: use of undeclared identifier
        'TASK_COMM_LEN'
    The macro is supplied by some bcc/kernel-header combinations and not by
    others, so relying on it makes the probe compile on the author's assumption
    rather than on the operator's kernel.
    """
    from agent.probe_ssl import PROBE_SOURCE

    assert "TASK_COMM_LEN" not in PROBE_SOURCE


def test_the_comm_field_uses_the_canonical_literal_size() -> None:
    """16 is the documented contract of bpf_get_current_comm."""
    from agent.probe_ssl import COMM_LEN, PROBE_SOURCE

    assert COMM_LEN == 16
    assert "char comm[16]" in PROBE_SOURCE
    assert "bpf_get_current_comm(&event.comm, sizeof(event.comm))" in PROBE_SOURCE


def test_pydantic_is_not_imported_at_module_scope() -> None:
    """The agent must run on the SYSTEM python, where bcc lives.

    pydantic is a venv dependency of this repo, not of the system interpreter,
    and the attach proof needs neither it nor the Finding mapping -- only
    --findings does. Importing it at module scope makes the minimal proof
    depend on a second, unrelated environment being right.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import agent.agent, sys; print('pydantic' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", (
        "importing agent.agent pulled in pydantic; keep the Finding mapping "
        "behind a lazy import so --json works on the system interpreter"
    )


def test_the_root_hint_tells_the_operator_to_use_the_module_form() -> None:
    """`python3 agent/agent.py` cannot resolve `from agent.probe_ssl import ...`.

    Running a file inside a package puts the package DIRECTORY on sys.path, not
    its parent, so the package's own absolute imports fail. The hint must not
    send an operator to the invocation that does not work.
    """
    from agent.agent import AgentError, check_privileges

    if os.geteuid() == 0:
        pytest.skip("running as root; the privilege hint is not reached")

    with pytest.raises(AgentError) as caught:
        check_privileges()

    message = str(caught.value)
    assert "-m agent.agent" in message
    assert "python3 agent/agent.py" not in message


def test_the_agent_uses_bccs_documented_event_decoder() -> None:
    """bcc's PerfEventArray exposes `.event(data)`, not `.event_data_type`.

    The first draft used `ctypes.cast(data, POINTER(table.event_data_type))`,
    which does not exist in bcc 0.35 and would have raised AttributeError on
    the very first captured event -- after the operator had already fixed the
    compile error and re-run. Found by reading the installed bcc rather than by
    another round trip through the human.
    """
    source = (Path(__file__).resolve().parent.parent / "agent" / "agent.py").read_text()

    assert "event_data_type" not in source
    assert ".event(data)" in source


def test_bcc_actually_exposes_that_decoder() -> None:
    """Check the claim above against the bcc that is installed, if any.

    bcc lives in the system interpreter, so this is skipped when the test run
    cannot see it -- which is the venv, and CI.
    """
    import subprocess

    probe = (
        "import bcc.table as t; "
        "print(hasattr(t.PerfEventArray, 'event'), "
        "hasattr(t.PerfEventArray, 'event_data_type'))"
    )
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/python3", "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("bcc is not importable from /usr/bin/python3")

    assert result.stdout.strip() == "True False"


# --------------------------------------------------------------------------
# Diagnostics added after the second attach proof captured nothing.
# --------------------------------------------------------------------------


def test_the_parser_exposes_the_diagnostic_switches() -> None:
    from agent.agent import build_parser

    args = build_parser().parse_args(
        ["--self-test", "--controls", "--attach-by-address"]
    )

    assert args.self_test is True
    assert args.controls is True
    assert args.attach_by_address is True


def test_the_probe_carries_a_probe_id_so_events_name_their_source() -> None:
    """With controls attached, an event must say WHICH probe produced it."""
    from agent.probe_ssl import PROBE_IDS, PROBE_SOURCE, SYMBOL

    assert PROBE_IDS[0] == SYMBOL
    assert set(PROBE_IDS.values()) >= {"SSL_new", "SSL_read", "SSL_write"}
    assert "u32 probe_id;" in PROBE_SOURCE
    assert "event.probe_id = probe_id;" in PROBE_SOURCE


def test_every_control_symbol_has_a_probe_function() -> None:
    from agent.agent import _CONTROL_FNS
    from agent.probe_ssl import CONTROL_SYMBOLS, PROBE_SOURCE

    assert len(_CONTROL_FNS) == len(CONTROL_SYMBOLS)
    for fn_name in _CONTROL_FNS:
        assert f"int {fn_name}(struct pt_regs *ctx)" in PROBE_SOURCE


def test_control_symbols_exist_in_the_real_libssl() -> None:
    """A control that is not exported would be a useless control."""
    from agent.elfsym import resolve_dynamic_symbol
    from agent.probe_ssl import CONTROL_SYMBOLS

    libssl = Path("/usr/lib/x86_64-linux-gnu/libssl.so.3")
    if not libssl.exists():
        pytest.skip("no libssl at the expected path")

    for symbol in CONTROL_SYMBOLS:
        offset = resolve_dynamic_symbol(libssl, symbol)
        assert offset, f"control symbol {symbol} does not resolve"


def test_report_symbol_offsets_prints_a_non_zero_offset(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The headline diagnostic: a real number the operator can read."""
    from agent.agent import report_symbol_offsets

    libssl = Path("/usr/lib/x86_64-linux-gnu/libssl.so.3")
    if not libssl.exists():
        pytest.skip("no libssl at the expected path")

    report_symbol_offsets(libssl, ["SSL_do_handshake"])

    printed = capsys.readouterr().err
    assert "resolved SSL_do_handshake at libssl+0x" in printed
    assert "libssl+0x0\n" not in printed


def test_report_symbol_offsets_names_a_missing_symbol(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agent.agent import report_symbol_offsets

    libc = Path("/lib/x86_64-linux-gnu/libc.so.6")
    if not libc.exists():
        pytest.skip("no libc at the expected path")

    report_symbol_offsets(libc, ["SSL_do_handshake"])

    assert "NOT EXPORTED" in capsys.readouterr().err


def test_the_poll_loop_loops_with_a_timeout() -> None:
    """A single poll can return before the event exists.

    perf_buffer_poll drains whatever is ready and returns; the event we are
    waiting for routinely arrives later. Polling once would report "captured
    nothing" for a probe that fires half a second afterwards.
    """
    source = (Path(__file__).resolve().parent.parent / "agent" / "agent.py").read_text()

    assert "while True:" in source
    assert "perf_buffer_poll(timeout=POLL_TIMEOUT_MS)" in source

    from agent.agent import POLL_TIMEOUT_MS, SELF_TEST_TIMEOUT_S

    assert POLL_TIMEOUT_MS > 0
    assert SELF_TEST_TIMEOUT_S >= 5


def test_the_event_counter_increments_before_decoding() -> None:
    """An undecodable event must not be reported as "nothing arrived".

    Those are different faults with different fixes, and ctypes callbacks
    swallow exceptions, so a decode error would otherwise be invisible.
    """
    source = (Path(__file__).resolve().parent.parent / "agent" / "agent.py").read_text()

    body = source[source.index("def handle(") : source.index("events_table.open_perf")]
    increment = body.index('counters["seen"] += 1')
    decode = body.index("_decode(")

    assert increment < decode, "seen is counted after decoding; a decode error "
    assert 'counters["decode_errors"] += 1' in body


def test_the_self_test_script_is_syntactically_valid() -> None:
    """It is executed by a child interpreter, so a syntax error would surface
    as a mystified "the handshake child FAILED"."""
    import ast

    from agent.agent import _SELF_TEST_SCRIPT

    ast.parse(_SELF_TEST_SCRIPT)
    assert "ssl.SSLContext" in _SELF_TEST_SCRIPT
    assert "127.0.0.1" in _SELF_TEST_SCRIPT, "self-test must stay on loopback"


def test_the_self_test_cleans_up_after_itself() -> None:
    source = (Path(__file__).resolve().parent.parent / "agent" / "agent.py").read_text()
    body = source[source.index("def _run_self_test(") :]

    assert "tempfile.TemporaryDirectory" in body, "cert material must be temporary"
    assert "child.kill()" in body, "a hung handshake child must be killed"
