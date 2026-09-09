"""The runtime agent: attach uprobes to libssl, drain events, print JSON lines.

    sudo python3 -m agent.agent --self-test          # one-command go/no-go
    sudo python3 -m agent.agent --libssl-path <p> --once

Run it with ``-m`` from the repository root. ``python3 agent/agent.py`` puts the
``agent/`` DIRECTORY on ``sys.path`` rather than its parent, so this module's
own ``from agent.probe_ssl import ...`` cannot resolve -- which is how the first
manual attach proof failed before it reached the kernel.

**Two imports are deliberately lazy, for opposite reasons.**

``bcc`` lives in the system Python, not in this project's venv, and needs root.
Importing it at module scope would make ``agent/to_finding.py`` -- the part with
logic worth testing -- unimportable in CI and in the venv.

``agent.to_finding`` (and through it pydantic) is imported only when
``--findings`` is passed. pydantic is a venv dependency of this repo and not of
the system interpreter where bcc lives, so importing it at module scope would
make the minimal attach proof depend on a second, unrelated environment being
right. It is not: the attach proof needs bcc and nothing else.

Tests assert both boundaries hold.

**Diagnostics, after the second attach proof captured nothing.** A clean attach
with zero events is ambiguous between three unrelated faults, so the agent now
distinguishes them in one run: it prints the symbol offset it resolved itself
(a uprobe at offset 0 sits on the ELF header and never fires), it can attach
control probes to simpler symbols, it counts events per probe, and it reports
decode failures separately from "nothing arrived". See ADR-0009.

**Read-only, and no network.** The agent attaches probes, reads a perf buffer
and writes JSON to stdout. It never writes to the observed process, never reads
payload, and never opens a socket. ``--self-test`` makes a loopback TLS
connection to a server it starts itself, which is the one deliberate exception
and is entirely local.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from agent.elfsym import ElfError, resolve_dynamic_symbol
from agent.probe_ssl import CONTROL_SYMBOLS, PROBE_IDS, SYMBOL, build_source

__all__ = [
    "AgentError",
    "build_parser",
    "main",
    "report_symbol_offsets",
    "resolve_libssl",
]

#: Human-readable phase names, matching probe_ssl's PHASE_* constants.
_PHASES = {0: "entry", 1: "return"}

#: Perf-buffer poll timeout. Short enough that --once feels immediate, long
#: enough not to spin.
POLL_TIMEOUT_MS = 200

#: How long --self-test waits for events after its handshake completes.
SELF_TEST_TIMEOUT_S = 20.0

#: Used when --libssl-path is omitted, so --self-test is a single flag.
DEFAULT_LIBSSL = "/usr/lib/x86_64-linux-gnu/libssl.so.3"

#: BPF C function name per control symbol.
_CONTROL_FNS = ("on_control_new", "on_control_read", "on_control_write")

_INSTALL_HINT = (
    "bcc is not importable. It ships with the distro rather than with pip: on "
    "Debian/Ubuntu `sudo apt install python3-bpfcc`, on Fedora "
    "`sudo dnf install bcc-tools python3-bcc`. Note that bcc installs into the "
    "SYSTEM python, so run this agent with `sudo python3 -m agent.agent`, not "
    "with a venv interpreter."
)


class AgentError(RuntimeError):
    """A condition that stops the agent, reported in words rather than a stack."""


# ---------------------------------------------------------------------------
# Preflight -- everything checkable before asking the kernel for anything
# ---------------------------------------------------------------------------


def resolve_libssl(path: str) -> Path:
    """Resolve and sanity-check the library to attach to."""
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise AgentError(
            f"no such file: {path}\n"
            "  Give the path to the libssl the TARGET process actually loaded, "
            "not the one on your PATH. Find it with:\n"
            "    cat /proc/<pid>/maps | grep -i libssl\n"
            "    ldd $(command -v openssl) | grep libssl"
        )
    if resolved.is_dir():
        raise AgentError(f"{path} is a directory; expected a libssl shared object")
    return resolved.resolve()


def check_symbol(libssl: Path, symbol: str = SYMBOL) -> None:
    """Fail early if the symbol is not attachable in this library.

    Resolved from the ELF rather than by shelling out: the agent already needs
    an independent resolver for the offset diagnostic, and one code path is
    better than two that can disagree.
    """
    try:
        offset = resolve_dynamic_symbol(libssl, symbol)
    except ElfError as exc:
        raise AgentError(f"could not read {libssl} as an ELF object: {exc}") from exc

    if offset is None:
        raise AgentError(
            f"{symbol} is not an exported function symbol of {libssl}\n"
            "  A uprobe attaches by symbol name, so it cannot attach here. "
            "Likely causes: the binary links OpenSSL statically, it is a "
            "different TLS library (GnuTLS, NSS), or this is not libssl.\n"
            f"  Check with:  nm -D --defined-only {libssl} | grep {symbol}"
        )


def report_symbol_offsets(libssl: Path, symbols: Sequence[str]) -> None:
    """Print where each symbol lives, resolved independently of bcc.

    The second attach proof attached cleanly and captured nothing, and the
    leading theory was that bcc had resolved the versioned
    ``SSL_do_handshake@@OPENSSL_3.0.0`` to the wrong place -- a uprobe at offset
    0 sits on the ELF header, which nothing executes, and looks exactly like a
    healthy attach. Printing a real, non-zero number every run settles that in
    one line instead of a round trip through a human with sudo.
    """
    for symbol in symbols:
        try:
            offset = resolve_dynamic_symbol(libssl, symbol)
        except ElfError as exc:
            print(f"  {symbol}: could not resolve ({exc})", file=sys.stderr)
            continue
        if offset is None:
            print(f"  {symbol}: NOT EXPORTED by {libssl}", file=sys.stderr)
        elif offset == 0:
            print(
                f"  {symbol}: resolved to offset 0 -- a uprobe here would sit "
                "on the ELF header and never fire",
                file=sys.stderr,
            )
        else:
            print(f"  resolved {symbol} at libssl+0x{offset:x}", file=sys.stderr)


def check_privileges() -> None:
    """Attaching eBPF needs root (or CAP_BPF + CAP_PERFMON). Say so up front."""
    if os.geteuid() != 0:
        raise AgentError(
            "attaching an eBPF probe requires root.\n"
            "  Re-run from the repository root with:\n"
            "    sudo python3 -m agent.agent --self-test"
        )


def check_btf() -> None:
    """A missing BTF blob is survivable for a uprobe, but worth naming."""
    if not Path("/sys/kernel/btf/vmlinux").exists():
        print(
            "warning: /sys/kernel/btf/vmlinux is absent. A userspace uprobe may "
            "still attach, but kernel-struct access would not. If attach fails, "
            "install the kernel BTF/debug package for this kernel.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Attach and drain. Everything below this line needs bcc and root.
# ---------------------------------------------------------------------------


def _load_bpf(source: str) -> Any:
    """Import bcc and compile the probe. The lazy-import boundary lives here."""
    try:
        from bcc import BPF
    except ImportError as exc:
        raise AgentError(f"{_INSTALL_HINT}\n  (import error: {exc})") from exc

    try:
        return BPF(text=source)
    except Exception as exc:  # bcc raises bare Exception on compile failure
        raise AgentError(
            "the BPF program failed to compile or load.\n"
            "  This usually means kernel headers are missing (install "
            "linux-headers for your running kernel) or the kernel forbids "
            f"unprivileged BPF.\n  Underlying error: {exc}"
        ) from exc


def _decode(raw_event: Any, libssl_path: str) -> dict[str, Any]:
    """One perf-buffer record as a plain dict, ready for the pure mapping."""
    return {
        "probe": PROBE_IDS.get(int(raw_event.probe_id), "unknown"),
        "phase": _PHASES.get(int(raw_event.phase), "unknown"),
        "pid": int(raw_event.pid),
        "tid": int(raw_event.tid),
        "comm": bytes(raw_event.comm),
        "timestamp_ns": int(raw_event.timestamp_ns),
        "retval": int(raw_event.retval),
        "ssl_ptr": hex(int(raw_event.ssl_ptr)),
        "libssl_path": libssl_path,
        # Zero-filled by the probe this slice; carried through so slice 2 only
        # has to start populating them.
        "observed_version": bytes(raw_event.version)
        .split(b"\x00", 1)[0]
        .decode("utf-8", "replace")
        or None,
        "observed_cipher": bytes(raw_event.cipher)
        .split(b"\x00", 1)[0]
        .decode("utf-8", "replace")
        or None,
    }


def _event_line(event: dict[str, Any]) -> str:
    """The documented output: one JSON object per line."""
    comm = event["comm"]
    return json.dumps(
        {
            "pid": event["pid"],
            "tid": event["tid"],
            "comm": comm.decode("utf-8", "replace").split("\x00", 1)[0]
            if isinstance(comm, bytes)
            else comm,
            "timestamp": event["timestamp_ns"],
            "probe": event["probe"],
            "phase": event["phase"],
            "retval": event["retval"],
            "observed_version": event["observed_version"],
            "observed_cipher": event["observed_cipher"],
            "libssl_path": event["libssl_path"],
        },
        sort_keys=True,
    )


def _report(seen: int, per_probe: dict[str, int], decode_errors: int) -> None:
    """What actually happened, in a form that localises a failure."""
    print(f"captured {seen} event(s)", file=sys.stderr)
    for probe, count in sorted(per_probe.items()):
        print(f"  {probe}: {count}", file=sys.stderr)
    if decode_errors:
        print(
            f"  {decode_errors} event(s) arrived but could not be decoded -- "
            "the probe fires and the buffer works; the reader is at fault",
            file=sys.stderr,
        )
    if not seen:
        print(
            "  nothing fired. If controls were attached (--controls) and they "
            f"did not fire either, the fault is not specific to {SYMBOL}.",
            file=sys.stderr,
        )


def _shutdown(bpf: Any, events_table: Any) -> None:
    """Release probes and perf buffers deterministically, and never raise.

    bcc's ``PerfEventArray.__del__`` re-runs its own teardown at
    garbage-collection time. Because this module keeps a reference to the table
    for the lifetime of the run, ``BPF.cleanup()`` does not drop the last one --
    so that finalizer fires later, at interpreter shutdown, when the map fd is
    already closed. ``bpf_delete_elem`` then fails, ``__delitem__`` raises
    ``KeyError``, and Python can only print "Exception ignored in:" because
    exceptions in finalizers have nowhere to go.

    The run has already succeeded by that point, so the only casualty is a
    traceback printed after the PASS line. That is cosmetic and still worth
    fixing: a demo that ends in a traceback reads as a failure.

    Three steps, in this order:

    1. Release the perf-buffer keys ourselves while the map is still open, so
       the readers are freed properly rather than leaked.
    2. ``cleanup()`` to detach the probes and close the module.
    3. Empty the bookkeeping bcc's finalizer iterates. Anything still in it is
       a key whose delete just failed, and the finalizer would retry exactly
       that failing delete where the error cannot be handled. Clearing it
       leaks nothing that matters -- the process is exiting and the kernel
       reclaims the rest.

    Called from a ``finally``, so it runs on Ctrl-C and on error too. It
    suppresses everything: teardown must not be able to turn a successful
    capture into a failure.
    """
    open_fds = getattr(events_table, "_open_key_fds", None)
    if isinstance(open_fds, dict):
        for key in list(open_fds):
            with contextlib.suppress(Exception):
                del events_table[key]

    with contextlib.suppress(Exception):
        bpf.cleanup()

    if isinstance(open_fds, dict):
        open_fds.clear()


# ---------------------------------------------------------------------------
# --self-test: cause a handshake ourselves, after attaching
# ---------------------------------------------------------------------------

#: A self-contained TLS server+client, run as a CHILD process so the handshake
#: happens in a process started after the probes are attached -- the ordering
#: the three-terminal walkthrough kept getting wrong.
_SELF_TEST_SCRIPT = """
import socket, ssl, sys, threading

cert, key = sys.argv[1], sys.argv[2]
ready = threading.Event()
port = [0]

def server():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port[0] = sock.getsockname()[1]
    sock.listen(1)
    ready.set()
    with ctx.wrap_socket(sock, server_side=True) as tls:
        try:
            conn, _ = tls.accept()
            conn.recv(16)
            conn.send(b"ok")
            conn.close()
        except OSError:
            pass

thread = threading.Thread(target=server, daemon=True)
thread.start()
ready.wait(10)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
conn = ctx.wrap_socket(
    socket.create_connection(("127.0.0.1", port[0]), timeout=10),
    server_hostname="localhost",
)
conn.send(b"hello")
conn.recv(16)
print("handshake ok: %s %s" % (conn.version(), conn.cipher()[0]), flush=True)
conn.close()
thread.join(2)
"""


def _make_test_cert(directory: Path) -> tuple[Path, Path] | None:
    """A throwaway self-signed cert, via openssl. None if it cannot be made."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    cert = directory / "self-test.crt"
    key = directory / "self-test.key"
    result = subprocess.run(  # noqa: S603 - argv list, no shell, resolved path
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0 or not cert.exists():
        return None
    return cert, key


def _run_self_test(
    bpf: Any,
    seen: Callable[[], int],
    per_probe: dict[str, int],
    decode_errors: Callable[[], int],
) -> int:
    """Attach, cause a handshake ourselves, and report PASS or FAIL.

    The three-terminal walkthrough has a timing race in it -- the operator must
    attach between starting a server and running a client -- and a race is a
    poor foundation for a go/no-go answer. Here the probes are already attached
    before the handshake process exists, so the ordering cannot be wrong.

    Everything it creates lives in a temporary directory that is removed on the
    way out, and the child is killed if it hangs.
    """
    with tempfile.TemporaryDirectory(prefix="ecdat-self-test-") as workdir:
        directory = Path(workdir)
        material = _make_test_cert(directory)
        if material is None:
            print(
                "self-test: could not generate a test certificate (is openssl "
                "installed?). Fall back to the manual walkthrough in "
                "agent/README.md.",
                file=sys.stderr,
            )
            return 2
        cert, key = material

        script = directory / "handshake.py"
        script.write_text(_SELF_TEST_SCRIPT, encoding="utf-8")

        print(
            "self-test: probes attached; running a local TLS handshake in a "
            "child process...",
            file=sys.stderr,
        )
        child = subprocess.Popen(  # noqa: S603 - our own script, our own paths
            [sys.executable, str(script), str(cert), str(key)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = child.communicate(timeout=SELF_TEST_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            print("self-test: the handshake child timed out", file=sys.stderr)

        if stdout.strip():
            print(f"self-test: {stdout.strip()}", file=sys.stderr)
        if child.returncode != 0:
            print(
                "self-test: the handshake child FAILED, so there was nothing "
                f"to observe:\n{stderr.strip()[:500]}",
                file=sys.stderr,
            )
            return 2

        # The handshake has already happened; this is the window in which its
        # events must arrive.
        deadline = time.monotonic() + SELF_TEST_TIMEOUT_S
        while time.monotonic() < deadline:
            bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)
            if seen():
                # Keep draining briefly, so the summary counts the whole
                # handshake rather than only its first event.
                grace = time.monotonic() + 1.0
                while time.monotonic() < grace:
                    bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)
                break

    _report(seen(), per_probe, decode_errors())

    handshake_events = per_probe.get(SYMBOL, 0)
    if handshake_events:
        print(
            f"self-test: PASS -- {SYMBOL} fired {handshake_events} time(s) on a "
            "real handshake.",
            file=sys.stderr,
        )
        return 0

    if seen():
        print(
            f"self-test: FAIL -- events arrived, but none from {SYMBOL}. The "
            "pipeline works; that symbol's probe does not fire.",
            file=sys.stderr,
        )
        return 1

    print(
        "self-test: FAIL -- a handshake completed and NO probe fired. The fault "
        "is upstream of the symbol: attach, the perf buffer, or the poll loop. "
        "Re-run with --controls to narrow it.",
        file=sys.stderr,
    )
    return 1


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    """Attach, drain, print. Returns a process exit code."""
    libssl = resolve_libssl(args.libssl_path)
    check_symbol(libssl)
    check_privileges()
    check_btf()

    wanted = [SYMBOL, *(CONTROL_SYMBOLS if args.controls else ())]
    print(f"symbol offsets in {libssl}:", file=sys.stderr)
    report_symbol_offsets(libssl, wanted)

    bpf = _load_bpf(build_source(args.target_pid))
    attached: list[str] = []

    def attach(symbol: str, fn_name: str, *, entry: bool = True) -> bool:
        """Attach one probe. Returns whether it took.

        With --attach-by-address the offset resolved from the ELF is passed
        directly, so a disagreement between bcc's name resolution and ours can
        be taken out of the picture without another round trip.
        """
        kind = "uprobe" if entry else "uretprobe"
        kwargs: dict[str, Any] = {"name": str(libssl), "fn_name": fn_name}
        if args.attach_by_address:
            offset = resolve_dynamic_symbol(libssl, symbol)
            if offset is None:
                print(
                    f"warning: {symbol} is not exported; cannot attach by address",
                    file=sys.stderr,
                )
                return False
            kwargs["addr"] = offset
        else:
            kwargs["sym"] = symbol

        try:
            if entry:
                bpf.attach_uprobe(**kwargs)
            else:
                bpf.attach_uretprobe(**kwargs)
        except Exception as exc:  # report and continue
            print(
                f"warning: {kind} on {symbol} did not attach ({exc})",
                file=sys.stderr,
            )
            return False
        attached.append(f"{kind}:{symbol}")
        return True

    if not attach(SYMBOL, "on_handshake_entry"):
        raise AgentError(
            f"could not attach a uprobe to {SYMBOL} in {libssl}; see the warning above."
        )
    attach(SYMBOL, "on_handshake_return", entry=False)

    if args.controls:
        # Controls separate "this symbol never fires" from "nothing fires".
        for symbol, fn_name in zip(CONTROL_SYMBOLS, _CONTROL_FNS, strict=True):
            attach(symbol, fn_name)

    print(
        f"attached: {', '.join(attached)}"
        + (f" (pid {args.target_pid} only)" if args.target_pid else "")
        + (" [by address]" if args.attach_by_address else " [by symbol name]"),
        file=sys.stderr,
    )

    counters = {"seen": 0, "decode_errors": 0}
    per_probe: dict[str, int] = {}
    events_table = bpf["handshake_events"]

    def handle(_cpu: int, data: Any, _size: int) -> None:
        # Counted BEFORE decoding. A decode failure must not be reported as
        # "captured nothing" -- those are different faults with different
        # fixes, and conflating them is what makes a silent probe hard to
        # diagnose.
        counters["seen"] += 1
        try:
            # bcc's documented decoder derives the ctypes struct from the BPF C,
            # so the layout is never restated in Python.
            event = _decode(events_table.event(data), str(libssl))
        except Exception as exc:  # ctypes callbacks swallow exceptions
            counters["decode_errors"] += 1
            print(f"warning: could not decode an event: {exc!r}", file=sys.stderr)
            return

        probe = str(event["probe"])
        per_probe[probe] = per_probe.get(probe, 0) + 1

        if args.json:
            print(_event_line(event), flush=True)

        if args.findings:
            # Imported here, not at module scope: this is the only code path
            # that needs pydantic, and the system interpreter that has bcc
            # usually does not have it.
            from agent.to_finding import event_to_finding

            finding = event_to_finding(event)
            if finding is not None:
                print(finding.model_dump_json(), flush=True)

    events_table.open_perf_buffer(handle)

    try:
        if args.self_test:
            return _run_self_test(
                bpf,
                lambda: counters["seen"],
                per_probe,
                lambda: counters["decode_errors"],
            )

        print("Waiting for a TLS handshake; Ctrl-C to stop.", file=sys.stderr)
        try:
            # A LOOP with a real timeout. perf_buffer_poll returns as soon as it
            # has drained whatever is ready, which is routinely before the event
            # we are waiting for exists; polling once would report "nothing" for
            # a probe that fires half a second later.
            while True:
                bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)
                if args.once and counters["seen"]:
                    break
        except KeyboardInterrupt:
            print("", file=sys.stderr)

        _report(counters["seen"], per_probe, counters["decode_errors"])
        return 0 if counters["seen"] else 1
    finally:
        # Deterministic teardown while the interpreter is still healthy, so the
        # run does not end on a finalizer traceback. See _shutdown.
        _shutdown(bpf, events_table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdat-agent",
        description=(
            "Observe TLS handshakes via an eBPF uprobe on libssl. Read-only: "
            "attaches, reads, and never modifies the observed process."
        ),
        epilog=(
            "Needs root. Start with --self-test. "
            "See agent/README.md for the full walkthrough."
        ),
    )
    parser.add_argument(
        "--libssl-path",
        default=DEFAULT_LIBSSL,
        help=(
            "path to the libssl.so the TARGET process loaded (find it with "
            f"`cat /proc/<pid>/maps | grep libssl`). Default: {DEFAULT_LIBSSL}"
        ),
    )
    parser.add_argument(
        "--target-pid",
        type=int,
        default=None,
        metavar="PID",
        help="only report handshakes from this process (default: all)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "attach, then cause a TLS handshake in a child process and report "
            "PASS/FAIL. One command, no terminal ordering to get wrong"
        ),
    )
    parser.add_argument(
        "--controls",
        action="store_true",
        help=(
            f"also attach probes to {', '.join(CONTROL_SYMBOLS)}. If those fire "
            f"and {SYMBOL} does not, the fault is that symbol's"
        ),
    )
    parser.add_argument(
        "--attach-by-address",
        action="store_true",
        help=(
            "attach at the file offset resolved from the ELF instead of by "
            "symbol name, to rule out a name-resolution difference"
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="exit after the first event",
    )
    parser.add_argument(
        "--json",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="print one JSON event per line (default: on)",
    )
    parser.add_argument(
        "--findings",
        action="store_true",
        help=(
            "also print each event mapped to an ECDAT Finding. Needs pydantic "
            "in the SAME interpreter as bcc; plain --json does not"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except AgentError as exc:
        print(f"ecdat-agent: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
