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
from agent.probe_ssl import (
    CONTROL_SYMBOLS,
    ENRICH_SYMBOLS,
    PROBE_IDS,
    SYMBOL,
    build_source,
)

# The wire format, shared with the consumer. A plain module with no pydantic in
# it, so importing it here does not break the agent's ability to run on the
# system interpreter (ADR-0009).
from agent.spool_format import TEMP_PREFIX, TEMP_SUFFIX, local_stem

__all__ = [
    "AgentError",
    "SpoolWriter",
    "build_parser",
    "main",
    "report_symbol_offsets",
    "resolve_libssl",
]

#: Human-readable phase names, matching probe_ssl's PHASE_* constants.
_PHASES = {0: "entry", 1: "return", 2: "enrich"}

#: How long a completed handshake waits for its accessor events before being
#: emitted with whatever was read.
#:
#: The ordering is unavoidable: an application calls SSL_do_handshake and only
#: THEN asks libssl what it negotiated, so the enrichment always arrives after
#: the handshake it belongs to. Holding the handshake briefly is what lets one
#: event carry all three facts instead of three unrelated events the consumer
#: would have to stitch together. Expiry is what stops a process that never
#: calls an accessor from holding a record forever -- it is emitted honestly
#: unenriched instead.
ENRICH_WINDOW_S = 0.4

#: Perf-buffer poll timeout. Short enough that --once feels immediate, long
#: enough not to spin.
POLL_TIMEOUT_MS = 200

#: How long --self-test waits for events after its handshake completes.
SELF_TEST_TIMEOUT_S = 20.0

#: Used when --libssl-path is omitted, so --self-test is a single flag.
DEFAULT_LIBSSL = "/usr/lib/x86_64-linux-gnu/libssl.so.3"

#: BPF C function name per control symbol.
_CONTROL_FNS = ("on_control_new", "on_control_read", "on_control_write")

#: BPF C function name per enrichment accessor, and which event field each
#: fills in.
_ENRICH_FNS = ("on_get_version", "on_cipher_name", "on_group_name")
_ENRICH_FIELDS = ("observed_version", "observed_cipher", "observed_group")

_INSTALL_HINT = (
    "bcc is not importable. It ships with the distro rather than with pip: on "
    "Debian/Ubuntu `sudo apt install python3-bpfcc`, on Fedora "
    "`sudo dnf install bcc-tools python3-bcc`. Note that bcc installs into the "
    "SYSTEM python, so run this agent with `sudo python3 -m agent.agent`, not "
    "with a venv interpreter."
)


class AgentError(RuntimeError):
    """A condition that stops the agent, reported in words rather than a stack."""


class SpoolWriter:
    """Writes each observed event as one JSON line into a spool directory.

    This is the producer half of the seam (ADR-0010). The agent runs as root
    and attaches eBPF; the scan path does not, and handing a privileged sensor
    an API credential to carry would undo that. So this writes files and
    nothing else -- no socket, no client, no token.

    **Atomic by temp-and-rename.** Each record is written to
    ``.tmp-<uniq>.partial`` and then renamed into place. Rename within a
    directory is atomic on POSIX, so the consumer -- which polls a directory
    it does not coordinate with -- can never observe a half-written record. A
    crash leaves the
    ``.tmp-`` file behind, which the consumer ignores and a human can inspect.

    **Filenames cannot collide.** ``<host>-<pid>-<timestamp_ns>-<seq>`` is
    unique across hosts, across concurrent agents, and across re-runs, so a
    later record can never overwrite an earlier one the consumer has not read.
    """

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self.written = 0
        _chown_to_invoking_user(self.directory)

    def write(self, event: dict[str, Any]) -> Path:
        """Write one event. Raises on I/O failure rather than losing it quietly."""
        self._seq += 1
        stem = local_stem(self._seq)
        temp = self.directory / f"{TEMP_PREFIX}{stem}{TEMP_SUFFIX}"
        final = self.directory / f"{stem}.jsonl"

        payload = json.dumps(event, sort_keys=True) + "\n"
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            # The rename is only atomic with respect to a file that is already
            # on disk; without this a crash could rename an empty inode into
            # place, which is precisely the readable-but-partial record the
            # temp-and-rename dance exists to prevent.
            os.fsync(handle.fileno())

        # os.rename, not Path.rename: identical syscall, but the atomicity
        # of this one line is the entire reason for the temp file, and the
        # POSIX spelling is what says so to a reader.
        os.rename(temp, final)  # noqa: PTH104
        _chown_to_invoking_user(final)
        self.written += 1
        return final


def _chown_to_invoking_user(path: Path) -> None:
    """Hand ownership to the user who ran sudo, if there is one.

    The agent must be root to attach probes, but the consumer must not be -- and
    the consumer has to MOVE files into ``consumed/``, which needs write
    permission on the directory, not just on the files. Leaving a root-owned
    spool would mean the only way to ingest it is to run the scan as root too,
    which drags the privilege back into the part of the system that was
    carefully kept clear of it.

    Best-effort and silent on failure: not running under sudo is the normal
    case for the tests, and a chown that cannot happen is not a reason to lose
    an observation.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not sudo_uid or os.geteuid() != 0:
        return
    with contextlib.suppress(OSError, ValueError):
        os.chown(path, int(sudo_uid), int(sudo_gid or sudo_uid))


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


def _cstr(value: Any) -> str | None:
    """A NUL-terminated C char array as a string, or None when it is empty.

    Empty means the probe never filled it in -- an accessor that was not
    called, or a read that failed. It is absence, not an observation of
    emptiness, and the mapping treats it that way (ADR-0011).
    """
    return bytes(value).split(b"\x00", 1)[0].decode("utf-8", "replace") or None


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
        # Filled in by the accessor uretprobes; empty on the handshake probe
        # itself, because nothing is negotiated until libssl is asked.
        "observed_version": _cstr(raw_event.version),
        "observed_cipher": _cstr(raw_event.cipher),
        "observed_group": _cstr(raw_event.group),
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
            "observed_group": event.get("observed_group"),
            "libssl_path": event["libssl_path"],
        },
        sort_keys=True,
    )


def _report(
    seen: int,
    per_probe: dict[str, int],
    decode_errors: int,
    spooled: int = 0,
) -> None:
    """What actually happened, in a form that localises a failure."""
    print(f"captured {seen} event(s)", file=sys.stderr)
    for probe, count in sorted(per_probe.items()):
        print(f"  {probe}: {count}", file=sys.stderr)
    if spooled:
        print(f"  spooled {spooled} event(s) to disk", file=sys.stderr)
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
    flush: Callable[..., None],
    seen: Callable[[], int],
    per_probe: dict[str, int],
    decode_errors: Callable[[], int],
    spooled: Callable[[], int] = lambda: 0,
    spool: SpoolWriter | None = None,
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
            flush(time.monotonic())
            if seen():
                # Keep draining briefly, so the summary counts the whole
                # handshake rather than only its first event, and so the
                # accessor events that enrich it have time to arrive.
                grace = time.monotonic() + 1.5
                while time.monotonic() < grace:
                    bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)
                    flush(time.monotonic())
                break

        flush(time.monotonic(), force=True)

    _report(seen(), per_probe, decode_errors(), spooled())

    if spool is not None:
        print(
            f"self-test: {spooled()} record(s) written to {spool.directory}\n"
            "  Ingest them with:\n"
            f"    .venv/bin/python cli.py scan {spool.directory} --kind spool",
            file=sys.stderr,
        )

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

    if not args.no_enrich:
        # Uretprobes on public accessors: the return value IS the negotiated
        # fact, as a const char*. No struct offsets anywhere (ADR-0011).
        for symbol, fn_name in zip(ENRICH_SYMBOLS, _ENRICH_FNS, strict=True):
            attach(symbol, fn_name, entry=False)

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

    counters = {
        "seen": 0,
        "decode_errors": 0,
        "spooled": 0,
        "enriched": 0,
        "enrich_orphan": 0,
    }
    per_probe: dict[str, int] = {}
    events_table = bpf["handshake_events"]

    spool = SpoolWriter(args.spool) if args.spool else None
    if spool is not None:
        print(f"spooling observed events to {spool.directory}", file=sys.stderr)

    # (pid, tid) -> a completed handshake waiting for its accessor events.
    pending: dict[tuple[int, int], tuple[float, dict[str, Any]]] = {}

    def emit(event: dict[str, Any]) -> None:
        """Publish one finished event to stdout, the spool, and findings."""
        probe = str(event["probe"])
        per_probe[probe] = per_probe.get(probe, 0) + 1

        line = _event_line(event)
        if args.json:
            print(line, flush=True)

        if spool is not None:
            # The SAME serialisation stdout gets, so producer and consumer
            # cannot drift apart: what a human reads in the terminal is byte
            # for byte what the scanner will ingest.
            try:
                spool.write(json.loads(line))
                counters["spooled"] += 1
            except OSError as exc:
                print(f"warning: could not spool an event: {exc}", file=sys.stderr)

        if args.findings:
            # Imported here, not at module scope: this is the only code path
            # that needs pydantic, and the system interpreter that has bcc
            # usually does not have it.
            from agent.to_finding import event_to_findings

            for finding in event_to_findings(event):
                print(finding.model_dump_json(), flush=True)

    def flush(now: float, *, force: bool = False) -> None:
        """Emit handshakes whose enrichment window has closed."""
        for key, (arrived, event) in list(pending.items()):
            if force or now - arrived >= ENRICH_WINDOW_S:
                del pending[key]
                emit(event)

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

        key = (int(event["pid"]), int(event["tid"]))

        if event["phase"] == "enrich":
            # An accessor return. It belongs to the handshake this thread just
            # completed; if there is none waiting, the process asked about a
            # connection we did not see and there is nothing to attach it to.
            held = pending.get(key)
            if held is None:
                counters["enrich_orphan"] += 1
                return
            for field in _ENRICH_FIELDS:
                value = event.get(field)
                if value:
                    held[1][field] = value
            counters["enriched"] += 1
            if all(held[1].get(f) for f in _ENRICH_FIELDS):
                # Everything read; no reason to keep holding it.
                del pending[key]
                emit(held[1])
            return

        if event["phase"] == "return" and event["retval"] == 1 and not args.no_enrich:
            # Hold it briefly for the accessor events that follow.
            flush(time.monotonic())
            pending[key] = (time.monotonic(), event)
            return

        emit(event)

    events_table.open_perf_buffer(handle)

    try:
        if args.self_test:
            return _run_self_test(
                bpf,
                flush,
                lambda: counters["seen"],
                per_probe,
                lambda: counters["decode_errors"],
                lambda: counters["spooled"],
                spool,
            )

        print("Waiting for a TLS handshake; Ctrl-C to stop.", file=sys.stderr)
        try:
            # A LOOP with a real timeout. perf_buffer_poll returns as soon as it
            # has drained whatever is ready, which is routinely before the event
            # we are waiting for exists; polling once would report "nothing" for
            # a probe that fires half a second later.
            while True:
                bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)
                flush(time.monotonic())
                if args.once and counters["seen"]:
                    break
        except KeyboardInterrupt:
            print("", file=sys.stderr)

        flush(time.monotonic(), force=True)

        _report(
            counters["seen"],
            per_probe,
            counters["decode_errors"],
            counters["spooled"],
        )
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
        "--spool",
        default=None,
        metavar="DIR",
        help=(
            "also write each observed event as one JSON line into DIR, "
            "atomically. This is how observed findings reach the store: the "
            "agent only ever writes files, and `ecdat scan DIR --kind spool` "
            "ingests them (ADR-0010)"
        ),
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help=(
            "do not attach the accessor uretprobes that read the negotiated "
            f"version/cipher/group ({', '.join(ENRICH_SYMBOLS)})"
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
