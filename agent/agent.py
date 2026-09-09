"""The runtime agent: attach one uprobe, drain events, print JSON lines.

    sudo python3 -m agent.agent --libssl-path /usr/lib/.../libssl.so.3 --once

Run it with ``-m`` from the repository root. ``python3 agent/agent.py`` puts the
``agent/`` DIRECTORY on ``sys.path`` rather than its parent, so this module's
own ``from agent.probe_ssl import ...`` cannot resolve -- which is how the first
manual attach proof failed before it reached the kernel.

Read the walkthrough in ``agent/README.md``; this module is the loader it
drives. Slice 1 proves attach and delivery on a real handshake (ADR-0009).

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

**Every failure is a sentence, not a traceback.** An operator running this under
sudo for the first time will hit a missing symbol, a missing library or a
missing privilege, and the difference between a useful tool and an abandoned one
is whether the message says what to do next.

**Read-only, and no network.** The agent attaches probes, reads a perf buffer
and writes JSON to stdout. It never writes to the observed process, never reads
payload, and never opens a socket.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agent.probe_ssl import SYMBOL, build_source

__all__ = ["AgentError", "build_parser", "main", "resolve_libssl"]

#: Human-readable phase names, matching probe_ssl's PHASE_* constants.
_PHASES = {0: "entry", 1: "return"}

_INSTALL_HINT = (
    "bcc is not importable. It ships with the distro rather than with pip: on "
    "Debian/Ubuntu `sudo apt install python3-bpfcc`, on Fedora "
    "`sudo dnf install bcc-tools python3-bcc`. Note that bcc installs into the "
    "SYSTEM python, so run this agent with `sudo python3`, not with a venv "
    "interpreter."
)


class AgentError(RuntimeError):
    """A condition that stops the agent, reported in words rather than a stack."""


# ---------------------------------------------------------------------------
# Preflight -- everything checkable before asking the kernel for anything
# ---------------------------------------------------------------------------


def resolve_libssl(path: str) -> Path:
    """Resolve and sanity-check the library to attach to.

    Checked here rather than left to bcc because bcc's failure for a missing
    file is a bare exception from deep inside its own loader, and the operator
    needs to know it was *their path* that was wrong.
    """
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
    """Warn early if the symbol is not attachable in this library.

    Distro libssl builds are stripped, but ``SSL_do_handshake`` is a *dynamic*
    symbol and survives stripping. If it is missing, the library is statically
    linked, unusually built, or not libssl at all -- and attach would fail later
    with a much less obvious message.

    Best-effort: if ``nm`` is unavailable this says nothing and lets the attach
    speak for itself.
    """
    nm = shutil.which("nm")
    if nm is None:
        return
    try:
        result = subprocess.run(  # noqa: S603 - argv list, no shell, resolved path
            [nm, "-D", "--defined-only", str(libssl)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if result.returncode != 0:
        return
    # nm prints versioned symbols as `SSL_do_handshake@@OPENSSL_3.0.0`, so an
    # exact-suffix match silently reports every real distro libssl as missing
    # the symbol. Compare the bare name.
    found = any(
        line.rsplit(" ", 1)[-1].split("@", 1)[0] == symbol
        for line in result.stdout.splitlines()
        if " " in line
    )
    if not found:
        raise AgentError(
            f"{symbol} is not an exported dynamic symbol of {libssl}\n"
            "  A uprobe attaches by symbol name, so it cannot attach here. "
            "Likely causes: the binary links OpenSSL statically, it is a "
            "different TLS library (GnuTLS, NSS), or this is not libssl.\n"
            f"  Check with:  nm -D --defined-only {libssl} | grep {symbol}"
        )


def check_privileges() -> None:
    """Attaching eBPF needs root (or CAP_BPF + CAP_PERFMON). Say so up front."""
    if os.geteuid() != 0:
        raise AgentError(
            "attaching an eBPF probe requires root.\n"
            "  Re-run from the repository root with:\n"
            "    sudo python3 -m agent.agent --libssl-path <path> --once"
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
        "probe": SYMBOL,
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
    return json.dumps(
        {
            "pid": event["pid"],
            "tid": event["tid"],
            "comm": event["comm"].decode("utf-8", "replace").split("\x00", 1)[0]
            if isinstance(event["comm"], bytes)
            else event["comm"],
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


def run(args: argparse.Namespace) -> int:
    """Attach, drain, print. Returns a process exit code."""
    libssl = resolve_libssl(args.libssl_path)
    check_symbol(libssl)
    check_privileges()
    check_btf()

    bpf = _load_bpf(build_source(args.target_pid))

    try:
        bpf.attach_uprobe(name=str(libssl), sym=SYMBOL, fn_name="on_handshake_entry")
    except Exception as exc:
        raise AgentError(
            f"could not attach a uprobe to {SYMBOL} in {libssl}.\n"
            f"  Underlying error: {exc}"
        ) from exc

    # Best-effort: the entry probe alone proves attach and delivery, so a
    # uretprobe that will not attach must not sink the run.
    try:
        bpf.attach_uretprobe(
            name=str(libssl), sym=SYMBOL, fn_name="on_handshake_return"
        )
        probes = "uprobe+uretprobe"
    except Exception as exc:
        print(
            f"warning: uretprobe on {SYMBOL} did not attach ({exc}); "
            "continuing with the entry probe only. Return codes will be absent.",
            file=sys.stderr,
        )
        probes = "uprobe"

    print(
        f"attached {probes} to {SYMBOL} in {libssl}"
        + (f" (pid {args.target_pid} only)" if args.target_pid else "")
        + ". Waiting for a TLS handshake; Ctrl-C to stop.",
        file=sys.stderr,
    )

    seen = 0

    events_table = bpf["handshake_events"]

    def handle(_cpu: int, data: Any, _size: int) -> None:
        nonlocal seen
        # bcc's documented decoder: it derives the ctypes struct from the BPF C
        # so the layout is never restated in Python and cannot drift from it.
        event = _decode(events_table.event(data), str(libssl))
        seen += 1

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
        while True:
            bpf.perf_buffer_poll(timeout=200)
            if args.once and seen:
                break
    except KeyboardInterrupt:
        print("", file=sys.stderr)

    print(f"captured {seen} event(s)", file=sys.stderr)
    return 0 if seen else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdat-agent",
        description=(
            "Observe TLS handshakes via an eBPF uprobe on libssl. Read-only: "
            "attaches, reads, and never modifies the observed process."
        ),
        epilog="Needs root. See agent/README.md for the full walkthrough.",
    )
    parser.add_argument(
        "--libssl-path",
        required=True,
        help=(
            "path to the libssl.so the TARGET process loaded (find it with "
            "`cat /proc/<pid>/maps | grep libssl`)"
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
        "--once",
        action="store_true",
        help="exit after the first event; this is the slice-1 attach proof",
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
