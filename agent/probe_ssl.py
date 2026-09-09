"""The BPF program: one read-only uprobe on ``SSL_do_handshake``.

Slice 1 answers one question -- *does a uprobe attach to a userspace libssl on
this kernel and deliver an event?* Everything else is deferred, because a probe
that never attaches makes the enrichment work worthless, and enrichment work is
where uprobe projects usually stall (ADR-0009).

**Read-only, and structurally so.** The program calls no helper that can write
to, block, or alter the observed process: no ``bpf_probe_write_user``, no
``bpf_override_return``, no ``bpf_send_signal``. It reads the current pid, the
command name and a timestamp, and on return the integer result. It never
touches the SSL buffer, so no plaintext and no key material can pass through
it -- there is no code path by which they could. A test asserts the absence of
those helpers, so a later edit cannot quietly add one.

**Perf buffer, not ring buffer.** Both work on this kernel, but the whole point
of slice 1 is a single manual attach that succeeds first time on a machine the
author cannot test on. ``BPF_PERF_OUTPUT`` is the oldest, most universally
supported bcc output path; ``BPF_RINGBUF_OUTPUT`` needs kernel 5.8+ and a
newer bcc surface. The cost is a little overhead and possible reordering,
neither of which matters for one event. Revisit in slice 2, when attach is a
known quantity rather than the thing being proved.

**No version or cipher this slice.** ``SSL_do_handshake(SSL *s)`` gives a
pointer to an opaque, version-dependent struct. Reading a negotiated version
out of it means either hard-coded struct offsets or a second probe on
``SSL_get_version``; both are real work and both are exactly the kind of
pointer-chasing that would stall the attach proof. The pointer is carried
through as an opaque correlation handle so slice 2 can pair an entry with its
return, and the version/cipher fields are zero-filled and reported as pending.
"""

from __future__ import annotations

__all__ = ["EVENT_STRUCT_FIELDS", "PROBE_SOURCE", "SYMBOL", "VERSION_LEN"]

#: The libssl symbol both probes attach to. Exported from OpenSSL 1.x and 3.x,
#: and a *dynamic* symbol -- so it survives the stripping that distro libssl
#: builds apply, and attach by name works without debug symbols.
SYMBOL = "SSL_do_handshake"

#: The size ``bpf_get_current_comm`` writes. This is the helper's documented
#: contract, not an assumption about the kernel: the comm buffer has been 16
#: bytes since the helper existed, and bcc's own examples hard-code it.
#:
#: Written as a literal rather than as ``TASK_COMM_LEN`` deliberately. The first
#: manual attach proof failed with
#:     /virtual/main.c:17:15: error: use of undeclared identifier 'TASK_COMM_LEN'
#: on kernel 7.0 with bcc 0.35. That macro is predefined by some bcc/header
#: combinations and not others, so naming it makes the probe compile against
#: the author's environment rather than the operator's.
COMM_LEN = 16

#: Sized to hold "TLSv1.3" and a JOSE-style suite name with room to spare.
#: Zero-filled this slice; see the module docstring.
VERSION_LEN = 24
CIPHER_LEN = 64

#: The fields user space reads off each event, documented once so the loader
#: and the tests agree on the contract.
EVENT_STRUCT_FIELDS = (
    "timestamp_ns",
    "pid",
    "tid",
    "phase",
    "retval",
    "ssl_ptr",
    "comm",
    "version",
    "cipher",
)

#: ``phase`` values. Entry always fires; return additionally carries retval.
PHASE_ENTRY = 0
PHASE_RETURN = 1

# ---------------------------------------------------------------------------
# The BPF C. Kept deliberately small: every line here runs in the kernel on
# every handshake of every observed process.
#
# `pid` vs `tid`: bpf_get_current_pid_tgid() returns (tgid << 32) | pid, where
# the kernel's `pid` is what userspace calls a THREAD id and the kernel's `tgid`
# is what userspace calls a PROCESS id. Naming them the kernel's way here would
# guarantee somebody later filters on the wrong one, so the event uses the
# userspace meaning: `pid` is the process, `tid` is the thread.
# ---------------------------------------------------------------------------
PROBE_SOURCE = f"""
#include <uapi/linux/ptrace.h>

/* Sizes are literals substituted from Python, and comm[] is written as a bare
 * 16 below. Nothing here depends on a macro bcc may or may not predefine --
 * see COMM_LEN in this module for why. */
#define VERSION_LEN {VERSION_LEN}
#define CIPHER_LEN  {CIPHER_LEN}

#define PHASE_ENTRY  {PHASE_ENTRY}
#define PHASE_RETURN {PHASE_RETURN}

struct handshake_event_t {{
    u64 timestamp_ns;
    u32 pid;              /* userspace process id (kernel tgid) */
    u32 tid;              /* userspace thread id  (kernel pid)  */
    u32 phase;            /* PHASE_ENTRY | PHASE_RETURN         */
    s32 retval;           /* SSL_do_handshake result; entry = 0 */
    u64 ssl_ptr;          /* opaque correlation handle, never dereferenced */
    char comm[16];               /* bpf_get_current_comm's documented size */
    char version[VERSION_LEN];   /* pending enrichment: zero-filled */
    char cipher[CIPHER_LEN];     /* pending enrichment: zero-filled */
}};

BPF_PERF_OUTPUT(handshake_events);

/* Entry-time SSL* per thread, so the return probe can carry the same handle.
 * Keyed by pid_tgid, so two threads handshaking at once do not collide. */
BPF_HASH(inflight, u64, u64);

static inline int emit(struct pt_regs *ctx, u32 phase, s32 retval, u64 ssl_ptr)
{{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    /* The loader substitutes the placeholder below with either nothing or a
     * guard dropping every event from other processes. Written on its own line
     * so the substitution cannot touch this comment. */
    TARGET_PID_FILTER

    struct handshake_event_t event = {{}};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.tid = (u32)id;
    event.phase = phase;
    event.retval = retval;
    event.ssl_ptr = ssl_ptr;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    /* version[] and cipher[] stay zero: slice 1 does not read them. */

    handshake_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

int on_handshake_entry(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u64 ssl = (u64)PT_REGS_PARM1(ctx);   /* the SSL* argument, not read */
    inflight.update(&id, &ssl);
    return emit(ctx, PHASE_ENTRY, 0, ssl);
}}

int on_handshake_return(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u64 *stashed = inflight.lookup(&id);
    u64 ssl = stashed ? *stashed : 0;
    s32 ret = (s32)PT_REGS_RC(ctx);

    if (stashed)
        inflight.delete(&id);

    return emit(ctx, PHASE_RETURN, ret, ssl);
}}
"""

#: Substituted into PROBE_SOURCE when --target-pid is given. Written as a
#: template rather than built with string concatenation at the call site so the
#: only thing interpolated into kernel C is an integer the loader has already
#: validated.
TARGET_PID_GUARD = "if (tgid != {pid}) {{ return 0; }}"


def build_source(target_pid: int | None = None) -> str:
    """The probe source, optionally narrowed to one process.

    ``target_pid`` is interpolated as an integer only -- the loader validates it
    before it reaches here, so nothing an operator types becomes kernel C.
    """
    guard = "" if target_pid is None else TARGET_PID_GUARD.format(pid=int(target_pid))
    return PROBE_SOURCE.replace("TARGET_PID_FILTER", guard)
