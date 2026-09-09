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

#: Control symbols, attached alongside the real one by ``--controls``.
#:
#: The first attach proof attached cleanly and captured nothing, which is
#: ambiguous between three very different faults: the probe never fires, it
#: fires but the event never reaches the buffer, or it arrives and the reader
#: drops it. Attaching simple, certainly-exercised symbols and counting them
#: separates those cases in a single run. Every one of these is called during a
#: normal TLS session, so if none of them fire the fault is not specific to
#: SSL_do_handshake.
CONTROL_SYMBOLS = ("SSL_new", "SSL_read", "SSL_write")

#: Accessors whose RETURN VALUE is the negotiated fact, read as a
#: ``const char *`` from RAX (ADR-0011).
#:
#: This is the entire enrichment design, and the reason it is not fragile: each
#: of these is a public libssl function documented to return a string, so a
#: uretprobe reads a pointer whose meaning is an API contract rather than an
#: internal struct layout. Reading the cipher out of the SSL struct instead
#: would mean chasing ssl+0x900 -> session+0x2f8 -> cipher+0x8 through three
#: internal structs with no DWARF to check them against, and the negotiated
#: group is not reachable that way at all -- SSL_get_negotiated_group is not
#: exported. See ADR-0011 for the measurements.
#:
#: The cost is coverage, not correctness: these fire only when the observed
#: process asks libssl for its own version or cipher. When it does not, the
#: value is reported UNREADABLE with a reason -- never guessed.
ENRICH_SYMBOLS = ("SSL_get_version", "SSL_CIPHER_get_name", "SSL_group_to_name")

#: Probe id -> symbol, so a captured event says which probe produced it.
PROBE_IDS = {
    0: SYMBOL,
    1: "SSL_new",
    2: "SSL_read",
    3: "SSL_write",
    4: "SSL_get_version",
    5: "SSL_CIPHER_get_name",
    6: "SSL_group_to_name",
}
_SYMBOL_IDS = {symbol: probe_id for probe_id, symbol in PROBE_IDS.items()}


def probe_id_for(symbol: str) -> int:
    return _SYMBOL_IDS[symbol]


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

#: "X25519MLKEM768" and friends, with room for a longer hybrid label.
GROUP_LEN = 48

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
    "group",
)

#: ``phase`` values. Entry always fires; return additionally carries retval.
#: ``PHASE_ENRICH`` is an accessor return carrying one negotiated string.
PHASE_ENTRY = 0
PHASE_RETURN = 1
PHASE_ENRICH = 2

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
#define GROUP_LEN   {GROUP_LEN}

#define PHASE_ENTRY  {PHASE_ENTRY}
#define PHASE_RETURN {PHASE_RETURN}
#define PHASE_ENRICH {PHASE_ENRICH}

struct handshake_event_t {{
    u64 timestamp_ns;
    u32 pid;              /* userspace process id (kernel tgid) */
    u32 tid;              /* userspace thread id  (kernel pid)  */
    u32 phase;            /* PHASE_ENTRY | PHASE_RETURN         */
    u32 probe_id;         /* index into PROBE_IDS                */
    s32 retval;           /* SSL_do_handshake result; entry = 0 */
    u64 ssl_ptr;          /* opaque correlation handle, never dereferenced */
    char comm[16];               /* bpf_get_current_comm's documented size */
    char version[VERSION_LEN];   /* SSL_get_version return, or zero */
    char cipher[CIPHER_LEN];     /* SSL_CIPHER_get_name return, or zero */
    char group[GROUP_LEN];       /* SSL_group_to_name return, or zero */
}};

BPF_PERF_OUTPUT(handshake_events);

/* Entry-time SSL* per thread, so the return probe can carry the same handle.
 * Keyed by pid_tgid, so two threads handshaking at once do not collide. */
BPF_HASH(inflight, u64, u64);

static inline int emit(struct pt_regs *ctx, u32 probe_id, u32 phase,
                       s32 retval, u64 ssl_ptr)
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
    event.probe_id = probe_id;
    event.retval = retval;
    event.ssl_ptr = ssl_ptr;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    /* version/cipher/group stay zero here: the handshake probe reports the
     * event, and the accessor probes report the negotiated values. */

    handshake_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

int on_handshake_entry(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u64 ssl = (u64)PT_REGS_PARM1(ctx);   /* the SSL* argument, not read */
    inflight.update(&id, &ssl);
    return emit(ctx, 0, PHASE_ENTRY, 0, ssl);
}}

int on_handshake_return(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u64 *stashed = inflight.lookup(&id);
    u64 ssl = stashed ? *stashed : 0;
    s32 ret = (s32)PT_REGS_RC(ctx);

    if (stashed)
        inflight.delete(&id);

    return emit(ctx, 0, PHASE_RETURN, ret, ssl);
}}

/* Controls. Deliberately as simple as an entry probe can be: no map lookup,
 * no argument read. If these fire and the handshake probe does not, the fault
 * is that symbol's; if none fire, the fault is the pipeline's. */
int on_control_new(struct pt_regs *ctx)
{{
    return emit(ctx, 1, PHASE_ENTRY, 0, 0);
}}

int on_control_read(struct pt_regs *ctx)
{{
    return emit(ctx, 2, PHASE_ENTRY, 0, 0);
}}

int on_control_write(struct pt_regs *ctx)
{{
    return emit(ctx, 3, PHASE_ENTRY, 0, 0);
}}

/* ------------------------------------------------------------------------
 * Enrichment. Each of these is a uretprobe on a public libssl accessor whose
 * return value IS the negotiated fact, as a NUL-terminated const char*.
 *
 * bpf_probe_read_user_str is the only memory read in this program, and what it
 * reads is a pointer the function just returned -- not a field at an offset we
 * guessed. If the read fails the field stays zero-filled and user space reports
 * it unreadable; nothing is ever invented.
 * ------------------------------------------------------------------------ */
int on_get_version(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    TARGET_PID_FILTER

    void *str = (void *)PT_REGS_RC(ctx);
    if (str == 0)
        return 0;

    struct handshake_event_t event = {{}};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.tid = (u32)id;
    event.phase = PHASE_ENRICH;
    event.probe_id = 4;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.version, sizeof(event.version), str);

    handshake_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

int on_cipher_name(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    TARGET_PID_FILTER

    void *str = (void *)PT_REGS_RC(ctx);
    if (str == 0)
        return 0;

    struct handshake_event_t event = {{}};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.tid = (u32)id;
    event.phase = PHASE_ENRICH;
    event.probe_id = 5;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.cipher, sizeof(event.cipher), str);

    handshake_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

int on_group_name(struct pt_regs *ctx)
{{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    TARGET_PID_FILTER

    void *str = (void *)PT_REGS_RC(ctx);
    if (str == 0)
        return 0;

    struct handshake_event_t event = {{}};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = tgid;
    event.tid = (u32)id;
    event.phase = PHASE_ENRICH;
    event.probe_id = 6;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.group, sizeof(event.group), str);

    handshake_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
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
