# ADR-0009: The eBPF runtime agent, slice 1

* Status: accepted (probe **unproven** until a human pastes a captured event)
* Date: 2026-09-09
* Slice: eBPF agent slice 1 — prove one uprobe attaches (Pillar 2 de-risk)
* Extends: [ADR-0001](0001-architecture.md) (the three views)

## Context

`observed` is the third drift view and the one that can contradict both others:
a repo can declare TLS 1.3, an image can ship an OpenSSL that supports it, and
the process can still negotiate TLS 1.2 against a legacy peer. Nothing but
runtime observation catches that.

It is also the riskiest thing in the project. Everything else runs as an
ordinary user against files. This needs root, a kernel facility, a userspace
symbol in someone else's shared library, and a toolchain that may not compile
on the running kernel. **The risk is concentrated entirely in "does it attach at
all".** So this slice buys down that specific risk and nothing else.

## Decision

### Attach first, enrich second

The event carries pid, tid, comm, timestamp, the return code, and the fact that
a handshake happened on a named libssl. It does **not** carry the negotiated
version or cipher.

That is the whole discipline of the slice. `SSL_do_handshake(SSL *s)` gives a
pointer to an opaque, version-dependent struct; reading a version out of it
means hard-coded offsets or a second probe on `SSL_get_version`. Both are real
work, both are where uprobe projects stall, and both are worthless if the probe
never attaches. Enrichment is slice 2, and it is now a *known* piece of work
sitting behind a *proven* mechanism rather than the reverse.

Findings from this slice carry `pending_enrichment: true`, so an unread field is
visibly unread rather than reported as `unknown` — which a later reader would
take for an observation.

### bcc now, libbpf CO-RE later

bcc compiles the BPF C at load time against the running kernel's headers. That
is heavier than a CO-RE binary and is exactly what is wanted for a proof: no
cross-compilation step, no BTF-relocation surprises, and a failure mode that
says "kernel headers missing" instead of failing silently on a struct offset.
libbpf CO-RE is the right answer for a shipped agent and is deferred.

### Perf buffer, not ring buffer

Both work on kernel 7.0 and bcc 0.35. `BPF_PERF_OUTPUT` was chosen because the
point of this slice is a **single manual attach that succeeds first time on a
machine the author cannot test on**. Perf output is the oldest and most
universally supported bcc output path; ring buffer needs kernel 5.8+ and a newer
bcc surface. The cost is a little overhead and possible reordering, neither of
which matters for one event. Revisit in slice 2, once attach is a known
quantity rather than the thing being proved.

### uprobe always, uretprobe best-effort

The entry probe alone proves attach and delivery, so a uretprobe that will not
attach must not sink the run: the agent warns, degrades to entry-only, and says
that return codes will be absent. The return probe adds `retval` (did the
handshake succeed) and pairs with the entry via an opaque `SSL*` handle stashed
per `pid_tgid` — the handle slice 2 needs to correlate the two.

### Read-only, structurally

The BPF program calls no helper that can write to, block, or alter the observed
process — no `bpf_probe_write_user`, no `bpf_override_return`, no
`bpf_send_signal`. It never touches the SSL buffer, so there is no code path by
which plaintext or key material could reach an event; this is a property of what
the program *cannot do*, not a promise about what it chooses not to. A test
asserts those helpers are absent from the source so a later edit cannot quietly
add one.

### bcc is imported lazily, inside the attach path

bcc lives in the **system** Python and needs root. Importing it at module scope
would make the event→Finding mapping — the part with actual logic in it —
unimportable in CI and in this repo's venv, and the whole suite would become
root-only. `test_bcc_is_not_imported_at_module_scope` asserts the boundary holds.

The mapping lives in `agent/to_finding.py` with no bcc import at all, so the
interesting logic is tested on every commit while the probe is tested by hand,
once.

### Every failure is a sentence

An operator running this under sudo for the first time will hit a missing
symbol, a wrong library or a missing privilege. The difference between a useful
tool and an abandoned one is whether the message says what to do next, so
`AgentError` carries the diagnosis and the command to run, and `main` prints it
without a traceback.

This paid for itself before the human ran anything: the symbol check originally
compared with `line.endswith(" SSL_do_handshake")`, and `nm` prints
`SSL_do_handshake@@OPENSSL_3.0.0`. Every real distro libssl would have been
reported as missing the symbol. Caught by running the error path locally —
which needs no root — and pinned by a test.

### Garbage that parses is skipped, not fatal

Events are read out of a C struct in a kernel buffer. A truncated read or a
`comm` with invalid UTF-8 produces a dict that looks fine and is not.
`event_to_finding` returns `None` and logs the reason rather than raising,
because **an agent that dies on one odd event stops observing, and a host that
has stopped being observed looks exactly like a host with no cryptography.**

Where a field is garbage the whole event is dropped rather than partially
trusted: if `comm` was misread, the other fields came from the same bytes and
have no better claim to being right.

### The manual-proof protocol

CLAUDE.md reserves sudo for the human. So: Claude Code wrote the probe, the
loader, the mapping and the root-free tests, and ran none of it.
`agent/README.md` carries the exact copy-pasteable sequence — throwaway cert,
local `s_server` (with a Python fallback for images that ship libssl but no
`openssl` binary, as `ubuntu:22.04` and `alpine:3.22` both do), finding the
right libssl via `/proc/<pid>/maps`, the sudo command, and what a successful
JSON line looks like.

**The probe is unproven until a captured event is pasted back.** This ADR's
status says so, and nothing in the repo claims the probe works.

## Consequences

* Pillar 2's central technical risk is isolated to one command a human runs
  once. If it fails, it fails now and cheaply, with a message naming the cause.
* Not registered in `core/registry.py`. The agent is a separate root process,
  not an in-process `Scanner`; the scan path deliberately needs no privileges.
  Wiring `observed` findings into the store and the correlator is a later slice.
* `--findings` already prints the mapped Finding, so the shape of the eventual
  integration is visible without building it.
* **Coverage is narrower than "TLS on this host".** Statically linked TLS, Go's
  `crypto/tls`, GnuTLS, NSS and mbedTLS are all invisible to a `libssl` uprobe.
  The agent reports that it cannot attach rather than reporting nothing found —
  the distinction that matters for an inventory.
* No container/cgroup attribution: slice 1 targets a plain host process
  deliberately, so a PID-to-container mapping cannot fail alongside the attach.

## Alternatives considered

* **Probe `SSL_read`/`SSL_write` instead.** They carry the plaintext buffer,
  which is why every TLS-sniffing tutorial uses them — and why this project must
  not. ECDAT is an inventory tool; it has no business anywhere near payload, and
  `SSL_do_handshake` gives the fact we want with no plaintext in reach.
* **Parse packets with tcpdump/pcap instead of eBPF.** Sees the wire but not the
  process, so it cannot attribute a handshake to a PID or a binary, which is
  most of the value of the `observed` view. It also cannot see anything about a
  session it did not capture from the first byte.
* **libbpf CO-RE now.** The right end state, and it front-loads BTF and
  relocation problems onto the slice whose only job is proving attach.
* **Ship the enrichment in slice 1.** Tempting, and it is the failure mode this
  ADR exists to avoid: struct-offset chasing produces no evidence that anything
  attaches, and would have hidden the `nm` bug behind a bigger unproven surface.
