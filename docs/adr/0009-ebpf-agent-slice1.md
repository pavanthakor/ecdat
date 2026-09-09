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

## What the first attach proof found

The manual proof got as far as bcc compiling the program, which already
established that the loader, the privilege path and the attach machinery work.
It then failed, and the failures are worth recording because two of the three
were invisible to every root-free test.

**1. `TASK_COMM_LEN` is not predefined.**

```
/virtual/main.c:17:15: error: use of undeclared identifier 'TASK_COMM_LEN'
    char comm[TASK_COMM_LEN];
```

The macro is supplied by some bcc/kernel-header combinations and not others.
The probe now writes `char comm[16]` as a literal — 16 is the documented
contract of `bpf_get_current_comm`, not an assumption about the kernel — and a
test asserts the macro is never named again. **Only a real compile could have
caught this**, which is precisely why the manual proof exists.

**2. `python3 agent/agent.py` cannot import its own package.**

Running a file inside a package puts the package *directory* on `sys.path`
rather than its parent, so `from agent.probe_ssl import ...` fails before the
kernel is ever reached. Fixed by documenting `python3 -m agent.agent`, not by
adding a `sys.path` shim: a shim would hide the same mistake everywhere else in
the repo, and the `-m` form is the one that is correct anyway.

**3. bcc and pydantic live in different interpreters.**

bcc is a distro package in the system Python; this repo's dependencies are in a
venv. The agent must run where bcc is, so it must not need anything else.
`agent.to_finding` — and through it pydantic — is now imported lazily and only
under `--findings`, so the attach proof itself needs bcc and nothing more. The
production CO-RE agent has no Python and removes the clash entirely.

**4. A bug the proof would have hit next, found by reading bcc instead.**

The event decoder used `ctypes.cast(data, POINTER(table.event_data_type))`.
`event_data_type` does not exist in bcc 0.35; the documented API is
`table.event(data)`. That would have raised `AttributeError` on the first
captured event — *after* the operator had fixed the compile error and re-run.
Found by reading the installed bcc's source rather than by another round trip
through the human, and pinned by two tests: one static, one that checks the
claim against the installed bcc when it is visible.

The pattern across all four: root-free tests cover the mapping and the
invocation surface well, and cannot say anything about whether kernel C
compiles or whether a third-party Python API exists. Reading the dependency is
the cheapest substitute for running it; the manual proof is the only thing that
settles the rest.

## What the second attach proof found: attach succeeded, zero events

The probe attached cleanly and captured nothing across five real TLS 1.3
handshakes, with the library confirmed identical by inode on both peers. The
leading theory was symbol resolution -- that bcc resolved the versioned
`SSL_do_handshake@@OPENSSL_3.0.0` to the wrong address, or through an IFUNC/PLT
indirection, so the uprobe sat somewhere never executed.

**That theory is disproved, and it cost no round trip to disprove.** Both checks
run without root:

* `libbcc`'s own `bcc_resolve_symname` returns `0x425e0` for
  `SSL_do_handshake`, exactly matching `objdump -T` and an independent ELF
  parse. Not zero, not an alias, no IFUNC (`nm` reports `T`, not `i`).
* Disassembly shows both callers reach it:
  `SSL_connect+0x22: jmp 425e0 <SSL_do_handshake@@OPENSSL_3.0.0>` and
  `SSL_accept+0x22: jmp 425e0`. The address is right *and* it is executed on
  every handshake.

So the fault is elsewhere, and "attached but silent" is ambiguous between three
unrelated causes with three different fixes: the probe never fires, it fires but
the event never reaches userspace, or the event arrives and the reader drops it.
Rather than guess again, this round makes the next run *decisive*.

### The diagnostics, and what each one rules out

**Symbol offsets printed every run** (`agent/elfsym.py`, a dependency-free ELF64
dynsym reader -- the agent runs on the system interpreter, so pyelftools is not
available). A uprobe at offset 0 sits on the ELF header, is never executed, and
looks exactly like a healthy attach. Printing a real number makes that visible
in one line.

**Control probes** (`--controls`) on `SSL_new`, `SSL_read` and `SSL_write` --
simple entry probes with no map lookup and no argument read, all certainly
called during a TLS session. If controls fire and `SSL_do_handshake` does not,
the fault is that symbol's. If nothing fires, the fault is the pipeline's. Each
event carries a `probe_id` so it names its own source.

**Attach by address** (`--attach-by-address`) passes the ELF-resolved file
offset instead of the symbol name, removing bcc's name resolution from the
picture entirely.

**Counting before decoding.** The event counter now increments *before* the
event is decoded, and decode failures are counted and printed separately. ctypes
callbacks swallow exceptions by design, so an `AttributeError` in the decoder
previously produced exactly the observed symptom -- "captured 0 events" -- while
the probe was working perfectly. That conflation is now impossible to make.

### `--self-test` removes the race

The three-terminal walkthrough asks the operator to attach *between* starting a
server and running a client. That is a race, and a race is a poor foundation for
a go/no-go answer. `--self-test` attaches first, then spawns a TLS handshake in
a child process against a throwaway cert in a temporary directory, drains, and
reports PASS or FAIL with a diagnosis. One command, no ordering to get wrong,
everything cleaned up on the way out. `--libssl-path` gained a default so
`sudo python3 -m agent.agent --self-test` needs nothing else.

The poll loop was re-checked and is a loop with a real 200 ms timeout, not a
single poll -- `perf_buffer_poll` returns as soon as it has drained what is
ready, which is routinely before the awaited event exists.

### The lesson

Two rounds of this have now been resolved by reading something locally rather
than by asking the human to run something again: the `nm` versioned-symbol bug,
the non-existent `event_data_type`, and now the address theory. Root-free
inspection is far cheaper than a round trip, and the remaining unknowns are
exactly the ones that genuinely require the kernel.

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
