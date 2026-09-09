# ADR-0011: Enriching the observed view with negotiated version/cipher/group

* Status: accepted (mapping proven root-free; enriched capture awaits a human run)
* Date: 2026-09-09
* Slice: enrichment
* Extends: [ADR-0009](0009-ebpf-agent-slice1.md) (the probe),
  [ADR-0010](0010-spool-seam.md) (the seam)

## Context

ADR-0009 deliberately deferred enrichment: the probe captured *that* a handshake
happened and marked the negotiated values `pending`. That was the right call for
proving attach, and it is useless for drift. The whole point of the observed
view is catching a repo that **declares** a hybrid post-quantum group while the
process **negotiates** a classical one, and "TLS, pending" cannot express that.

## Measurement first

### Path (a) — read struct fields at offsets — measured and REJECTED

Disassembling this VM's `libssl.so.3` (OpenSSL 3.5.5):

```
SSL_get_version:          mov (%rdi),%eax        ; type tag at offset 0
                          je  → mov 0x48(%rdi)   ; version int, type-0 only
                          test $0x80,%al → QUIC path

SSL_get_current_cipher:   mov 0x900(%rdi),%rax   ; ssl -> session
                          mov 0x2f8(%rax),%rax   ; session -> cipher
SSL_CIPHER_get_name:      mov 0x8(%rdi),%rax     ; cipher -> name
```

Three findings decided against this:

1. **The cipher needs a four-level chase through three unrelated internal
   structs** (`SSL_CONNECTION` → `SSL_SESSION` → `SSL_CIPHER` → `char*`), at
   offsets `0x900` and `0x2f8` that are large, internal, and move between
   OpenSSL minor releases.
2. **There is no DWARF to check them against.** `readelf -S` reports zero
   `.debug_*` sections and no debug package is available, so the offsets could
   only ever be transcribed from a disassembly of *this* build.
3. **The negotiated group is unreachable this way at all.**
   `SSL_get_negotiated_group` is **not exported** by this libssl, so there is no
   accessor to disassemble and no documented struct position to read.

OpenSSL 3.5 also makes `SSL` a *polymorphic base* with a type tag at offset 0
(TLS / QUIC / listener), so even the version read needs a tag gate before the
`0x48` is meaningful. That is doable, but it buys one field out of three at the
cost of exactly the fragility the frame warns about.

### Path (b) — CHOSEN: uretprobes on public accessors

The same disassembly shows the accessors are trivial leaves that return a
`const char *`:

```
SSL_CIPHER_get_name:  mov 0x8(%rdi),%rax ; ret     ← returns const char*
SSL_group_to_name:    exported ✓                   ← the ONLY route to the group
SSL_get_version:      returns const char*
```

So a **uretprobe reads `RAX` with `bpf_probe_read_user_str`** and gets
`"TLSv1.3"`, `"TLS_AES_256_GCM_SHA384"`, `"X25519MLKEM768"` directly.

**There are no struct offsets anywhere in this design.** "This function returns a
NUL-terminated string" is a public API contract that OpenSSL cannot break
without a major version bump; `0x900` is an implementation detail that can move
in a patch release. The single memory read in the whole program dereferences a
pointer the function *just returned*, not a field at a position we guessed.

`SSL_group_to_name` being exported while `SSL_get_negotiated_group` is not also
means accessors are the only route to the group at all — consistency argues for
using them throughout rather than mixing two mechanisms.

### The cost, stated plainly

**Coverage, not correctness.** These fire only when the observed process asks
libssl for its own version or cipher. `openssl s_client`/`s_server` do (they
print them), Python's `ssl` module does (`.version()`, `.cipher()`), and most
TLS-logging applications do — but a process that never asks gives us nothing to
read. That case is reported `enrichment="partial"` or `"none"` **with a
reason**, never guessed. Per the frame: honest partial beats fragile full.

## Decision

### Nothing is ever invented

A value is emitted only if it was read. `_clean_enrichment` refuses anything
non-printable (reading a wrong address yields bytes, and bytes are not a suite
name), over-long (>96 chars — the longest real suite name is ~45), empty, or of
the wrong type, and records *why*. A wrong-**typed** field means the record
itself is untrustworthy and the whole event is dropped; a merely unreadable one
is an honest gap.

Every observed finding carries `enrichment` (`full` / `partial` / `none`) and,
when not full, `enrichment_reason`. "We did not read it" and "there was nothing
to read" are different claims and a reader must be able to tell them apart.

### Nothing is negotiated at entry, or on failure

Values are attached only when `phase == "return"` **and** `retval == 1`. An
entry-phase event and a failed handshake carry no negotiated values and say so —
reporting a suite for a handshake that failed would be a claim the wire does not
support.

### One handshake, three artefacts

A TLS handshake negotiates three separate cryptographic facts, so
`event_to_findings` returns up to three components sharing one locator:

| Fact | Artefact |
|---|---|
| version | `protocol` / TLS, `params.version` |
| cipher suite | `algorithm`, primitive from a short explicit table (AES → block-cipher, ChaCha20 → stream-cipher), `usage=encrypt` |
| key-exchange group | `algorithm`, `key-agreement`, `usage=key-exchange`, `hybrid: true` when the label carries MLKEM/Kyber/etc. |

The suite→primitive table is deliberately short and explicit: a name it does not
recognise yields `unknown`, because guessing the most likely primitive is the
same class of invention this design exists to avoid.

`event_to_finding` still returns the principal (protocol) artefact, so existing
callers keep working.

### Correlation happens in user space, with a window

An application calls `SSL_do_handshake` and only *then* asks what it negotiated,
so enrichment always arrives **after** the handshake it belongs to. The agent
holds a completed handshake per `(pid, tid)` for `ENRICH_WINDOW_S` (0.4 s),
attaches accessor values as they arrive, and emits early once all three are in.
Expiry is what stops a process that never calls an accessor from holding a
record forever — it is emitted honestly unenriched instead.

The ADR-0009 lazy-import split is unchanged and re-verified: `agent.agent`
imports on the system interpreter with **neither pydantic nor bcc** pulled in.

## Consequences

* **This unblocks the correlator's drift beat.** A repo declaring
  `X25519MLKEM768` and a host observed negotiating `x25519` now produce two
  comparable artefacts in the same CBOM, with `hybrid: true` on one and not the
  other. That comparison is the product.
* The observed view names what actually ran, so policy scores a real suite
  rather than a placeholder.
* **`--no-enrich` exists** to turn the accessor probes off, because they add
  three uretprobes to hot-ish functions (`SSL_CIPHER_get_name` is called per
  connection by anything that logs).
* Coverage is application-dependent, as above. An estate whose services never
  log their TLS parameters will show `partial` — visibly, with a reason, which
  is itself a finding about that estate.
* Path (a) is not closed off: if a future slice needs enrichment for silent
  applications, the type-tag-gated `0x48` version read is the least-bad start,
  and it must carry the refuse-on-mismatch discipline rather than reading
  whatever is there.

## Alternatives considered

* **Offsets with a gate (path a).** Measured above. One field of three, with no
  DWARF to verify against, and the group unreachable regardless.
* **Coarse-only (path c).** What ADR-0009 shipped. Correct then, and it leaves
  the drift beat unbuildable, which is the whole reason for the observed view.
* **Probing internal functions that receive the negotiated values as
  arguments** (`ssl_choose_client_version` and friends). They are not exported
  and the library is stripped, so there is no symbol to attach to.
* **Parsing the ServerHello off the wire.** Sees the negotiation without any
  libssl coupling, and cannot attribute it to a process — which is most of the
  value of the observed view — and fails entirely on encrypted handshakes.
