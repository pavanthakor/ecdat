# ECDAT runtime agent — slice 1: prove one uprobe attaches

This slice answers exactly one question: **does a uprobe attach to a userspace
`libssl` on this kernel and deliver an event for a real TLS handshake?**

Everything else is deferred. The negotiated version and cipher are *not* read
this slice — see [Limits](#honest-limits) and
[ADR-0009](../docs/adr/0009-ebpf-agent-slice1.md).

## Division of labour

**Claude Code wrote the probe, the loader and the root-free tests. It did not
run any of it.** Attaching eBPF needs root, and CLAUDE.md reserves privileged
commands for the human. So the commands below are for **you** to run, and the
probe is not proved until you paste back a captured event.

The root-free parts — the event→Finding mapping, the argument parsing, the
read-only assertions on the BPF source — are covered by `tests/test_agent.py`
and run in CI with no bcc and no privileges.

---

## Before you start — two invocation rules that bit the first run

**1. Run it as a module, from the repository root.**

```bash
cd /home/pavan/projects/ecdat
sudo python3 -m agent.agent ...          # correct
sudo python3 agent/agent.py ...          # FAILS
```

Running a file that lives inside a package puts the package *directory* on
`sys.path`, not its parent, so this module's own
`from agent.probe_ssl import ...` cannot resolve. The `-m` form is the fix; no
`sys.path` shim was added, because a shim would paper over the same mistake
everywhere else in the repo.

**2. Use the system `python3`, which is where `bcc` lives.**

```bash
python3 -c "import bcc; print(bcc.__version__)"   # expect 0.35.0
```

If that fails: `sudo apt install python3-bpfcc` (Debian/Ubuntu) or
`sudo dnf install bcc-tools python3-bcc` (Fedora).

**Never `.venv/bin/python`** — the venv has no bcc.

### The interpreter clash, and how to avoid it

`bcc` is installed by the distro into the **system** interpreter. This repo's
dependencies (`pydantic` and the rest) live in the **venv**. Those are two
different Pythons, and the agent has to run in the one that has bcc.

The attach proof therefore needs **bcc only**. `agent/to_finding.py` — the
Finding mapping, and the only thing that touches pydantic — is imported lazily
and *only* when you pass `--findings`. So:

| Invocation | Needs |
|---|---|
| `--json` (the attach proof) | bcc |
| `--findings` | bcc **and** pydantic, in the same interpreter |

If you want `--findings` on the system interpreter:
`sudo python3 -m pip install pydantic` (or run it in a venv created with
`--system-site-packages` so it can see bcc).

This clash is an artefact of bcc being a distro package. The production agent
is a self-contained libbpf CO-RE binary with no Python at all, which removes it
entirely — punchlisted.

---

## Status: capture PROVEN

`--self-test` passed on kernel 7.0.0-31-generic / bcc 0.35.0 / OpenSSL 3.5:
`SSL_do_handshake` fired 6 times on one real handshake, 8 events captured, zero
decode errors, client and server threads distinguished by `tid`.

Every earlier "attached but captured 0 events" was the **three-terminal timing
race** in the manual walkthrough below — not the probe. Use `--self-test`.

## The Pillar 2 end-to-end proof (canonical)

A real TLS handshake, observed by an eBPF uprobe, becoming an **observed
component in a stored CBOM** — in one command:

```bash
cd /home/pavan/projects/ecdat
sudo scripts/prove_pillar2.sh          # or: make prove-pillar2
```

It sequences itself, so there is no terminal ordering to get wrong:

1. **(root)** `agent --self-test --controls --spool /tmp/ecdat-spool` — attach
   probes, cause a TLS handshake in a child process, write each observed event
   as one atomic JSON line into the spool.
2. **(drops back to your user)** `ecdat scan /tmp/ecdat-spool --kind spool` —
   ingest those lines as observed Findings, score them, store the CBOM.
3. Print the observed component and show the records moved to `consumed/`.

The agent chowns the spool to `$SUDO_USER` so step 2 never needs root — the scan
path stays unprivileged, which is the whole reason the seam is a directory and
not an HTTP endpoint (ADR-0010).

Expected tail:

```
  name      : TLS
  view      : observed
  locator   : host:<yours>:pid<N>
  detail    : probe=SSL_do_handshake observed_version=pending observed_cipher=pending
  PASS: a real TLS handshake reached the store as an observed component.
```

`observed_version`/`observed_cipher` are `pending` **by design** until
enrichment lands (slice 2).

## Just the probe: one command

```bash
cd /home/pavan/projects/ecdat
sudo python3 -m agent.agent --self-test --controls
```

This attaches the probes, causes a TLS handshake itself in a child process, and
reports PASS or FAIL. There is no terminal ordering to get wrong, and it cleans
up its certificate and child process on the way out.

It prints the resolved symbol offsets first, so a bad address is visible
immediately:

```
symbol offsets in /usr/lib/x86_64-linux-gnu/libssl.so.3:
  resolved SSL_do_handshake at libssl+0x425e0
  ...
attached: uprobe:SSL_do_handshake, uretprobe:SSL_do_handshake, ... [by symbol name]
self-test: probes attached; running a local TLS handshake in a child process...
self-test: handshake ok: TLSv1.3 TLS_AES_256_GCM_SHA384
captured N event(s)
  SSL_do_handshake: N
self-test: PASS -- SSL_do_handshake fired N time(s) on a real handshake.
```

**Reading a FAIL:**

| Message | Meaning | Next step |
|---|---|---|
| `PASS` | The probe works. | Done. |
| `FAIL -- events arrived, but none from SSL_do_handshake` | Pipeline is fine; that symbol's probe does not fire. | Try `--attach-by-address`. |
| `FAIL -- a handshake completed and NO probe fired` | Fault is upstream: attach, perf buffer, or poll. | Re-run with `--controls` if you omitted it. |
| `N event(s) arrived but could not be decoded` | The probe fires and the buffer works; the reader is wrong. | Paste the warning; that is a code bug. |

**`--once` against an external process is race-prone.** The manual walkthrough
below is kept for observing a *real* workload rather than a synthetic one, but
if you are answering "does the probe work?", use `--self-test`: attaching
between starting a server and running a client is exactly the ordering that
produced every false negative so far.

---

## Step 1 — make a throwaway certificate

Test material only. It is generated into `/tmp`, is self-signed, names
`localhost`, and should never be reused for anything.

```bash
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ecdat-test.key -out ecdat-test.crt \
  -days 1 -subj "/CN=localhost"
```

## Step 2 — start a local TLS server (terminal A)

This host has the OpenSSL CLI (3.5.5), so use it:

```bash
openssl s_server -key /tmp/ecdat-test.key -cert /tmp/ecdat-test.crt \
  -accept 4433 -www
```

<details>
<summary>Python fallback — use this if <code>openssl</code> is absent</summary>

Some minimal images (the `ubuntu:22.04` and `alpine:3.22` we scanned in
ADR-0006 among them) ship `libssl` but no `openssl` binary. Python's `ssl`
module links the same `libssl`, so it probes identically.

```bash
cat > /tmp/ecdat_tls_server.py <<'EOF'
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/ecdat-test.crt", "/tmp/ecdat-test.key")
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 4433)); srv.listen(5)
print("listening on 127.0.0.1:4433", flush=True)
with ctx.wrap_socket(srv, server_side=True) as tls:
    while True:
        try:
            conn, addr = tls.accept()
            print("handshake from", addr, conn.version(), conn.cipher(), flush=True)
            conn.close()
        except ssl.SSLError as exc:
            print("ssl error:", exc, flush=True)
EOF
python3 /tmp/ecdat_tls_server.py
```
</details>

## Step 3 — find the libssl the server actually loaded (terminal B)

Attach to the library **the target process loaded**, not the one on your
`$PATH`. They are usually the same and occasionally are not.

```bash
pgrep -a -f 's_server|ecdat_tls_server'          # note the PID
cat /proc/<PID>/maps | grep -i libssl            # the authoritative answer
```

On this host that is expected to be:

```
/usr/lib/x86_64-linux-gnu/libssl.so.3
```

Confirm the symbol is attachable (it is a *dynamic* symbol, so it survives the
stripping distro builds apply):

```bash
nm -D --defined-only /usr/lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_do_handshake
# 00000000000425e0 T SSL_do_handshake@@OPENSSL_3.0.0
```

## Step 4 — attach the probe (terminal B, as root)

```bash
cd /home/pavan/projects/ecdat
sudo python3 -m agent.agent \
  --libssl-path /usr/lib/x86_64-linux-gnu/libssl.so.3 \
  --once --json
```

Optionally narrow it to the server process with `--target-pid <PID>`, and add
`--findings` to also print the mapped ECDAT Finding.

You should see on stderr:

```
attached uprobe+uretprobe to SSL_do_handshake in /usr/lib/x86_64-linux-gnu/libssl.so.3. Waiting for a TLS handshake; Ctrl-C to stop.
```

It now blocks, waiting.

## Step 5 — trigger one handshake (terminal C)

```bash
openssl s_client -connect 127.0.0.1:4433 </dev/null
```

<details>
<summary>Python fallback client</summary>

```bash
python3 - <<'EOF'
import socket, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 4433)),
                     server_hostname="localhost") as s:
    print("client negotiated", s.version(), s.cipher())
EOF
```
</details>

## Step 6 — what success looks like

The agent prints one JSON object per line and, with `--once`, exits after the
first. A successful capture looks like this — `observed_version` and
`observed_cipher` are `null` **by design this slice**:

```json
{"comm":"openssl","libssl_path":"/usr/lib/x86_64-linux-gnu/libssl.so.3","observed_cipher":null,"observed_version":null,"phase":"entry","pid":48231,"probe":"SSL_do_handshake","retval":0,"timestamp":68421339115523,"tid":48231}
```

then on stderr:

```
captured 1 event(s)
```

Exit code `0` means at least one event was captured; `1` means it attached but
saw nothing; `2` means it could not attach and the reason is printed in words.

**Paste that JSON line back.** Until it exists, the probe is unproven — nothing
in this repo claims otherwise.

---

## Honest limits

* **Linux only.** uprobes are a Linux facility; there is no macOS or Windows
  equivalent of this approach.
* **Version and cipher are pending enrichment (slice 2).**
  `SSL_do_handshake(SSL *s)` hands over a pointer to an opaque, version-
  dependent struct. Reading the negotiated version out of it needs either
  hard-coded struct offsets or a second probe on `SSL_get_version` — real work,
  and exactly the pointer-chasing that would have stalled the attach proof.
  Findings from this slice carry `pending_enrichment: true` so they are visibly
  *unread* rather than silently *unknown*.
* **You must know the process's libssl.** A uprobe attaches to a specific file
  on disk. Two processes using two different OpenSSL builds need two attaches.
* **Statically linked or stripped-of-dynamic-symbols TLS is invisible.** A Go
  binary using `crypto/tls`, or anything linking OpenSSL statically, has no
  `libssl.so` to attach to. The agent says so rather than silently reporting
  nothing.
* **Other TLS libraries are not covered.** GnuTLS, NSS and mbedTLS have their
  own symbols and are not probed.
* **No container attribution.** Slice 1 deliberately targets a plain host
  process. Mapping a PID to a container/cgroup comes later.
* **Read-only, always.** The probe uses no helper that can write to, block, or
  alter the observed process, and reads no payload — there is no code path by
  which plaintext or key material could reach an event. `tests/test_agent.py`
  asserts the absence of `bpf_probe_write_user`, `bpf_override_return` and
  `bpf_send_signal` in the BPF source.
* **Two Pythons.** bcc is a distro package in the system interpreter; this
  repo's deps are in a venv. The attach proof needs only bcc, but anything that
  builds a `Finding` needs pydantic in that same interpreter. The production
  CO-RE agent has no Python and no such clash.
* **Not wired into the store yet.** The agent is a separate root process, not an
  in-process `Scanner`, so it is deliberately **not** in `core/registry.py`.
  Feeding `observed` findings into the store and the drift correlator is a
  later slice.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No module named 'agent'` | Ran `python3 agent/agent.py`. Use `python3 -m agent.agent` from the repo root. |
| `bcc is not importable` | Running under the venv. Use the system `sudo python3`. |
| `No module named 'pydantic'` with `--findings` | pydantic is venv-only. Drop `--findings`, or install it into the system interpreter. |
| `use of undeclared identifier 'TASK_COMM_LEN'` | Fixed — the probe now uses a literal `char comm[16]`. Pull the latest commit. |
| `requires root` | Missing `sudo`. |
| `is not an exported dynamic symbol` | Wrong file, or statically linked TLS. |
| `BPF program failed to compile` | Kernel headers missing — install `linux-headers-$(uname -r)`. |
| Attaches, `captured 0 event(s)` | No handshake happened on *that* libssl. Re-check `/proc/<pid>/maps`. |
| `uretprobe ... did not attach` warning | Entry probe still works; return codes absent. Not fatal. |
