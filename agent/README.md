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

## Before you start

`bcc` lives in the **system** Python, not in this repo's `.venv`:

```bash
python3 -c "import bcc; print(bcc.__version__)"   # expect 0.35.0
```

If that fails: `sudo apt install python3-bpfcc` (Debian/Ubuntu) or
`sudo dnf install bcc-tools python3-bcc` (Fedora).

**Run the agent with `sudo python3`, never with `.venv/bin/python`** — the venv
has no bcc.

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
sudo python3 agent/agent.py \
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
* **Not wired into the store yet.** The agent is a separate root process, not an
  in-process `Scanner`, so it is deliberately **not** in `core/registry.py`.
  Feeding `observed` findings into the store and the drift correlator is a
  later slice.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `bcc is not importable` | Running under the venv. Use `sudo python3`. |
| `requires root` | Missing `sudo`. |
| `is not an exported dynamic symbol` | Wrong file, or statically linked TLS. |
| `BPF program failed to compile` | Kernel headers missing — install `linux-headers-$(uname -r)`. |
| Attaches, `captured 0 event(s)` | No handshake happened on *that* libssl. Re-check `/proc/<pid>/maps`. |
| `uretprobe ... did not attach` warning | Entry probe still works; return codes absent. Not fatal. |
