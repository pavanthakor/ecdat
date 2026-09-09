# ADR-0013: The config scanner — the endpoint-oriented declared view

* Status: accepted — **makes the drift beat run live**
* Date: 2026-09-09
* Slice: config scanner
* Extends: [ADR-0004](0004-source-scanning-semgrep.md) (source scanning),
  [ADR-0011](0011-enrichment.md) (the observed spelling),
  [ADR-0012](0012-correlator-drift.md) (the correlator)

## Context

ADR-0012 made config-declared against observed the **primary** drift axis, and
then had to record that nothing produced the config side. R1 could run against
real fixtures; R2, R3 and R4 had no declared producer and existed only against
hand-built components. That was the largest remaining gap in Pillar 2's story.

## Decision

### Parsers per format, not Semgrep

The source scanner's rule-pack design (ADR-0004) is right for code: the
interesting thing is a call site, the grammar is enormous, and Semgrep already
owns it. Config is the opposite — small, structured grammars where the
interesting thing is **a directive inside a block**. Semgrep's generic mode
matches text without understanding nesting, and nesting is exactly what carries
the endpoint.

So: a small parser per format. `nginx.py` is a brace-depth scanner, not an nginx
grammar; it needs to know which block a directive is in and nothing else.

### The endpoint is the join key

`ssl_ecdh_curve X25519MLKEM768` inside `server { listen 443; }` is a fact about
**that** endpoint and about no other. The endpoint is built from `listen` and
`server_name` into `host:port` (`api.quantumbank.invalid:443`), and it is what
the correlator joins the observed view on.

**Misattribution is the characteristic failure of a config parser**, and the
dangerous kind: a parser that attributed directives to the *file* would put
`X25519MLKEM768` and `TLSv1` on the same endpoint, the correlator would compare
a handshake against whichever config it picked, and every test would still pass.
So the endpoint is part of the answer key, and the central fixture is two server
blocks with deliberately different crypto.

### Global configs get a scope marker, not a fake endpoint

sshd and openssl.cnf apply to a daemon or a whole system — there is no
per-endpoint block. They carry `sshd@<system>` and `openssl@<system>`.

Deliberately *not* shaped like `host:port`: inventing `:22` for sshd would let
the correlator join an SSH key-exchange policy against an unrelated TLS
handshake and report drift between two things that have nothing to do with each
other.

### Canonicalisation, because the join is a string comparison

The correlator compares declared and observed group names as strings, so a
declared `P-256` and an observed `prime256v1` must become the same token or the
comparison silently never matches — the worst failure mode available, because it
looks like agreement.

`canonical_group` maps aliases to **the spelling OpenSSL itself reports**, since
that is what ADR-0011's observed side carries (it reads `SSL_group_to_name`).
The post-quantum marker table is the same one ADR-0011 uses, so a declared
hybrid and an observed hybrid agree about being hybrid.

### Precision over recall, again

A commented-out directive reported as live configuration is a finding an
operator will chase and find nothing behind. Comments are stripped *before* any
matching, and a directive outside an ssl-bearing `server` block is not reported
at all. The decoy fixture is a commented `ssl_protocols`, a `map` block whose
*value* reads like a cipher list, and a plain-HTTP block whose `server_name`
merely contains "ssl". None of them fire.

`configurable=True` on every finding: config is by definition changeable without
a code edit, and this is the one view where that is knowable rather than
inferred. It feeds ADR-0008's migration-effort estimate.

### Scope

**In:** nginx (`nginx.conf`, `conf.d/*.conf`, `sites-*`), `sshd_config`,
`openssl.cnf`.

**Apache: skipped.** `SSLProtocol` / `SSLCipherSuite` / `SSLOpenSSLConfCmd` are
individually easy, but Apache's endpoint lives in `<VirtualHost *:443>` plus
`ServerName`, which is a second block grammar — the same work as nginx again,
not the cheap addition the frame allowed for. Deferred and punchlisted rather
than half-done.

**Deferred:** HAProxy, Postfix, strongSwan, Envoy, and Kubernetes Ingress
annotations. Each is another grammar; the three that landed are the ones the
demo turns on.

File matching is an explicit allowlist rather than "any `.conf`": walking a repo
and parsing everything ending in `.conf` as nginx would produce confident
nonsense.

## Consequences

* **R2, R3 and R4 now run live.** The end-to-end tests take the declared side
  from the real parser at its real config line — `nginx.conf:18` appears in the
  drift evidence — rather than from a hand-built component.
* R1 also improves: its declared side is now parsed, so the demo path is
  config → shipped image → drift with no fixtures in the middle.
* 100% recall and 100% precision on 11 planted findings across three formats,
  with zero false positives on the decoys.
* **The certificate finding is a reference, not a parse.** `ssl_certificate`
  records the path with `resolved: false`; reading the certificate is the
  container scanner's job and the file may not be in this tree at all.
* sshd's *first* occurrence of a keyword wins, because that is what sshd itself
  does. Reporting the last would describe a configuration the daemon is not
  running.

## Alternatives considered

* **Semgrep generic mode.** One engine for both declared scanners, and it
  cannot see block structure — which is the only thing that makes a config
  finding attributable to an endpoint.
* **Full nginx/Apache grammars (e.g. crossplane).** Correct for every edge case,
  a dependency in the offline scan path, and far more than "which block is this
  directive in" requires.
* **Treating sshd as endpoint `:22`.** Would let the correlator join an SSH
  policy against a TLS handshake. The scope marker exists to make that
  impossible rather than merely unlikely.
* **Parsing every `.conf` found.** More coverage, and it would report a
  Postfix or systemd file's contents as nginx directives with total confidence.
