# ECDAT — developer onboarding

From a fresh Ubuntu machine to a working dev environment, in one command.

```bash
git clone git@github.com:pavanthakor/ecdat.git
cd ecdat
make setup          # installs everything
#   ... log out and back in (docker group) ...
make verify         # health check
make images         # pull the container test images
make test
```

> **`make setup` has not yet been run on a truly fresh machine.** It is
> idempotent and its dry run (`scripts/setup.sh --check`) is verified, but the
> only thing that proves a setup script is a teammate running it on a clean
> install. If it fails for you, that is a bug worth reporting — paste the step
> and the remedy it printed. Tracked in PUNCHLIST.

---

## Prerequisites

| | |
|---|---|
| **OS** | Ubuntu 24.04 or newer (26.04 is what the project is developed on) |
| **Disk** | ~20 GB (semgrep, Docker images, and the venv are the bulk) |
| **Kernel** | needs BTF at `/sys/kernel/btf/vmlinux` — **only for the eBPF agent** |

### The WSL2 caveat, up front

**WSL2 does not work for the eBPF agent.** No BTF, no working uprobes. Everything
else — scanners, policy, correlator, API, dashboard, the KPI harness — runs fine
on WSL2.

If you are touching the agent, you need bare-metal Ubuntu or a full VM
(VirtualBox/KVM/Multipass). `make setup` detects WSL2 and says so rather than
letting you discover it three hours later.

### What each teammate actually needs

| Working on | Needs BTF / bcc? | Needs Docker? |
|---|---|---|
| Dashboard (React/Vite) | no | no |
| Scanners, policy, correlator | no | yes (container tests) |
| The eBPF agent | **yes** | no |
| Running the full KPI | no | yes |

Nobody is blocked by lacking a BTF kernel unless they are working on the agent.
`make verify` reports those as `SKIP`, not `FAIL`, for exactly this reason.

---

## Clone over SSH, not HTTPS

```bash
ssh-keygen -t ed25519 -C "you@example.com"     # if you have no key yet
cat ~/.ssh/id_ed25519.pub                      # paste this into GitHub
```

Add it at **GitHub → Settings → SSH and GPG keys → New SSH key**
([the official steps](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)).
Then:

```bash
ssh -T git@github.com          # should greet you by username
git clone git@github.com:pavanthakor/ecdat.git
```

HTTPS with a personal access token also works, but the token expires and the
whole team hits it on the same day. SSH keys do not.

---

## Setup

```bash
make setup                     # or: scripts/setup.sh
scripts/setup.sh --check       # print the plan, change nothing
```

It is **idempotent** — safe to re-run, and every step is a no-op when already
satisfied. It is **non-destructive** — it never overwrites an existing `.venv`
or `.env`. Every failure prints a remedy rather than a traceback.

What it installs and why:

| | why |
|---|---|
| `build-essential`, `linux-headers-$(uname -r)` | bcc compiles the BPF program against your running kernel's headers |
| `bpfcc-tools`, `python3-bpfcc` | the eBPF agent — installs into **system** python3 |
| Docker CE + compose plugin | container-scanner test images |
| Node 20 | the dashboard |
| `semgrep` (via pipx) | the source scanner's engine |
| `tshark` | network handshake capture (a later slice) |
| `skopeo` | fetching OCI images without a daemon |
| `binutils` | `nm`/`objdump` — the agent checks libssl symbols with these |
| `.venv` + `requirements-dev.txt` | everything else |

**After setup, log out and back in.** Adding you to the `docker` group does not
affect a shell that is already running. `newgrp docker` works for the current
shell if you would rather not log out.

---

## The two Pythons

This is the single most confusing thing about the repo, so it is worth reading
once rather than debugging twice.

| | interpreter | has | runs |
|---|---|---|---|
| **The app** | `.venv/bin/python` | pydantic, cyclonedx, semgrep, fastapi… | scanners, policy, correlator, API, CLI, tests, KPI |
| **The agent** | system `/usr/bin/python3` | **bcc** | the eBPF probe, as root |

`bcc` is a **distro package**. `apt` installs it into the system interpreter and
it cannot be pip-installed into a venv. The agent therefore runs on the system
python — and, because it needs root anyway, under `sudo`:

```bash
sudo python3 -m agent.agent --self-test          # correct
.venv/bin/python -m agent.agent --self-test      # WRONG: no bcc
python3 agent/agent.py --self-test               # WRONG: see below
```

**Run it as `-m agent.agent` from the repo root.** Running `agent/agent.py`
directly puts the `agent/` *directory* on `sys.path` instead of its parent, so
the package's own `from agent.probe_ssl import ...` cannot resolve.

**`--findings` additionally needs pydantic on the system python:**

```bash
sudo python3 -m pip install --break-system-packages pydantic
```

Plain `--self-test` and `--spool` need **only bcc** — the Finding mapping is
imported lazily precisely so the attach proof does not depend on a second
environment being right (ADR-0009).

---

## Running things

```bash
make test           # the full suite (~570 tests, ~80s)
make check          # what CI runs: lint + typecheck + test + validate
make kpi            # score ECDAT against the QuantumBank seeded repo
make verify         # health-check this machine, any time
```

Docker-marked tests are **opt-in**, because they shell out to `docker save` and
CLAUDE.md reserves docker for a human to run deliberately:

```bash
make images                             # pull the images first
ECDAT_RUN_DOCKER_TESTS=1 make test
```

### The eBPF proof

```bash
sudo scripts/prove_pillar2.sh           # or: make prove-pillar2
```

One command, no terminal ordering: it attaches the probes as root, causes a TLS
handshake in a child process, drops back to your user to scan the spool, and
prints the observed component. See `agent/README.md`.

---

## Troubleshooting

Every one of these is a snag that actually happened.

| Symptom | Cause & fix |
|---|---|
| `docker: permission denied` / `Cannot connect to the Docker daemon` | You were added to the `docker` group but have not re-logged in. Log out and back in, or `newgrp docker`. |
| `semgrep: command not found` after setup | pipx put it in `~/.local/bin`, which is not on this shell's PATH. `pipx ensurepath`, then open a new shell. |
| `no /sys/kernel/btf/vmlinux` | Your kernel has no BTF. **Only the eBPF agent needs it** — everything else works. Use bare-metal Ubuntu or a VM for agent work. |
| `ModuleNotFoundError: No module named 'agent'` | You ran `python3 agent/agent.py`. Use `python3 -m agent.agent` **from the repo root**. |
| `ModuleNotFoundError: No module named 'bcc'` | You ran the agent with `.venv/bin/python`. Use the system `sudo python3`. |
| `ModuleNotFoundError: No module named 'pydantic'` under sudo | Only `--findings` needs it: `sudo python3 -m pip install --break-system-packages pydantic`. Or drop `--findings`. |
| `use of undeclared identifier 'TASK_COMM_LEN'` | Old checkout. Pull latest — fixed in ADR-0009. |
| `Host key for github.com has changed` | GitHub rotated a key, or you are behind a proxy. `ssh-keygen -R github.com`, then `ssh -T git@github.com` and verify the fingerprint against GitHub's published list. |
| Tests fail with `no such file: knowledge/...` | You are not in the repo root. All paths are repo-relative. |
| `docker save` tests skip | That is correct — they are opt-in. `ECDAT_RUN_DOCKER_TESTS=1 make test`. |
| A scan writes `ecdat.db` into the repo | Expected: that is the default store path. It is gitignored. Set `ECDAT_DB` to move it. |

If `make verify` passes and something still does not work, that is worth a bug
report — the health check is meant to catch exactly this class of problem.
