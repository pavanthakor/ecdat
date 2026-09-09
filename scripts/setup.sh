#!/usr/bin/env bash
#
# ECDAT developer setup. One command, idempotent, safe to re-run.
#
#     make setup              # do it
#     scripts/setup.sh --check   # print the plan, change nothing
#
# Everything this installs was learned by hitting its absence. The comments say
# which part of ECDAT needs what, so a teammate can skip what they do not need
# rather than guess.
#
# NON-DESTRUCTIVE: it never overwrites an existing .venv or .env without asking,
# and every step is a no-op when already satisfied.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK=0
[[ "${1:-}" == "--check" || "${1:-}" == "-n" ]] && CHECK=1

WARNINGS=()
FAILURES=()

# --- output -----------------------------------------------------------------
c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m'; c_dim=$'\033[2m'
[[ -t 1 ]] || { c_reset=""; c_bold=""; c_ok=""; c_warn=""; c_err=""; c_dim=""; }

step()  { printf '\n%s==>%s %s\n' "$c_bold" "$c_reset" "$1"; }
ok()    { printf '    %s[ ok ]%s %s\n' "$c_ok" "$c_reset" "$1"; }
info()  { printf '    %s%s%s\n' "$c_dim" "$1" "$c_reset"; }
warn()  { printf '    %s[warn]%s %s\n' "$c_warn" "$c_reset" "$1"; WARNINGS+=("$1"); }
fail()  { printf '    %s[FAIL]%s %s\n' "$c_err" "$c_reset" "$1"; FAILURES+=("$1"); }
remedy(){ printf '           %sremedy:%s %s\n' "$c_bold" "$c_reset" "$1"; }
plan()  { printf '    %s[plan]%s %s\n' "$c_dim" "$c_reset" "$1"; }

run() {
  # Execute, or print, depending on --check.
  if (( CHECK )); then plan "$*"; return 0; fi
  "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- 0. what are we on? -----------------------------------------------------
step "Checking the machine"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  info "distro: ${PRETTY_NAME:-unknown}"
  if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
    warn "this script installs with apt; ${ID:-this distro} is not Debian-based."
    remedy "Install the equivalents by hand -- see docs/ONBOARDING.md."
  fi
else
  warn "cannot read /etc/os-release; assuming Debian-like."
fi
info "kernel: $(uname -r)"

if grep -qi microsoft /proc/version 2>/dev/null; then
  warn "WSL2 detected. The eBPF agent will NOT work here (no BTF, no uprobes)."
  remedy "Scanner/policy/UI work is fine on WSL2. For the agent, use bare-metal Ubuntu or a full VM."
fi

# BTF is what the eBPF agent needs. Its absence is a WARNING, not a failure:
# a teammate doing dashboard or scanner work has no use for the agent.
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  ok "BTF present at /sys/kernel/btf/vmlinux (eBPF agent supported)"
else
  warn "no /sys/kernel/btf/vmlinux -- the eBPF agent will not run on this kernel."
  remedy "Everything except the agent still works. For the agent: a mainline Ubuntu kernel with CONFIG_DEBUG_INFO_BTF=y."
fi

# --- 1. apt packages --------------------------------------------------------
step "Installing system packages (apt)"

APT_PACKAGES=(
  build-essential git curl jq make
  python3 python3-venv python3-pip pipx
  "linux-headers-$(uname -r)"   # bcc compiles the BPF program against these
  bpfcc-tools python3-bpfcc     # the eBPF agent; installs into SYSTEM python
  tshark                        # network handshake capture (later slice)
  skopeo                        # pulling OCI images without a docker daemon
  binutils                      # nm/objdump, used to check libssl symbols
)

missing=()
for pkg in "${APT_PACKAGES[@]}"; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done

if (( ${#missing[@]} == 0 )); then
  ok "all ${#APT_PACKAGES[@]} apt packages already installed"
else
  info "missing: ${missing[*]}"
  run sudo apt-get update -qq
  if ! run sudo apt-get install -y "${missing[@]}"; then
    fail "apt install failed"
    remedy "Run 'sudo apt-get update && sudo apt-get install ${missing[*]}' and read the error."
  else
    ok "installed ${#missing[@]} package(s)"
  fi
fi

# --- 2. Docker --------------------------------------------------------------
step "Installing Docker CE"

if have docker; then
  ok "docker present: $(docker --version 2>/dev/null || echo unknown)"
else
  info "adding Docker's apt repository"
  run sudo install -m 0755 -d /etc/apt/keyrings
  if (( ! CHECK )); then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME:-noble} stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  else
    plan "curl docker gpg key -> /etc/apt/keyrings/docker.gpg"
    plan "write /etc/apt/sources.list.d/docker.list"
  fi
  run sudo apt-get update -qq
  run sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  ok "docker installed"
fi

if id -nG "$USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  ok "$USER is in the docker group"
else
  run sudo usermod -aG docker "$USER"
  warn "added $USER to the docker group -- YOU MUST LOG OUT AND BACK IN."
  remedy "Log out and in (or run 'newgrp docker'), then 'docker ps' should work without sudo."
fi

# --- 3. Node 20 (dashboard) -------------------------------------------------
step "Installing Node 20 (dashboard)"

if have node && [[ "$(node --version 2>/dev/null | cut -c2- | cut -d. -f1)" -ge 20 ]]; then
  ok "node present: $(node --version)"
else
  if (( CHECK )); then
    plan "curl nodesource setup_20.x | sudo bash -"
    plan "sudo apt-get install -y nodejs"
  else
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null 2>&1
    if sudo apt-get install -y nodejs >/dev/null 2>&1; then
      ok "node installed: $(node --version)"
    else
      fail "node install failed"
      remedy "See https://github.com/nodesource/distributions"
    fi
  fi
fi

# --- 4. semgrep via pipx ----------------------------------------------------
step "Installing semgrep (source scanner engine)"

if have semgrep; then
  ok "semgrep present: $(semgrep --version 2>/dev/null)"
else
  run pipx install semgrep
  run pipx ensurepath
  warn "semgrep installed via pipx; ~/.local/bin may not be on PATH in THIS shell."
  remedy "Run 'pipx ensurepath' then open a new shell, or 'export PATH=\$PATH:~/.local/bin'."
fi

# --- 5. the virtualenv ------------------------------------------------------
step "Creating the Python virtualenv (.venv)"

if [[ -d "$REPO/.venv" ]]; then
  # NON-DESTRUCTIVE: an existing venv may have local state a teammate wants.
  ok ".venv already exists (left untouched)"
  info "to rebuild it: rm -rf .venv && make setup"
else
  run python3 -m venv "$REPO/.venv"
  ok "created .venv"
fi

VENV_PY="$REPO/.venv/bin/python"
if (( CHECK )); then
  plan "$VENV_PY -m pip install -r requirements-dev.txt"
elif [[ -x "$VENV_PY" ]]; then
  info "installing requirements (this takes a minute; semgrep is large)"
  if [[ -f "$REPO/requirements-dev.txt" ]]; then
    "$VENV_PY" -m pip install -q --upgrade pip >/dev/null 2>&1
    if "$VENV_PY" -m pip install -q -r "$REPO/requirements-dev.txt"; then
      ok "installed requirements-dev.txt (includes requirements.txt)"
    else
      fail "pip install failed"
      remedy "Run '$VENV_PY -m pip install -r requirements-dev.txt' and read the error."
    fi
  fi

  # Verify the imports the app actually needs, rather than trusting pip's exit.
  if "$VENV_PY" -c "import pydantic, cyclonedx, cryptography, yaml, fastapi, sqlalchemy" 2>/dev/null; then
    ok "venv imports verified (pydantic, cyclonedx, cryptography, yaml, fastapi, sqlalchemy)"
  else
    fail "the venv cannot import a required package"
    remedy "Delete .venv and re-run: rm -rf .venv && make setup"
  fi
fi

# --- 6. bcc on SYSTEM python ------------------------------------------------
step "Checking bcc on the SYSTEM python (the eBPF agent runs there, not in .venv)"

if python3 -c "import bcc" 2>/dev/null; then
  ok "bcc importable on system python3: $(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null)"
  info "the agent runs as 'sudo python3 -m agent.agent', NOT with .venv/bin/python"
else
  warn "bcc is not importable on system python3 -- the eBPF agent will not run."
  remedy "sudo apt install python3-bpfcc bpfcc-tools"
fi

# --- 7. the test suite ------------------------------------------------------
step "Running the test suite"

if (( CHECK )); then
  plan "$VENV_PY -m pytest -q"
elif [[ -x "$VENV_PY" ]]; then
  if output="$("$VENV_PY" -m pytest -q 2>&1 | tail -3)"; then
    ok "tests passed"
    printf '%s\n' "$output" | sed 's/^/      /'
  else
    fail "tests failed"
    printf '%s\n' "$output" | sed 's/^/      /'
    remedy "Run '$VENV_PY -m pytest' for the full output."
  fi
fi

# --- summary ----------------------------------------------------------------
printf '\n%s%s%s\n' "$c_bold" "========================================" "$c_reset"
if (( CHECK )); then
  printf '%sDRY RUN%s -- nothing was changed. Re-run without --check to apply.\n' \
    "$c_bold" "$c_reset"
fi
if (( ${#FAILURES[@]} )); then
  printf '%s%d step(s) FAILED:%s\n' "$c_err" "${#FAILURES[@]}" "$c_reset"
  printf '  - %s\n' "${FAILURES[@]}"
fi
if (( ${#WARNINGS[@]} )); then
  printf '%s%d warning(s):%s\n' "$c_warn" "${#WARNINGS[@]}" "$c_reset"
  printf '  - %s\n' "${WARNINGS[@]}"
fi
if (( ${#FAILURES[@]} == 0 && ${#WARNINGS[@]} == 0 )); then
  printf '%sSetup complete.%s\n' "$c_ok" "$c_reset"
fi
printf '\nNext:  make verify     health-check this machine\n'
printf   '       make images     pull the container test images\n'
printf   '       make test       run the suite\n'
printf   '       make kpi        score ECDAT against QuantumBank\n\n'

exit $(( ${#FAILURES[@]} > 0 ))
