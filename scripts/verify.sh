#!/usr/bin/env bash
#
# ECDAT health check. Read-only: it inspects and reports, and changes nothing.
#
#     make verify
#
# Run it any time something stops working. Every FAIL prints the remedy, and a
# SKIP means "this capability is absent but you may not need it" -- a teammate
# doing dashboard work has no use for BTF or bcc.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m'; c_dim=$'\033[2m'
[[ -t 1 ]] || { c_reset=""; c_bold=""; c_ok=""; c_warn=""; c_err=""; c_dim=""; }

FAILED=0
REMEDIES=()

row() {
  # row <status> <check> <detail>
  local status="$1" check="$2" detail="$3" colour
  case "$status" in
    PASS) colour="$c_ok" ;;
    FAIL) colour="$c_err"; FAILED=$((FAILED + 1)) ;;
    *)    colour="$c_warn" ;;
  esac
  printf '  %s%-4s%s  %-30s %s%s%s\n' \
    "$colour" "$status" "$c_reset" "$check" "$c_dim" "$detail" "$c_reset"
}

remedy() { REMEDIES+=("$1"); }

have() { command -v "$1" >/dev/null 2>&1; }

printf '\n%s%s%s\n' "$c_bold" "ECDAT environment check" "$c_reset"
printf '%s\n' "-------------------------------------------------------------------"

# --- the machine ------------------------------------------------------------
row PASS "kernel" "$(uname -r)"

if grep -qi microsoft /proc/version 2>/dev/null; then
  row SKIP "not WSL2" "WSL2 detected -- the eBPF agent cannot run here"
  remedy "WSL2: scanner/policy/UI work is fine. For the agent use bare-metal Ubuntu or a full VM."
else
  row PASS "not WSL2" "native kernel"
fi

if [[ -r /sys/kernel/btf/vmlinux ]]; then
  row PASS "BTF (eBPF agent)" "/sys/kernel/btf/vmlinux"
else
  row SKIP "BTF (eBPF agent)" "absent -- agent unavailable, everything else fine"
  remedy "BTF: needs a kernel built with CONFIG_DEBUG_INFO_BTF=y. Only the eBPF agent needs it."
fi

# --- docker -----------------------------------------------------------------
if ! have docker; then
  row FAIL "docker installed" "not on PATH"
  remedy "docker: run 'make setup', or install Docker CE by hand."
elif docker info >/dev/null 2>&1; then
  row PASS "docker (no sudo)" "$(docker --version | cut -d, -f1)"
else
  row FAIL "docker (no sudo)" "installed, but this user cannot talk to the daemon"
  remedy "docker: you are probably not in the docker group yet. Log out and back in, or run 'newgrp docker'."
fi

# --- the test images --------------------------------------------------------
if have docker && docker info >/dev/null 2>&1; then
  for image in ubuntu:22.04 alpine:3.22; do
    if docker image inspect "$image" >/dev/null 2>&1; then
      row PASS "image $image" "present"
    else
      row SKIP "image $image" "absent -- docker-marked tests will skip"
      remedy "images: run 'make images' to pull the container test images."
    fi
  done
fi

# --- semgrep ----------------------------------------------------------------
if have semgrep; then
  row PASS "semgrep on PATH" "$(semgrep --version 2>/dev/null)"
else
  row FAIL "semgrep on PATH" "not found"
  remedy "semgrep: 'pipx install semgrep && pipx ensurepath', then open a new shell."
fi

# --- the venv ---------------------------------------------------------------
VENV_PY="$REPO/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  row FAIL "venv exists" ".venv/bin/python missing"
  remedy "venv: run 'make setup'."
else
  row PASS "venv exists" "$("$VENV_PY" --version 2>&1)"
  if "$VENV_PY" -c "import pydantic, cyclonedx, cryptography, yaml, fastapi, sqlalchemy" 2>/dev/null; then
    row PASS "venv imports" "pydantic, cyclonedx, cryptography, yaml, fastapi, sqlalchemy"
  else
    row FAIL "venv imports" "a required package is missing"
    remedy "venv: '.venv/bin/python -m pip install -r requirements-dev.txt'."
  fi
fi

# --- bcc on SYSTEM python ---------------------------------------------------
# Deliberately checked against python3, NOT the venv: the agent runs on the
# system interpreter because that is where the distro installs bcc.
if python3 -c "import bcc" 2>/dev/null; then
  row PASS "bcc (system python3)" "$(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null)"
else
  row SKIP "bcc (system python3)" "absent -- eBPF agent unavailable"
  remedy "bcc: 'sudo apt install python3-bpfcc bpfcc-tools'. Only the agent needs it."
fi

if python3 -c "import pydantic" 2>/dev/null; then
  row PASS "pydantic (system)" "agent --findings will work"
else
  row SKIP "pydantic (system)" "absent -- 'agent --self-test' still fine"
  remedy "agent --findings: 'sudo python3 -m pip install --break-system-packages pydantic'. Plain --self-test does NOT need it."
fi

# --- tooling ----------------------------------------------------------------
for tool in git make jq nm; do
  if have "$tool"; then
    row PASS "$tool" "present"
  else
    row FAIL "$tool" "not on PATH"
    remedy "$tool: run 'make setup'."
  fi
done

printf '%s\n' "-------------------------------------------------------------------"
if (( FAILED )); then
  printf '%s%d check(s) FAILED.%s\n' "$c_err" "$FAILED" "$c_reset"
else
  printf '%sAll required checks passed.%s\n' "$c_ok" "$c_reset"
fi

if (( ${#REMEDIES[@]} )); then
  printf '\n%sNotes:%s\n' "$c_bold" "$c_reset"
  printf '  - %s\n' "${REMEDIES[@]}"
fi
printf '\n'

exit $(( FAILED > 0 ))
