# ECDAT developer entry points. The human runs privileged commands (docker,
# tcpdump, eBPF attach) personally; nothing here needs root.

PY ?= .venv/bin/python
SHELLCHECK ?= .venv/bin/shellcheck

.PHONY: help install lint format typecheck test validate golden serve check

help:
	@echo "ECDAT -- make targets"
	@echo ""
	@echo "  SETUP (new machine -- see docs/ONBOARDING.md)"
	@echo "    setup       install everything: apt, docker, node, semgrep, .venv"
	@echo "    verify      read-only health check of this machine"
	@echo "    images      docker pull the container test images"
	@echo "    install     (re)install Python deps into an existing .venv"
	@echo ""
	@echo "  DEVELOP"
	@echo "    lint        ruff check + format check + shellcheck"
	@echo "    format      ruff format (rewrites files)"
	@echo "    typecheck   mypy over the source packages and tests"
	@echo "    test        full pytest run"
	@echo "    check       lint + typecheck + test + validate (what CI runs)"
	@echo ""
	@echo "  PROVE"
	@echo "    validate    fail if any produced CBOM is not valid CycloneDX 1.6"
	@echo "    kpi         score ECDAT against the QuantumBank seeded repo"
	@echo "    prove-pillar2  eBPF handshake -> spool -> observed CBOM (needs sudo)"
	@echo "    golden      regenerate tests/golden/*.cbom.json (review the diff!)"
	@echo "    sign-packs  re-sign policy packs with the committed DEV key"
	@echo ""
	@echo "  RUN"
	@echo "    serve       run the API on http://127.0.0.1:8000"
	@echo ""

install:
	$(PY) -m pip install -r requirements-dev.txt

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	@# shellcheck ships as a wheel (shellcheck-py), so the binary lands in the
	@# venv and `make lint` needs no apt package.
	$(SHELLCHECK) -x scripts/*.sh

format:
	$(PY) -m ruff format .

typecheck:
	$(PY) -m mypy core api scanners policy correlate agent cli.py
	$(PY) -m mypy tests

test:
	$(PY) -m pytest

# The schema gate. Every test marked `validation` runs a CBOM through the
# official CycloneDX 1.6 schema shipped with cyclonedx-python-lib, offline.
# A non-zero exit here means a document ECDAT produced is not a valid CBOM.
validate:
	$(PY) -m pytest -m validation

golden:
	$(PY) -m tests.golden_gen

serve:
	$(PY) -m uvicorn api.app:app --reload --host 127.0.0.1 --port 8000

check: lint typecheck test validate

# Re-sign every policy pack with the DEV key after editing one. The dev keypair
# is committed and is NOT a production key -- see policy/sign.py and ADR-0007.
sign-packs:
	$(PY) -m policy.sign

# The Pillar 2 end-to-end proof: a real TLS handshake -> eBPF uprobe -> spool
# -> scan -> observed component in a stored CBOM. Needs root for the agent half
# only; the scan half drops back to the invoking user. See ADR-0010.
prove-pillar2:
	sudo scripts/prove_pillar2.sh

# The KPI harness: scan QuantumBank, score against its answer key, and print
# the misses and known gaps alongside the numbers. See ADR-0014.
kpi:
	ECDAT_DB=$${ECDAT_DB:-.ecdat-kpi.db} $(PY) -m kpi.harness

setup:
	scripts/setup.sh

verify:
	scripts/verify.sh

images:
	scripts/pull-images.sh
