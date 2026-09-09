# ECDAT developer entry points. The human runs privileged commands (docker,
# tcpdump, eBPF attach) personally; nothing here needs root.

PY ?= .venv/bin/python

.PHONY: help install lint format typecheck test validate golden serve check

help:
	@echo "install    install runtime + dev dependencies into .venv"
	@echo "lint       ruff check + format check"
	@echo "format     ruff format (rewrites files)"
	@echo "typecheck  mypy over core/, api/, scanners/, cli.py and tests/"
	@echo "test       full pytest run"
	@echo "validate   fail if any produced CBOM does not validate against"
	@echo "           the official CycloneDX 1.6 JSON schema"
	@echo "golden     regenerate tests/golden/*.cbom.json (review the diff!)"
	@echo "check      lint + typecheck + test + validate  (what CI runs)"
	@echo "sign-packs re-sign policy packs with the committed DEV key"
	@echo "prove-pillar2  end-to-end: eBPF handshake -> spool -> observed CBOM (sudo)"
	@echo "serve      run the API on http://127.0.0.1:8000"

install:
	$(PY) -m pip install -r requirements-dev.txt

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

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
