# ECDAT developer entry points. The human runs privileged commands (docker,
# tcpdump, eBPF attach) personally; nothing here needs root.

PY ?= .venv/bin/python

.PHONY: help install lint format typecheck test validate golden check

help:
	@echo "install    install runtime + dev dependencies into .venv"
	@echo "lint       ruff check + format check"
	@echo "format     ruff format (rewrites files)"
	@echo "typecheck  mypy over core/ and tests/"
	@echo "test       full pytest run"
	@echo "validate   fail if any produced CBOM does not validate against"
	@echo "           the official CycloneDX 1.6 JSON schema"
	@echo "golden     regenerate tests/golden/*.cbom.json (review the diff!)"
	@echo "check      lint + typecheck + test + validate  (what CI runs)"

install:
	$(PY) -m pip install -r requirements-dev.txt

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff format .

typecheck:
	$(PY) -m mypy core
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

check: lint typecheck test validate
