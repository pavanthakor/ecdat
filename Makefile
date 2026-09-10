# ECDAT developer entry points. The human runs privileged commands (docker,
# tcpdump, eBPF attach) personally; nothing here needs root.

PY ?= .venv/bin/python
SHELLCHECK ?= .venv/bin/shellcheck

.PHONY: help install lint format typecheck test validate golden serve check \
        web web-dev web-test scans reports

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
	@echo "  CONSOLE (web/)"
	@echo "    web         build the dashboard into web/dist (run before a demo)"
	@echo "    web-dev     vite dev server on :5173, proxying /api to :8000"
	@echo "    web-test    vitest data-logic suite"
	@echo ""
	@echo "  REPORT"
	@echo "    reports SCAN=<id>   executive + technical + coverage PDFs -> reports-out/"
	@echo "    scans       list the scans in the current database (and name the file)"
	@echo ""
	@echo "  RUN"
	@echo "    serve       run the API + built console on http://127.0.0.1:8000"
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

# Which database am I on? The one question worth being able to answer in one
# command before a demo (ADR-0020).
scans:
	$(PY) cli.py scans

# All three reports for one scan. SCAN defaults to the newest row.
#
# The default is resolved INSIDE the recipe, not with `$(shell ...)`: make
# expands that at parse time, so a `$(shell)` here would open the database on
# `make -n reports` -- a dry run that writes a file is the kind of surprise
# that leaves a stray ecdat.db in a working tree.
SCAN ?=

reports:
	@scan="$(SCAN)"; \
	if [ -z "$$scan" ]; then \
		scan=$$($(PY) -c "from core import store; rows=store.list_scans(); print(rows[0].id if rows else '')"); \
	fi; \
	if [ -z "$$scan" ]; then \
		echo "no scans in $$($(PY) -c 'from core import store; print(store.database_location())')"; \
		echo "run a scan first, or pass SCAN=<id>"; \
		exit 2; \
	fi; \
	for kind in executive technical coverage; do \
		$(PY) cli.py report "$$scan" --kind $$kind || exit 1; \
	done

# ---------------------------------------------------------------------------
# The console. `make web` is the only step that needs Node; once it has run,
# `make serve` hands out pre-built static files and the demo machine needs no
# npm at all (ADR-0018).
# ---------------------------------------------------------------------------
NPM ?= npm

web:
	$(NPM) --prefix web install --no-audit --no-fund
	$(NPM) --prefix web run build

web-dev:
	$(NPM) --prefix web run dev

web-test:
	$(NPM) --prefix web run test

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
