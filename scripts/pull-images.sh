#!/usr/bin/env bash
#
# Pull the container images the tests and the KPI use, so they work offline
# afterwards.
#
#     make images
#
# ECDAT's scan path never pulls anything (ADR-0006: local images only). This is
# a SETUP step, run deliberately and in advance, precisely so that scanning
# stays air-gapped.
set -uo pipefail

# ubuntu:22.04  ships libssl3 3.0.2 -- the pre-ML-KEM library the drift demo
#               turns on (ADR-0006, ADR-0012).
# alpine:3.22   ships libssl3 3.5.7 -- PQC-capable, the contrast case.
# python:3.12-slim, nginx:1.27 -- realistic application bases.
IMAGES=(ubuntu:22.04 alpine:3.22 python:3.12-slim nginx:1.27)

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed. Run 'make setup' first." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Cannot talk to the docker daemon." >&2
  echo "  You are probably not in the docker group yet -- log out and back in," >&2
  echo "  or run 'newgrp docker'." >&2
  exit 1
fi

failed=0
for image in "${IMAGES[@]}"; do
  if docker image inspect "$image" >/dev/null 2>&1; then
    printf '  [ ok ] %s already present\n' "$image"
    continue
  fi
  printf '  [pull] %s\n' "$image"
  if ! docker pull -q "$image" >/dev/null; then
    printf '  [FAIL] %s could not be pulled\n' "$image" >&2
    failed=$((failed + 1))
  fi
done

if (( failed )); then
  echo "" >&2
  echo "$failed image(s) failed. Check network/proxy, then re-run 'make images'." >&2
  exit 1
fi

printf '\nAll test images present. Docker-marked tests can now run with:\n'
printf '    ECDAT_RUN_DOCKER_TESTS=1 make test\n\n'
