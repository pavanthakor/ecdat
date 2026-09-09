#!/usr/bin/env bash
#
# The Pillar 2 end-to-end proof: a real TLS handshake observed by an eBPF
# uprobe becomes an observed component in a stored CBOM.
#
#     sudo scripts/prove_pillar2.sh
#
# ONE COMMAND, no terminal ordering. ADR-0009's lesson was that a proof
# requiring a human to perform three steps in the right order cannot
# distinguish "it does not work" from "we ran it wrong" -- so this sequences
# itself:
#
#   1. (root)      agent --self-test --spool  : attach probes, cause a
#                                               handshake, write JSON lines
#   2. (unprivileged) ecdat scan --kind spool : ingest them into the store
#   3. (unprivileged) show the observed component in the CBOM
#
# The agent must be root; the scan must NOT be. The agent chowns the spool to
# the invoking user so step 2 can move files into consumed/ (ADR-0010).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPOOL="${ECDAT_SPOOL_DIR:-/tmp/ecdat-spool}"
VENV="$REPO/.venv/bin/python"

cd "$REPO"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This proof needs root for step 1 (attaching eBPF probes)." >&2
  echo "  Re-run:  sudo scripts/prove_pillar2.sh" >&2
  exit 2
fi

if [[ -z "${SUDO_UID:-}" ]]; then
  echo "warning: SUDO_UID is unset, so the spool will stay root-owned and" >&2
  echo "         step 2 may not be able to move files into consumed/." >&2
fi

echo "=============================================================="
echo " STEP 1  (root)  agent: attach, handshake, spool"
echo "=============================================================="
rm -rf "$SPOOL"
python3 -m agent.agent --self-test --controls --spool "$SPOOL"

echo
echo "spool contents:"
find "$SPOOL" -maxdepth 1 -type f -printf '    %f  (%s bytes)\n' | sort

echo
echo "=============================================================="
echo " STEP 2  (unprivileged)  scan the spool"
echo "=============================================================="
# Drop back to the invoking user: the scan path must never need root.
RUN_AS=("${VENV}")
if [[ -n "${SUDO_USER:-}" ]]; then
  RUN_AS=(sudo -u "${SUDO_USER}" "${VENV}")
fi

"${RUN_AS[@]}" cli.py scan "$SPOOL" --kind spool --scanner runtime-spool \
  --system quantumbank --exposure internet -o /tmp/ecdat-observed.cbom.json

echo
echo "=============================================================="
echo " STEP 3  the observed component in the CBOM"
echo "=============================================================="
"${RUN_AS[@]}" - <<'PYEOF'
import json
from pathlib import Path

document = json.loads(Path("/tmp/ecdat-observed.cbom.json").read_text())
components = document.get("components", [])
if not components:
    print("  FAIL: the CBOM has no components")
    raise SystemExit(1)

observed = 0
for component in components:
    properties = {}
    for prop in component["properties"]:
        properties.setdefault(prop["name"], []).append(prop["value"])
    view = properties.get("ecdat:view", ["?"])[0]
    if view != "observed":
        continue
    observed += 1
    occurrence = component["evidence"]["occurrences"][0]
    def param(name, default="-"):
        return properties.get(f"ecdat:param:{name}", [default])[0]

    print(f"  name      : {component['name']}")
    print(f"  view      : {view}")
    print(f"  version   : {param('version')}")
    print(f"  cipher    : {param('cipher_suite')}")
    print(f"  group     : {param('group')}"
          + ("   [HYBRID PQ]" if param("hybrid") == "True" else ""))
    print(f"  enrichment: {param('enrichment')}"
          + (f"  ({param('enrichment_reason')})"
             if param("enrichment") != "full" else ""))
    print(f"  locator   : {occurrence['location']}")
    print(f"  band      : {properties.get('ecdat:band', ['-'])[0]}"
          f"  score {properties.get('ecdat:score', ['-'])[0]}")
    print()

print(f"  {observed} observed component(s) in the stored CBOM")
enriched = [
    c for c in components
    for p in c["properties"]
    if p["name"] == "ecdat:param:enrichment" and p["value"] == "full"
]
print(f"  {len(enriched)} fully enriched (real negotiated version+cipher+group)")
print()
print("  PASS: a real TLS handshake reached the store as an observed component."
      if observed else "  FAIL: no observed component reached the store.")
raise SystemExit(0 if observed else 1)
PYEOF

echo
echo "spool after ingest (records moved to consumed/, not deleted):"
find "$SPOOL" -type f | sed 's/^/    /'
