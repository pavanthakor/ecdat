"""Pillar 3's fix half: verified diffs, never applied (ADR-0015).

Recommendations tell an operator *what* to do; this package produces the
*patch*, and refuses to hand one over until a re-scan of a sandbox copy agrees
the finding is gone and nothing Critical arrived with it.

Three rules, all enforced in :mod:`correlate.fixit.engine`:

* **Never auto-apply.** ECDAT emits a diff. A human applies it.
* **Verify by re-scan, not by trusting the template.** The producing scanner
  re-reads a patched copy; the template's own opinion of its patch is not
  evidence.
* **Read-only on the real target.** Everything happens in a temporary
  directory, and ``tests/test_fixit.py`` hashes the target tree either side to
  prove it.
"""

from __future__ import annotations

from correlate.fixit.apply import FIX_PROPERTIES, apply_fixes, propose_fixes
from correlate.fixit.engine import FixResult, propose_fix
from correlate.fixit.template import FixTemplate, Precondition, Site
from correlate.fixit.templates import DEFAULT_TEMPLATES

__all__ = [
    "DEFAULT_TEMPLATES",
    "FIX_PROPERTIES",
    "FixResult",
    "FixTemplate",
    "Precondition",
    "Site",
    "apply_fixes",
    "propose_fix",
    "propose_fixes",
]
