"""openssl.cnf: an INI-ish system-wide TLS policy. Global in scope.

Only ``[system_default_sect]`` is read -- the section OpenSSL applies to every
application that does not override it, which is what makes it a system-level
declaration rather than one endpoint's.
"""

from __future__ import annotations

import re

__all__ = ["SYSTEM_DEFAULT_SECTION", "parse_openssl_cnf"]

SYSTEM_DEFAULT_SECTION = "system_default_sect"

#: Keys worth reading, lower-cased.
_KEYS = frozenset(
    {"groups", "cipherstring", "ciphersuites", "minprotocol", "maxprotocol"}
)

_SECTION = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]")
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


def parse_openssl_cnf(text: str) -> dict[str, tuple[str, int]]:
    """``key -> (value, line)`` from ``[system_default_sect]``."""
    section = ""
    found: dict[str, tuple[str, int]] = {}

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0]
        if not line.strip():
            continue

        header = _SECTION.match(line)
        if header:
            section = header.group(1).strip().lower()
            continue
        if section != SYSTEM_DEFAULT_SECTION:
            continue

        assignment = _ASSIGN.match(line)
        if assignment and assignment.group(1).lower() in _KEYS:
            found[assignment.group(1).lower()] = (
                assignment.group(2).strip(),
                number,
            )
    return found
