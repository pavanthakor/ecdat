"""sshd_config: ``Keyword value`` lines, global in scope.

sshd has no per-endpoint block in the sense nginx does -- ``KexAlgorithms``
applies to the daemon, not to a virtual host -- so its findings carry a
system-level scope marker rather than a ``host:port``. See ADR-0013.
"""

from __future__ import annotations

import re

__all__ = ["SSHD_KEYWORDS", "parse_sshd"]

#: keyword -> (canonical algorithm name, primitive). The names are ECDAT's, so
#: an SSH key exchange and a TLS one are distinguishable in the CBOM rather
#: than colliding on a generic "key-agreement".
SSHD_KEYWORDS: dict[str, tuple[str, str]] = {
    "kexalgorithms": ("SSH-KEX", "key-agreement"),
    "ciphers": ("SSH-CIPHERS", "block-cipher"),
    "macs": ("SSH-MACS", "mac"),
    "hostkeyalgorithms": ("SSH-HOSTKEY", "signature"),
}

_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$")


def parse_sshd(text: str) -> list[tuple[str, str, str, int]]:
    """``(algorithm, primitive, value, line)`` for each recognised keyword.

    A later occurrence of a keyword does not override an earlier one here --
    sshd itself takes the FIRST, and reporting the last would describe a
    configuration the daemon is not running.
    """
    found: list[tuple[str, str, str, int]] = []
    seen: set[str] = set()

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0]
        if not line.strip():
            continue
        match = _LINE.match(line)
        if match is None:
            continue

        keyword = match.group(1).lower()
        entry = SSHD_KEYWORDS.get(keyword)
        if entry is None or keyword in seen:
            continue
        seen.add(keyword)
        algorithm, primitive = entry
        found.append((algorithm, primitive, match.group(2).strip(), number))

    return found
