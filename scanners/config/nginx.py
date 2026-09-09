"""nginx configuration: a brace grammar, parsed for its ``server {}`` blocks.

The endpoint is the whole point. ``ssl_ecdh_curve X25519MLKEM768`` inside
``server { listen 443; }`` is a fact about *that* endpoint and about no other,
and a parser that attributed it to the file would silently ruin the
correlator's join while every other test still passed (ADR-0013).

Deliberately a small brace-depth scanner rather than a full nginx grammar: this
needs to know which block a directive is in and nothing else. Comments are
stripped before anything is matched, and a directive outside an ssl-bearing
``server`` block is not reported -- a commented-out or contextless line
reported as live configuration is a finding an operator will chase and find
nothing behind.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

__all__ = ["ServerBlock", "parse_nginx"]

#: Directives worth reading. Anything else in a server block is ignored.
_TLS_DIRECTIVES = frozenset(
    {
        "ssl_protocols",
        "ssl_ciphers",
        "ssl_ecdh_curve",
        "ssl_certificate",
        "ssl_certificate_key",
        "ssl_conf_command",
    }
)

_BLOCK_START = re.compile(r"^\s*(\w+)([^{;]*)\{\s*$")
_DIRECTIVE = re.compile(r"^\s*(\w+)\s+([^;]+);")


@dataclass
class ServerBlock:
    """One ``server {}`` and the TLS directives inside it."""

    listen_ports: list[str] = field(default_factory=list)
    server_names: list[str] = field(default_factory=list)
    #: directive -> (value, 1-based line number)
    directives: dict[str, tuple[str, int]] = field(default_factory=dict)
    line: int = 0

    @property
    def is_tls(self) -> bool:
        """Whether this block terminates TLS.

        Either a ``listen ... ssl`` or any ``ssl_*`` directive counts. A plain
        HTTP block with a hostname that merely mentions "ssl" does not.
        """
        return bool(self.directives) or any(
            "ssl" in port.split() for port in self.listen_ports
        )

    def endpoint(self) -> str:
        """``host:port`` -- the key the observed view is joined on.

        The first ``server_name`` wins when several are listed, and an absent
        one yields a bare ``:port``, which is what an unnamed default server
        really is.
        """
        port = ""
        for listen in self.listen_ports:
            first = listen.split()[0] if listen.split() else ""
            port = first.rpartition(":")[2] or first
            if port:
                break
        host = self.server_names[0] if self.server_names else ""
        return f"{host}:{port}"


def _strip_comment(line: str) -> str:
    """Remove a ``#`` comment.

    Done before ANY matching, so ``# ssl_protocols TLSv1;`` cannot be read as a
    directive -- which is the single most likely false positive in a config
    file, because disabled crypto looks exactly like enabled crypto.
    """
    return line.split("#", 1)[0]


def parse_nginx(text: str) -> Iterator[ServerBlock]:
    """Yield every TLS-terminating ``server {}`` block, in file order."""
    stack: list[str] = []
    current: ServerBlock | None = None

    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue

        opened = _BLOCK_START.match(line)
        if opened:
            name = opened.group(1)
            stack.append(name)
            if name == "server":
                if current is not None and current.is_tls:
                    yield current
                current = ServerBlock(line=number)
            continue

        if line.strip().startswith("}"):
            closing = stack.pop() if stack else ""
            if closing == "server" and current is not None:
                if current.is_tls:
                    yield current
                current = None
            continue

        directive = _DIRECTIVE.match(line)
        if directive is None or current is None or stack[-1:] != ["server"]:
            # Outside a server block, or not a directive at all. A `map` block
            # whose VALUE reads like a cipher list is data, not configuration.
            continue

        name, value = directive.group(1), directive.group(2).strip()
        if name == "listen":
            current.listen_ports.append(value)
        elif name == "server_name":
            current.server_names.extend(value.split())
        elif name in _TLS_DIRECTIVES:
            current.directives[name] = (value, number)

    if current is not None and current.is_tls:
        yield current
