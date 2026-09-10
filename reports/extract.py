"""Pull the text back out of a PDF, for tests.

Not a general PDF reader: it decompresses the content streams a report writes
and collects the string literals from `Tj`/`TJ` operators. That is enough to
assert a number, a citation or a caveat is on the page, which is the whole
point -- "it did not crash" is not an assertion about a report.

Kept in the package rather than in the test file because `reports/` is the only
thing that knows how the PDFs are written.
"""

from __future__ import annotations

import re
import zlib

__all__ = ["extract_text"]

_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_SHOW = re.compile(rb"\((?:\\.|[^\\()])*\)\s*Tj|\[(?:[^\]\\]|\\.)*\]\s*TJ", re.DOTALL)
_LITERAL = re.compile(rb"\((?:\\.|[^\\()])*\)", re.DOTALL)


def _unescape(literal: bytes) -> str:
    body = literal[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char == 0x5C and index + 1 < len(body):  # backslash
            nxt = body[index + 1]
            mapped = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}.get(nxt)
            if mapped is not None:
                out.append(mapped)
                index += 2
                continue
            if 0x30 <= nxt <= 0x37:  # octal
                digits = body[index + 1 : index + 4]
                octal = bytes(d for d in digits if 0x30 <= d <= 0x37)
                out.append(int(octal.decode("ascii"), 8) & 0xFF)
                index += 1 + len(octal)
                continue
            out.append(nxt)
            index += 2
            continue
        out.append(char)
        index += 1
    return out.decode("latin-1")


def extract_text(payload: bytes) -> str:
    """Every string a report drew, in page order."""
    pieces: list[str] = []
    for raw in _STREAM.findall(payload):
        try:
            content = zlib.decompress(raw)
        except zlib.error:
            content = raw
        for show in _SHOW.findall(content):
            for literal in _LITERAL.findall(show):
                pieces.append(_unescape(literal))
            pieces.append(" ")
    return "".join(pieces)
