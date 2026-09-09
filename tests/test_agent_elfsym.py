"""Independent ELF symbol resolution, so the agent can check bcc's homework.

The first attach proof attached cleanly and captured nothing, and the leading
theory was that bcc resolved ``SSL_do_handshake`` to the wrong address because
the symbol is versioned. Rather than argue about it, the agent now resolves the
symbol itself and prints the offset, so a human can see a real number and
compare (ADR-0009).

Root-free: this is ELF parsing, not kernel work.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.elfsym import (
    ElfError,
    dynamic_symbols,
    resolve_dynamic_symbol,
)

REAL_LIBSSL = Path("/usr/lib/x86_64-linux-gnu/libssl.so.3")
REAL_LIBC = Path("/lib/x86_64-linux-gnu/libc.so.6")


def _require(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"{path} is not present on this host")
    return path


def test_a_known_symbol_resolves_to_a_non_zero_offset() -> None:
    """The headline check: a real symbol in a real library, not zero.

    Zero is the failure the diagnostic exists to catch -- a uprobe attached at
    offset 0 sits on the ELF header, which nothing ever executes, and looks
    exactly like a successful attach that never fires.
    """
    offset = resolve_dynamic_symbol(_require(REAL_LIBSSL), "SSL_do_handshake")

    assert offset is not None
    assert offset > 0


def test_versioned_symbols_are_matched_by_their_bare_name() -> None:
    """libssl exports ``SSL_do_handshake@@OPENSSL_3.0.0``, and callers ask for
    ``SSL_do_handshake``."""
    symbols = dynamic_symbols(_require(REAL_LIBSSL))

    assert "SSL_do_handshake" in symbols
    assert not any("@" in name for name in symbols)


def test_several_libssl_symbols_resolve_and_differ() -> None:
    libssl = _require(REAL_LIBSSL)
    offsets = {
        name: resolve_dynamic_symbol(libssl, name)
        for name in ("SSL_do_handshake", "SSL_read", "SSL_write", "SSL_new")
    }

    assert all(o is not None and o > 0 for o in offsets.values())
    assert len(set(offsets.values())) == len(offsets), "distinct functions collided"


def test_an_absent_symbol_resolves_to_none() -> None:
    assert resolve_dynamic_symbol(_require(REAL_LIBSSL), "not_a_real_symbol") is None


def test_a_symbol_from_another_library_is_not_found() -> None:
    assert resolve_dynamic_symbol(_require(REAL_LIBC), "SSL_do_handshake") is None


def test_libc_symbols_resolve_too() -> None:
    """Not libssl-specific: the parser reads ELF, not OpenSSL."""
    assert resolve_dynamic_symbol(_require(REAL_LIBC), "malloc") not in (None, 0)


def test_a_non_elf_file_is_reported_clearly(tmp_path: Path) -> None:
    junk = tmp_path / "not-an-elf"
    junk.write_bytes(b"this is not an ELF file at all")

    with pytest.raises(ElfError, match="ELF"):
        dynamic_symbols(junk)


def test_a_truncated_elf_does_not_crash(tmp_path: Path) -> None:
    """A short read must be an error with a sentence, not an IndexError."""
    truncated = tmp_path / "short.so"
    truncated.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 20)

    with pytest.raises(ElfError):
        dynamic_symbols(truncated)


def test_a_missing_file_is_reported_clearly(tmp_path: Path) -> None:
    with pytest.raises(ElfError, match="no such"):
        dynamic_symbols(tmp_path / "nope.so")


def test_a_32_bit_elf_is_refused_rather_than_misparsed(tmp_path: Path) -> None:
    """ELFCLASS32 has a different header layout; parsing it as 64-bit would
    yield a plausible-looking wrong offset, which is worse than an error."""
    header = bytearray(b"\x7fELF\x01\x01\x01" + b"\x00" * 57)
    elf32 = tmp_path / "thirty-two.so"
    elf32.write_bytes(bytes(header))

    with pytest.raises(ElfError, match="64-bit"):
        dynamic_symbols(elf32)


def test_resolution_agrees_with_objdump() -> None:
    """Cross-check against the toolchain, so the parser cannot be quietly wrong."""
    import re
    import shutil
    import subprocess

    libssl = _require(REAL_LIBSSL)
    objdump = shutil.which("objdump")
    if objdump is None:
        pytest.skip("objdump is not available")

    result = subprocess.run(  # noqa: S603
        [objdump, "-T", str(libssl)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("objdump failed")

    expected: dict[str, int] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^([0-9a-f]+)\s.*\s(\S+?)(?:@@?\S+)?$", line.strip())
        if match:
            expected.setdefault(match.group(2), int(match.group(1), 16))

    for name in ("SSL_do_handshake", "SSL_read", "SSL_new"):
        if name in expected:
            assert resolve_dynamic_symbol(libssl, name) == expected[name], name
