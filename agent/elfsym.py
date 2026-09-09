"""Minimal ELF64 dynamic-symbol reader, so the agent can check bcc's homework.

The first attach proof attached cleanly and captured nothing. The leading theory
was that bcc resolved ``SSL_do_handshake`` to the wrong address because the
symbol is versioned (``SSL_do_handshake@@OPENSSL_3.0.0``). Arguing about that
costs a round trip through a human with sudo; resolving the symbol
independently and printing the number costs nothing, so the agent now does that
every run.

Deliberately dependency-free. The agent runs on the SYSTEM interpreter -- the
one that has bcc and, usually, nothing else -- so this cannot reach for
pyelftools. It reads only what it needs: the section headers, ``.dynsym``, and
its linked string table.

Read-only, obviously: it opens a file and parses bytes.
"""

from __future__ import annotations

import struct
from pathlib import Path

__all__ = ["ElfError", "dynamic_symbols", "resolve_dynamic_symbol"]

_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_SHT_DYNSYM = 11
_SHT_SYMTAB = 2

#: Sizes fixed by the ELF64 spec.
_EHDR_SIZE = 64
_SHDR_SIZE = 64
_SYM_SIZE = 24

#: STT_FUNC and STT_GNU_IFUNC -- the symbol types a uprobe can sit on.
_STT_FUNC = 2
_STT_GNU_IFUNC = 10


class ElfError(ValueError):
    """The file is not an ELF64 object, or is too damaged to read."""


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise ElfError(f"no such file: {path}") from exc
    except OSError as exc:
        raise ElfError(f"could not read {path}: {exc}") from exc


def _at(data: bytes, offset: int, size: int, what: str) -> bytes:
    """Slice with a bounds check, so a truncated file is an error not an
    IndexError and not a silently short read."""
    end = offset + size
    if offset < 0 or end > len(data):
        raise ElfError(
            f"file is truncated: needed {size} bytes at 0x{offset:x} for {what}, "
            f"file is {len(data)} bytes"
        )
    return data[offset:end]


def dynamic_symbols(path: Path | str) -> dict[str, int]:
    """``{bare symbol name: st_value}`` for the dynamic symbol table.

    Versioned names are keyed by their bare form: libssl exports
    ``SSL_do_handshake@@OPENSSL_3.0.0`` and every caller asks for
    ``SSL_do_handshake``. Where several versions of a name exist, the default
    one (``@@``) wins over a compatibility alias (``@``).

    Only function symbols are returned. A uprobe on a data symbol would attach
    somewhere never executed, which looks exactly like the failure this module
    exists to diagnose.
    """
    elf = Path(path)
    data = _read(elf)

    if _at(data, 0, 4, "ELF magic") != _ELF_MAGIC:
        raise ElfError(f"{elf} is not an ELF file (bad magic)")
    if data[4] != _ELFCLASS64:
        raise ElfError(
            f"{elf} is not a 64-bit ELF (ELFCLASS={data[4]}). Refusing to parse "
            "it as one: a 32-bit header read as 64-bit yields a plausible but "
            "wrong offset, which is worse than an error."
        )

    header = _at(data, 0, _EHDR_SIZE, "ELF header")
    e_shoff = struct.unpack_from("<Q", header, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", header, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", header, 0x3C)[0]

    if e_shoff == 0 or e_shnum == 0:
        raise ElfError(f"{elf} has no section headers; cannot read .dynsym")
    if e_shentsize != _SHDR_SIZE:
        raise ElfError(f"{elf} has unexpected section header size {e_shentsize}")

    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(e_shnum):
        raw = _at(
            data, e_shoff + index * _SHDR_SIZE, _SHDR_SIZE, f"section header {index}"
        )
        sh_type = struct.unpack_from("<I", raw, 0x04)[0]
        sh_offset = struct.unpack_from("<Q", raw, 0x18)[0]
        sh_size = struct.unpack_from("<Q", raw, 0x20)[0]
        sh_link = struct.unpack_from("<I", raw, 0x28)[0]
        sh_entsize = struct.unpack_from("<Q", raw, 0x38)[0]
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    symbols: dict[str, int] = {}
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        # .dynsym is what a uprobe can use; .symtab is read too when present,
        # because a locally built or unstripped library has more in it.
        if sh_type not in (_SHT_DYNSYM, _SHT_SYMTAB):
            continue
        if sh_entsize != _SYM_SIZE or sh_link >= len(sections):
            continue

        _, str_offset, str_size, _, _ = sections[sh_link]
        strtab = _at(data, str_offset, str_size, "string table")

        for position in range(0, sh_size - sh_size % _SYM_SIZE, _SYM_SIZE):
            entry = _at(data, sh_offset + position, _SYM_SIZE, "symbol")
            st_name = struct.unpack_from("<I", entry, 0x00)[0]
            st_info = entry[0x04]
            st_value = struct.unpack_from("<Q", entry, 0x08)[0]

            if st_value == 0 or st_name == 0 or st_name >= len(strtab):
                continue
            if (st_info & 0xF) not in (_STT_FUNC, _STT_GNU_IFUNC):
                continue

            end = strtab.find(b"\x00", st_name)
            raw_name = strtab[st_name : end if end != -1 else len(strtab)]
            name = raw_name.decode("utf-8", "replace")

            # `name@@VERSION` is the default version, `name@VERSION` a
            # compatibility alias. Prefer the default; never let an alias
            # overwrite one already found.
            default = "@@" in name
            bare = name.split("@", 1)[0]
            if not bare:
                continue
            if bare not in symbols or default:
                symbols[bare] = st_value

    return symbols


def resolve_dynamic_symbol(path: Path | str, symbol: str) -> int | None:
    """``st_value`` for ``symbol``, or None if the library does not export it.

    The returned value is a virtual address. For the shared objects a uprobe
    targets these coincide with the file offset, because the first PT_LOAD maps
    at ``p_offset == p_vaddr``. bcc does its own conversion at attach time, so
    this number is for COMPARISON and diagnosis; it is not passed to the kernel
    unless the operator explicitly asks for address-based attach.
    """
    return dynamic_symbols(path).get(symbol)
