"""Build the byte-technique binary fixtures. Run by make_fixtures.sh.

These carry payloads the scanner finds by SCANNING BYTES rather than by reading
a symbol table -- an embedded PEM block, an ASN.1 algorithm OID, a well-known
constant table, a version banner. They are compiled C so they are genuine ELF
files with real sections, not blobs with an ELF header glued on: the scanner
locates each hit by section, and a fake container would not exercise that.

The PE is hand-assembled. There is no Windows cross-toolchain on the build
host, and a minimal PE32+ is a few hundred bytes of well-documented structs --
far less machinery than adding mingw as a build dependency for one fixture.
"""

from __future__ import annotations

import struct
import subprocess
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# The planted secrets. Every one of these must reach NO Finding --
# tests/test_scanner_binary.py asserts it. See answer_key.yaml.
# ---------------------------------------------------------------------------
SENTINEL_KEY = "BINSECRETSENTINELaaaabbbbccccdddd"
SENTINEL_CERT = "BINNOTAREALCERTBINNOTAREALCERTBINNOTAREALCERTBINNOTAREAL"

def _real_certificate() -> str:
    """A GENUINE self-signed RSA-2048 certificate, generated once and committed.

    Genuine rather than a text placeholder because the scanner PARSES what it
    finds -- subject, validity, public-key algorithm and size -- and a fixture
    that could not be parsed would leave that path untested while looking
    covered. The private half is thrown away here; the key fixture below is a
    separate, deliberately fake block carrying the sentinel.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "ecdat-binary-fixture.invalid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT test fixture"),
        ]
    )
    # Fixed dates so a regenerated fixture differs only in its key material.
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x0ECDA7)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=825))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode().strip()


CERT_PEM = _real_certificate()

#: NOT a real key -- a PEM banner around a sentinel. The scanner must record
#: that a private key is present and never carry its body anywhere, so the body
#: only has to be recognisable, and a genuine key in a committed fixture is a
#: genuine key in a public repository.
KEY_PEM = f"""-----BEGIN RSA PRIVATE KEY-----
{SENTINEL_KEY}0000000000000000000000000000
-----END RSA PRIVATE KEY-----"""

#: sha256WithRSAEncryption, 1.2.840.113549.1.1.11, DER-encoded as a full
#: AlgorithmIdentifier OID TLV: tag 0x06, length 9, then the arc bytes.
OID_SHA256_WITH_RSA = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])

#: id-ecPublicKey, 1.2.840.10045.2.1.
OID_EC_PUBLIC_KEY = bytes([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])

#: The first 32 bytes of the AES forward S-box (FIPS 197 Figure 7). A constant
#: is the WEAKEST technique -- these bytes can occur in a lookup table that has
#: nothing to do with AES -- so the scanner scores it low on purpose.
AES_SBOX_HEAD = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    ]
)

VERSION_BANNER = "OpenSSL 3.0.13 30 Jan 2024"


def _c_array(name: str, data: bytes) -> str:
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char {name}[] = {{{body}}};"


def _compile(name: str, source: str) -> None:
    c_file = Path("/tmp") / f"ecdat_{name}.c"
    c_file.write_text(source, encoding="utf-8")
    subprocess.run(
        ["gcc", "-O0", "-o", str(HERE / name), str(c_file)],
        check=True,
    )


def _c_string(pem: str) -> str:
    """A PEM block as a C string literal, one source line per PEM line."""
    return "\n".join(f'"{line}\\n"' for line in pem.splitlines())


def build_embedded_pem() -> None:
    """A cert AND a private key, both embedded. The redaction fixture."""
    source = (
        "#include <stdio.h>\n"
        "static const char partner_cert[] =\n"
        f"{_c_string(CERT_PEM)};\n"
        "static const char signing_key[] =\n"
        f"{_c_string(KEY_PEM)};\n"
        "int main(void) {\n"
        '    printf("%zu %zu\\n", sizeof partner_cert, sizeof signing_key);\n'
        "    return 0;\n"
        "}\n"
    )
    _compile("elf_embedded_pem", source)


def build_embedded_oid() -> None:
    source = textwrap.dedent(f"""
        #include <stdio.h>
        {_c_array("sig_alg_oid", OID_SHA256_WITH_RSA)}
        {_c_array("key_alg_oid", OID_EC_PUBLIC_KEY)}
        int main(void) {{
            printf("%zu %zu\\n", sizeof sig_alg_oid, sizeof key_alg_oid);
            return 0;
        }}
    """).strip()
    _compile("elf_embedded_oid", source)


def build_constants() -> None:
    source = textwrap.dedent(f"""
        #include <stdio.h>
        {_c_array("sbox", AES_SBOX_HEAD)}
        int main(void) {{
            printf("%zu\\n", sizeof sbox);
            return 0;
        }}
    """).strip()
    _compile("elf_constants", source)


def build_version_banner() -> None:
    source = textwrap.dedent(f"""
        #include <stdio.h>
        static const char banner[] = "{VERSION_BANNER}";
        int main(void) {{
            printf("%s\\n", banner);
            return 0;
        }}
    """).strip()
    _compile("elf_version_banner", source)


def build_pe() -> None:
    """A minimal PE32+ carrying an import table for bcrypt.dll.

    Windows CNG is where PE crypto lives, so the fixture has to exercise the
    IMPORT path rather than only the byte scan -- otherwise "PE is supported"
    would mean "we can read strings out of a PE", which is not the claim.
    """
    text = b"\x48\x31\xc0\xc3"
    banner = (VERSION_BANNER + "\0").encode()

    # .idata laid out by hand at RVA 0x3000.
    idata_rva = 0x3000
    names = [b"BCryptGenerateSymmetricKey", b"BCryptEncrypt", b"BCryptSignHash"]
    dll_name = b"bcrypt.dll\0"

    descriptors = 2 * 20  # one real descriptor plus the null terminator
    thunk_bytes = (len(names) + 1) * 8
    ilt_off = descriptors
    iat_off = ilt_off + thunk_bytes
    hint_off = iat_off + thunk_bytes
    hints: list[int] = []
    blob = bytearray()
    cursor = hint_off
    for name in names:
        hints.append(cursor)
        entry = struct.pack("<H", 0) + name + b"\0"
        if len(entry) % 2:
            entry += b"\0"
        blob += entry
        cursor += len(entry)
    dll_off = cursor
    blob += dll_name

    idata = bytearray()
    idata += struct.pack(
        "<IIIII", idata_rva + ilt_off, 0, 0, idata_rva + dll_off, idata_rva + iat_off
    )
    idata += b"\0" * 20
    for table in (ilt_off, iat_off):
        assert len(idata) == table
        for hint in hints:
            idata += struct.pack("<Q", idata_rva + hint)
        idata += struct.pack("<Q", 0)
    assert len(idata) == hint_off
    idata += blob

    sections = [
        (b".text", text, 0x1000, 0x400),
        (b".rdata", banner, 0x2000, 0x600),
        (b".idata", bytes(idata), idata_rva, 0x800),
    ]

    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80) + b"\0" * (0x80 - 64)
    coff = b"PE\0\0" + struct.pack(
        "<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x0022
    )
    opt = struct.pack(
        "<HBBIIIIIQ", 0x20B, 14, 0, len(text), len(banner), 0, 0x1000, 0x1000,
        0x140000000,
    )
    opt += struct.pack(
        "<IIHHHHHHIIIIHH", 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x5000, 0x400, 0, 3, 0
    )
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = [(0, 0)] * 16
    directories[1] = (idata_rva, len(idata))  # IMAGE_DIRECTORY_ENTRY_IMPORT
    for rva, size in directories:
        opt += struct.pack("<II", rva, size)

    table = b""
    for name, data, vaddr, raw in sections:
        table += name.ljust(8, b"\0")
        table += struct.pack("<IIII", len(data), vaddr, len(data), raw)
        table += struct.pack("<IIHHI", 0, 0, 0, 0, 0x40000040)

    image = bytearray((dos + coff + opt + table).ljust(0x400, b"\0"))
    for _name, data, _vaddr, raw in sections:
        image[raw : raw + len(data)] = data
        if len(image) < raw + 0x200:
            image.extend(b"\0" * (raw + 0x200 - len(image)))
    (HERE / "pe_bcrypt.exe").write_bytes(bytes(image))


def build_broken() -> None:
    """Not a parseable binary. Proves one bad file does not end the scan."""
    (HERE / "broken.bin").write_bytes(
        b"\x7fELF" + b"this file claims to be an ELF and is not" + b"\x00" * 32
    )


if __name__ == "__main__":
    build_embedded_pem()
    build_embedded_oid()
    build_constants()
    build_version_banner()
    build_pe()
    build_broken()
    print("payload fixtures written")
