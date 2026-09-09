"""Generate the synthetic container images the container-scanner tests use.

    .venv/bin/python -m tests.fixtures.build_container_fixtures

The generated tarballs under ``testdata/images/synthetic/`` are COMMITTED, and
they -- not this script -- are what the tests read. That is the point: a test
that pulls ``ubuntu:22.04`` is testing whatever Canonical published this
morning, and a parser regression would show up as a mysterious version change
months later. The synthetic images pin the *inputs* so the tests measure the
parser (ADR-0006).

The package-database stanzas below are the real formats, field for field, as
dpkg and apk actually write them. Copying the shape is the whole value; a
made-up format would make these tests prove nothing about a real image.

Determinism: tar member metadata (mtime, uid/gid, names) is pinned, and the
certificate's validity window is fixed, so regenerating changes nothing except
the throwaway keypair -- which is generated fresh on purpose and which nothing
asserts on by value.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUTPUT_DIR = Path("testdata/images/synthetic")

#: Pinned so regenerating produces byte-stable metadata.
EPOCH = 0

#: Fixed validity window, so the answer key can assert exact dates.
CERT_NOT_BEFORE = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
CERT_NOT_AFTER = dt.datetime(2034, 1, 1, tzinfo=dt.UTC)

# ---------------------------------------------------------------------------
# Real package-database formats
# ---------------------------------------------------------------------------

#: A dpkg status stanza exactly as Ubuntu 22.04 writes it for libssl3, plus a
#: neighbouring non-crypto package so the parser has to discriminate rather
#: than return everything it sees.
DPKG_STATUS = """\
Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 13228
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.35-0ubuntu3.8
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.
Homepage: https://www.gnu.org/software/libc/

Package: libssl3
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 4396
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.2-0ubuntu1.10
Depends: libc6 (>= 2.34)
Description: Secure Sockets Layer toolkit - shared libraries
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols for secure communication over the
 Internet.
 .
 It contains the libssl and libcrypto libraries.
Original-Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
Homepage: https://www.openssl.org/

Package: libgnutls30
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 2114
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gnutls28
Version: 3.7.3-4ubuntu1.5
Depends: libc6 (>= 2.34)
Description: GNU TLS library - main runtime library
 GnuTLS is a portable library which implements the Transport Layer
 Security (TLS) protocol.
Homepage: https://www.gnutls.org/

Package: perl-base
Status: install ok installed
Priority: required
Section: perl
Installed-Size: 7767
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Version: 5.34.0-3ubuntu1.3
Description: minimal Perl system
 Perl is a scripting language used in many system scripts and utilities.
Homepage: http://dev.perl.org/perl5/
"""

#: An apk installed database exactly as Alpine writes it. Note the differences
#: from dpkg that a parser must actually handle: single-letter keys, `P:` for
#: the package name, `V:` for a version carrying an `-rN` package revision,
#: and `o:` for the origin (source) package.
APK_INSTALLED = """\
C:Q1VMTdQnrPqLzZOFvUmYVYVpZ8xLk=
P:musl
V:1.2.5-r10
A:x86_64
S:408443
I:663552
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teras <timo.teras@iki.fi>
t:1748404746
c:8f4bd1c1a34dd6b0f2b1e9d0d1f2a3b4c5d6e7f8
p:so:libc.musl-x86_64.so.1=1

C:Q1eVpkKZmvUOgOEQNjWY2VUCHkzOU=
P:libssl3
V:3.5.7-r0
A:x86_64
S:222917
I:544768
T:SSL shared libraries
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1758706163
c:0f1b8b7a3f0a2c4e5d6f7a8b9c0d1e2f3a4b5c6d
D:so:libc.musl-x86_64.so.1
p:so:libssl.so.3=3

C:Q1kL9mNoPqRsTuVwXyZ0123456789=
P:libcrypto3
V:3.5.7-r0
A:x86_64
S:1795891
I:4726784
T:Crypto library from openssl
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1758706163
c:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d
D:so:libc.musl-x86_64.so.1
p:so:libcrypto.so.3=3

C:Q1zZyYxXwWvVuUtTsSrRqQpPoOnNm=
P:busybox
V:1.37.0-r19
A:x86_64
S:512079
I:962560
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Sertonix <sertonix@posteo.net>
t:1751980854
c:9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c
D:so:libc.musl-x86_64.so.1
"""


# ---------------------------------------------------------------------------
# tar / image plumbing
# ---------------------------------------------------------------------------


def _member(name: str, data: bytes) -> tarfile.TarInfo:
    """A tar member with every varying field pinned."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = EPOCH
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def _layer_tar(files: dict[str, bytes]) -> bytes:
    """One layer's filesystem, as an uncompressed tar."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name in sorted(files):
            tar.addfile(_member(name, files[name]), io.BytesIO(files[name]))
    return buffer.getvalue()


def _docker_save_tar(
    destination: Path, layers: list[dict[str, bytes]], instructions: list[str]
) -> None:
    """Write a `docker save`-format image containing ``layers``.

    The layout is the one `docker save` produces: a manifest.json naming the
    config and the layer tars, a config carrying rootfs.diff_ids and history,
    and one directory per layer. diff_ids are real sha256 digests of the layer
    tars, because the scanner uses them as evidence locators and a fake digest
    would make the fixture prove nothing.
    """
    layer_blobs = [_layer_tar(files) for files in layers]
    diff_ids = ["sha256:" + hashlib.sha256(blob).hexdigest() for blob in layer_blobs]
    layer_paths = [f"{digest.removeprefix('sha256:')}/layer.tar" for digest in diff_ids]

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [
            {"created": "2024-01-01T00:00:00Z", "created_by": instruction}
            for instruction in instructions
        ],
    }
    config_blob = json.dumps(config, indent=3, sort_keys=True).encode("utf-8")
    config_name = f"{hashlib.sha256(config_blob).hexdigest()}.json"

    manifest = [
        {
            "Config": config_name,
            "RepoTags": [f"ecdat-synthetic/{destination.stem}:latest"],
            "Layers": layer_paths,
        }
    ]
    manifest_blob = json.dumps(manifest, indent=3).encode("utf-8")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, mode="w", format=tarfile.GNU_FORMAT) as tar:
        tar.addfile(_member(config_name, config_blob), io.BytesIO(config_blob))
        for path, blob in zip(layer_paths, layer_blobs, strict=True):
            tar.addfile(_member(path, blob), io.BytesIO(blob))
        tar.addfile(_member("manifest.json", manifest_blob), io.BytesIO(manifest_blob))


# ---------------------------------------------------------------------------
# a genuinely valid throwaway certificate
# ---------------------------------------------------------------------------


def _self_signed() -> tuple[bytes, bytes]:
    """A real, parseable self-signed certificate and its private key.

    Generated fresh each run and thrown away. Nothing asserts on the key by
    value -- the redaction test asserts the opposite, that its bytes appear
    nowhere in any Finding.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT Synthetic Fixtures"),
            x509.NameAttribute(NameOID.COMMON_NAME, "api.quantumbank.invalid"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x2F1C)
        .not_valid_before(CERT_NOT_BEFORE)
        .not_valid_after(CERT_NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("api.quantumbank.invalid")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


# ---------------------------------------------------------------------------
# the three fixtures
# ---------------------------------------------------------------------------


def build_dpkg_image(destination: Path) -> None:
    """An Ubuntu-shaped image: dpkg status declaring libssl3 3.0.2."""
    _docker_save_tar(
        destination,
        layers=[
            {
                "var/lib/dpkg/status": DPKG_STATUS.encode("utf-8"),
                "usr/lib/x86_64-linux-gnu/libssl.so.3": b"\x7fELF not a real library",
            }
        ],
        instructions=["/bin/sh -c #(nop) ADD file:synthetic-rootfs in / "],
    )


def build_apk_image(destination: Path) -> None:
    """An Alpine-shaped image: apk installed declaring libssl3 3.5.7."""
    _docker_save_tar(
        destination,
        layers=[
            {
                "lib/apk/db/installed": APK_INSTALLED.encode("utf-8"),
                "lib/libssl.so.3": b"\x7fELF not a real library",
            }
        ],
        instructions=["/bin/sh -c #(nop) ADD file:synthetic-alpine in / "],
    )


def build_cert_image(destination: Path) -> None:
    """An image carrying a real certificate and a planted private key.

    Two layers, so the test also proves the scanner walks past the first.
    """
    certificate_pem, key_pem = _self_signed()
    _docker_save_tar(
        destination,
        layers=[
            {"etc/os-release": b'PRETTY_NAME="ECDAT Synthetic"\n'},
            {
                "etc/ssl/certs/api.quantumbank.pem": certificate_pem,
                "etc/ssl/private/api.quantumbank.key": key_pem,
            },
        ],
        instructions=[
            "/bin/sh -c #(nop) ADD file:synthetic-rootfs in / ",
            "/bin/sh -c #(nop) COPY dir:tls-material in /etc/ssl ",
        ],
    )


FIXTURES = {
    "dpkg-openssl302.tar": build_dpkg_image,
    "apk-openssl357.tar": build_apk_image,
    "certs-and-key.tar": build_cert_image,
}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, build in FIXTURES.items():
        destination = OUTPUT_DIR / filename
        build(destination)
        print(f"wrote {destination} ({destination.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
