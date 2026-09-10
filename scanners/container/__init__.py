"""Scanner C -- container image crypto detection. The first `shipped` view.

What an image *ships* is the second of the three drift views, and the one that
most often contradicts the first: a repo can declare a post-quantum-ready
dependency and still ship an OpenSSL that has no ML-KEM compiled into it.

Design decisions, all recorded in ADR-0006:

* **Local images only.** ``target.ref`` is a ``docker save`` tar or an OCI
  layout directory on disk. There is no registry pull in ``scan()`` -- not a
  fallback, not a retry. The scan path is air-gapped by construction, and a
  pull is a separate step someone runs deliberately before scanning.
* **Streamed, never extracted.** Layers are read as nested tar streams. Nothing
  is unpacked to disk, so a hostile image cannot escape a scratch directory it
  is never given, and path traversal in a member name has nothing to traverse.
* **Certificates are parsed; private keys are not.** A certificate is public
  by design, so its subject, validity, key algorithm and signature algorithm
  are read out in full. A private key is recorded by presence, location and a
  fingerprint of its *public* half -- never its bytes, and never a hash of its
  secret bytes either. See :func:`_key_finding`.
* **The knowledge pack decides what counts as cryptography.** Package names
  live in ``knowledge/libraries.yaml``, not here, the same way algorithm names
  live in the semgrep rules and not in the source scanner (ADR-0004).

Evidence locators are ``sha256:<layer-diff-id>/<path-inside-layer>``, so a
finding names the exact layer that introduced it -- which is what makes "this
came in with the base image, not with your Dockerfile" answerable.
"""

from __future__ import annotations

import io
import json
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from core.scanner import ScanContext, Target
from core.schema import AssetType, Evidence, Finding, Occurrence, Primitive, View
from scanners.libraries import (
    DISTRO,
    LibraryFact,
    LibraryPackMissingError,
    index_for,
    is_pqc_capable,
    upstream_version,
)

__all__ = [
    "ContainerScanError",
    "ContainerScanner",
    "ImageLayoutError",
    "ImageUnreadableError",
    "LibraryPackMissingError",
]

#: Package databases we know how to read, as in-layer paths.
DPKG_STATUS_PATH = "var/lib/dpkg/status"
APK_INSTALLED_PATH = "lib/apk/db/installed"

#: What replaces a snippet that could carry key material.
REDACTED = "<redacted key material>"

#: Read cap for any single member. A package database on a fat image is a few
#: MB; anything claiming to be far larger is not something we need in memory.
MAX_MEMBER_BYTES = 32 * 1024 * 1024

#: Extensions that make a file worth opening as crypto material.
CERT_SUFFIXES = frozenset({".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle"})
KEY_SUFFIXES = frozenset({".key"})
KEYSTORE_SUFFIXES = frozenset({".jks", ".p12", ".pfx", ".keystore", ".truststore"})

#: Directories whose contents are worth opening whatever they are called.
CRYPTO_DIRS = (
    "etc/ssl/",
    "etc/pki/",
    "etc/ca-certificates/",
    "usr/share/ca-certificates/",
    "usr/local/share/ca-certificates/",
    "etc/tls/",
)

_PEM_CERTIFICATE = b"-----BEGIN CERTIFICATE-----"
_PEM_PRIVATE_KEY = b"PRIVATE KEY-----"
_DER_SEQUENCE = b"\x30\x82"

#: Keystore magic -> format name.
_KEYSTORE_MAGIC = {
    b"\xfe\xed\xfe\xed": "JKS",
    b"\xce\xce\xce\xce": "JCEKS",
}


class ContainerScanError(RuntimeError):
    """Base class for conditions that make an image scan impossible."""


class ImageUnreadableError(ContainerScanError):
    """The path is not a readable tar archive or OCI layout directory."""


class ImageLayoutError(ContainerScanError):
    """The archive opened, but it is not a container image we understand."""


# ---------------------------------------------------------------------------
# The knowledge pack
# ---------------------------------------------------------------------------


# The pack is read through `scanners.libraries`, which the dependency scanner
# (ADR-0021) shares. Two readers of one pack is how a version comparison drifts
# until the same OpenSSL is PQC-capable in one view and not in the other.
#
# The lookup is scoped to `distro` -- system packages -- so a PyPI wheel called
# `cryptography` can never be matched against a dpkg entry, and vice versa.
# They are different artefacts with different version numbering.


def _load_library_pack(knowledge_dir: Path) -> dict[str, LibraryFact]:
    """``dpkg/apk package name -> LibraryFact``, lower-cased for matching."""
    return index_for(knowledge_dir, DISTRO)


def _is_pqc_capable(fact: LibraryFact, version: str) -> bool | None:
    """``None`` when the pack does not know -- never a guess (ADR-0017)."""
    return is_pqc_capable(fact, version)


def _upstream_version(raw: str) -> str:
    """Strip distro packaging from a version. See `scanners.libraries`."""
    return upstream_version(raw)


# ---------------------------------------------------------------------------
# Package database parsers
# ---------------------------------------------------------------------------


def _parse_dpkg_status(text: str) -> list[dict[str, str]]:
    """Blank-line-separated RFC822-ish stanzas, as dpkg writes them.

    Only ``Package:``, ``Version:``, ``Source:`` and ``Status:`` are read.
    Continuation lines (leading whitespace) belong to the previous field and
    are skipped rather than mistaken for new fields -- a ``Description`` body
    containing "Version: 1.0" would otherwise poison the stanza.
    """
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in text.splitlines():
        if not line.strip():
            if current:
                packages.append(current)
                current = {}
            continue
        if line[0].isspace():
            continue
        key, separator, value = line.partition(":")
        if separator:
            current[key.strip().lower()] = value.strip()

    if current:
        packages.append(current)

    # dpkg keeps removed-but-not-purged packages in the same file; those are
    # not shipped and must not appear in an inventory of what is installed.
    return [p for p in packages if " installed" in p.get("status", "")]


def _parse_apk_installed(text: str) -> list[dict[str, str]]:
    """Blank-line-separated single-letter records, as apk writes them.

    ``P:`` is the package name, ``V:`` the version, ``o:`` the origin package.
    """
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in text.splitlines():
        if not line.strip():
            if current:
                packages.append(current)
                current = {}
            continue
        key, separator, value = line.partition(":")
        if separator and len(key) == 1:
            current[key] = value.strip()

    if current:
        packages.append(current)
    return [p for p in packages if "P" in p and "V" in p]


# ---------------------------------------------------------------------------
# Certificate and key readers
# ---------------------------------------------------------------------------


def _common_name(name: x509.Name) -> str | None:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _public_key_facts(public_key: object) -> tuple[str, int | None, str | None]:
    """``(algorithm, key_size, curve)`` for a public key, without its private half."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.curve.key_size, public_key.curve.name
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, None
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    return "unknown", None, None


def _public_key_fingerprint(public_key: Any) -> str:
    """SHA-256 over the SubjectPublicKeyInfo DER.

    The same construction as an SSH or TLS key fingerprint: derived from the
    PUBLIC half, so it correlates the same key across images and views while
    revealing nothing. Deliberately NOT a hash of the private key bytes --
    that would be a verifier for the secret we are refusing to store.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{sha256(der).hexdigest()}"


def _primitive_for(algorithm: str) -> Primitive:
    return {
        "RSA": "pke",
        "ECDSA": "signature",
        "Ed25519": "signature",
        "Ed448": "signature",
        "DSA": "signature",
    }.get(algorithm, "unknown")  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Image layouts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Layer:
    """One layer's blob, with the identity and provenance to describe it."""

    diff_id: str
    blob: bytes
    created_by: str | None


def _read_member(tar: tarfile.TarFile, name: str) -> bytes:
    handle = tar.extractfile(name)
    if handle is None:
        raise ImageLayoutError(f"{name} is not a regular file in the image archive")
    return handle.read(MAX_MEMBER_BYTES)


def _instructions(config: dict[str, Any]) -> list[str | None]:
    """Dockerfile instructions, one per non-empty layer, in layer order.

    ``history`` includes metadata-only steps (ENV, LABEL) marked
    ``empty_layer``; those contribute no filesystem layer, so dropping them
    realigns history with ``rootfs.diff_ids``. Best-effort: an image built by a
    tool that omits history yields ``None`` and the finding says so.
    """
    return [
        entry.get("created_by")
        for entry in config.get("history", [])
        if not entry.get("empty_layer")
    ]


def _layers_from_docker_save(tar: tarfile.TarFile) -> list[_Layer]:
    """A `docker save` archive: manifest.json names the config and the layers."""
    manifest = json.loads(_read_member(tar, "manifest.json"))
    if not isinstance(manifest, list) or not manifest:
        raise ImageLayoutError("manifest.json is empty or not a list")

    entry = manifest[0]
    config = json.loads(_read_member(tar, entry["Config"]))
    diff_ids = list(config.get("rootfs", {}).get("diff_ids", []))
    created_by = _instructions(config)

    layers: list[_Layer] = []
    for index, layer_path in enumerate(entry.get("Layers", [])):
        blob = _read_member(tar, layer_path)
        digest = (
            diff_ids[index]
            if index < len(diff_ids)
            else f"sha256:{sha256(blob).hexdigest()}"
        )
        layers.append(
            _Layer(
                diff_id=digest,
                blob=blob,
                created_by=created_by[index] if index < len(created_by) else None,
            )
        )
    return layers


def _layers_from_oci_layout(root: Path) -> list[_Layer]:
    """An OCI image layout directory: index.json -> manifest -> config+layers."""
    index_path = root / "index.json"
    if not index_path.is_file():
        raise ImageLayoutError(f"{root} has no index.json; not an OCI image layout")

    def blob(digest: str) -> bytes:
        algorithm, _, value = digest.partition(":")
        path = root / "blobs" / algorithm / value
        if not path.is_file():
            raise ImageLayoutError(f"blob {digest} is missing from {root}")
        return path.read_bytes()

    index = json.loads(index_path.read_text(encoding="utf-8"))
    manifests = index.get("manifests", [])
    if not manifests:
        raise ImageLayoutError(f"{index_path} lists no manifests")

    manifest = json.loads(blob(manifests[0]["digest"]))
    config = json.loads(blob(manifest["config"]["digest"]))
    diff_ids = list(config.get("rootfs", {}).get("diff_ids", []))
    created_by = _instructions(config)

    layers: list[_Layer] = []
    for index_position, descriptor in enumerate(manifest.get("layers", [])):
        raw = blob(descriptor["digest"])
        digest = (
            diff_ids[index_position]
            if index_position < len(diff_ids)
            else descriptor["digest"]
        )
        layers.append(
            _Layer(
                diff_id=digest,
                blob=raw,
                created_by=(
                    created_by[index_position]
                    if index_position < len(created_by)
                    else None
                ),
            )
        )
    return layers


def _open_image(reference: str) -> list[_Layer]:
    """Read a local image. Never touches the network."""
    path = Path(reference)

    if path.is_dir():
        return _layers_from_oci_layout(path)

    if not path.is_file():
        raise ImageUnreadableError(
            f"{reference} is neither a readable file nor a directory. The "
            "container scanner reads a local `docker save` tar or an OCI "
            "layout directory; it never pulls from a registry."
        )

    try:
        with tarfile.open(path, mode="r") as tar:
            names = set(tar.getnames())
            if "manifest.json" in names:
                return _layers_from_docker_save(tar)
            if "index.json" in names or "oci-layout" in names:
                raise ImageLayoutError(
                    f"{reference} looks like an OCI layout inside a tar; "
                    "extract it to a directory and point the scan at that"
                )
            raise ImageLayoutError(
                f"{reference} is a tar archive but has no manifest.json, so it "
                "is not a container image"
            )
    except tarfile.TarError as exc:
        raise ImageUnreadableError(
            f"{reference} could not be read as a tar archive: {exc}"
        ) from exc


def _layer_entries(layer: _Layer) -> Iterator[tuple[str, bytes]]:
    """Stream ``(normalised path, bytes)`` for the regular files in a layer.

    ``r|*`` streams and transparently handles a gzipped blob, so nothing is
    written to disk and the whole layer is never held decompressed at once.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(layer.blob), mode="r|*") as inner:
            for member in inner:
                if not member.isfile():
                    continue
                name = member.name.removeprefix("./").lstrip("/")
                if not _is_interesting(name):
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    continue
                handle = inner.extractfile(member)
                if handle is None:
                    continue
                yield name, handle.read(MAX_MEMBER_BYTES)
    except tarfile.TarError:
        # A single unreadable layer is not a reason to abandon the image; the
        # orchestrator's per-scanner guard still sees anything that follows.
        return


def _is_interesting(name: str) -> bool:
    """Whether a member is worth reading at all. Keeps the walk cheap."""
    if name in (DPKG_STATUS_PATH, APK_INSTALLED_PATH):
        return True
    if name.startswith(CRYPTO_DIRS):
        return True
    suffix = Path(name).suffix.lower()
    return (
        suffix in CERT_SUFFIXES or suffix in KEY_SUFFIXES or suffix in KEYSTORE_SUFFIXES
    )


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------

_VIEW: View = "shipped"


def _occurrence(
    layer: _Layer, path: str, detail: str, snippet: str | None
) -> Occurrence:
    return Occurrence(
        view=_VIEW,
        locator=f"{layer.diff_id}/{path}",
        detail=detail,
        snippet=snippet,
    )


def _finding(
    *,
    asset_type: AssetType,
    primitive: Primitive,
    algorithm: str,
    params: dict[str, Any],
    layer: _Layer,
    path: str,
    detail: str,
    snippet: str | None,
    confidence: float,
    raw: dict[str, Any],
) -> Finding:
    enriched = dict(params)
    if layer.created_by is not None:
        enriched["created_by"] = layer.created_by
    return Finding(
        scanner_id="container",
        view=_VIEW,
        asset_type=asset_type,
        primitive=primitive,
        algorithm=algorithm,
        params=enriched,
        usage="unknown",
        configurable=False,
        evidence=Evidence(occurrences=[_occurrence(layer, path, detail, snippet)]),
        confidence=confidence,
        raw=raw,
    )


def _library_findings(
    packages: list[dict[str, str]],
    *,
    name_key: str,
    version_key: str,
    source_key: str,
    pack: dict[str, LibraryFact],
    layer: _Layer,
    path: str,
    detail: str,
) -> Iterator[Finding]:
    for package in packages:
        name = package.get(name_key, "")
        fact = pack.get(name.lower())
        if fact is None:
            continue

        raw_version = package.get(version_key, "")
        version = _upstream_version(raw_version)
        params: dict[str, Any] = {
            "version": version,
            "package": name,
            "package_version": raw_version,
        }
        origin = package.get(source_key)
        if origin:
            params["source_package"] = origin

        capable = _is_pqc_capable(fact, version)
        if capable is not None:
            params["pqc_capable"] = capable
        if fact.eol is not None:
            params["eol"] = fact.eol

        yield _finding(
            asset_type="library",
            primitive="unknown",
            algorithm=fact.name,
            params=params,
            layer=layer,
            path=path,
            detail=detail,
            snippet=f"{name} {raw_version}",
            confidence=1.0,
            raw={
                "package": name,
                "provides": list(fact.provides),
                "knowledge_source": fact.source,
            },
        )


def _load_pem_blocks(data: bytes) -> list[x509.Certificate]:
    """Load each PEM certificate independently, skipping the unparseable."""
    certificates: list[x509.Certificate] = []
    end = b"-----END CERTIFICATE-----"
    for chunk in data.split(end):
        start = chunk.find(_PEM_CERTIFICATE)
        if start == -1:
            continue
        try:
            certificates.append(x509.load_pem_x509_certificate(chunk[start:] + end))
        except (ValueError, TypeError):
            continue
    return certificates


def _certificate_findings(data: bytes, layer: _Layer, path: str) -> Iterator[Finding]:
    """Every certificate in a PEM bundle, or the single DER certificate."""
    certificates: list[x509.Certificate] = []
    if _PEM_CERTIFICATE in data:
        try:
            certificates = x509.load_pem_x509_certificates(data)
        except (ValueError, TypeError):
            # A real CA bundle is ~150 certificates and only has to contain one
            # that offends a strictness check -- Alpine's ships a certificate
            # with a non-positive serial number, which RFC 5280 disallows and
            # newer `cryptography` refuses. Falling back to block-at-a-time
            # keeps the other 149 rather than losing the file.
            certificates = _load_pem_blocks(data)
    elif data.startswith(_DER_SEQUENCE):
        try:
            certificates = [x509.load_der_x509_certificate(data)]
        except (ValueError, TypeError):
            certificates = []

    for certificate in certificates:
        algorithm, key_size, curve = _public_key_facts(certificate.public_key())
        subject = _common_name(certificate.subject)
        issuer = _common_name(certificate.issuer)

        params: dict[str, Any] = {
            "format": "X.509",
            "serial_number": hex(certificate.serial_number),
            "not_valid_before": certificate.not_valid_before_utc.isoformat(),
            "not_valid_after": certificate.not_valid_after_utc.isoformat(),
            "self_signed": certificate.subject == certificate.issuer,
            "public_key_fingerprint": _public_key_fingerprint(certificate.public_key()),
        }
        if key_size is not None:
            params["key_size"] = key_size
        if curve is not None:
            params["curve"] = curve
        if subject is not None:
            params["subject_common_name"] = subject
        if issuer is not None:
            params["issuer_common_name"] = issuer
        params["signature_algorithm"] = certificate.signature_algorithm_oid._name

        yield _finding(
            asset_type="certificate",
            primitive=_primitive_for(algorithm),
            algorithm=algorithm,
            params=params,
            layer=layer,
            path=path,
            detail=f"x509 serial={params['serial_number']}",
            # Public metadata only: a certificate is published by design.
            snippet=subject or issuer or "X.509 certificate",
            confidence=1.0,
            raw={"subject": certificate.subject.rfc4514_string()},
        )


def _key_finding(data: bytes, layer: _Layer, path: str) -> Finding | None:
    """A private key, recorded by presence, location and public fingerprint.

    The private half is loaded only long enough to derive the public half, and
    is never placed in a Finding, a snippet or ``raw``. When the key cannot be
    loaded -- encrypted, or a format we do not parse -- the fingerprint is
    omitted rather than replaced by a hash of the secret bytes.
    """
    algorithm = "unknown"
    key_size: int | None = None
    fingerprint: str | None = None

    try:
        private_key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Encrypted, or a curve/format this build does not support. Either way
        # the fact and the location are still worth recording.
        private_key = None

    if private_key is not None:
        public_key = private_key.public_key()
        algorithm, key_size, _curve = _public_key_facts(public_key)
        fingerprint = _public_key_fingerprint(public_key)

    params: dict[str, Any] = {"material": "private-key", "format": "PEM"}
    if key_size is not None:
        params["key_size"] = key_size
    if fingerprint is not None:
        params["public_key_fingerprint"] = fingerprint
    else:
        params["fingerprint_unavailable"] = "key is encrypted or unparseable"

    return _finding(
        asset_type="key",
        primitive=_primitive_for(algorithm),
        algorithm=algorithm,
        params=params,
        layer=layer,
        path=path,
        detail="pem private key (contents not read)",
        snippet=REDACTED,
        confidence=1.0,
        # No key bytes, no key hash -- only what a reviewer needs to go look.
        raw={"material": "private-key"},
    )


def _keystore_finding(data: bytes, layer: _Layer, path: str) -> Finding | None:
    """A keystore, recorded by presence only. Contents are never opened."""
    suffix = Path(path).suffix.lower()
    fmt = _KEYSTORE_MAGIC.get(data[:4])
    if fmt is None:
        if suffix in (".p12", ".pfx"):
            fmt = "PKCS12"
        elif suffix in (".jks", ".keystore", ".truststore"):
            fmt = "JKS"
        else:
            return None

    return _finding(
        asset_type="key",
        primitive="unknown",
        algorithm="unknown",
        params={"material": "keystore", "format": fmt},
        layer=layer,
        path=path,
        detail=f"{fmt} keystore (contents not opened)",
        snippet=REDACTED,
        confidence=1.0,
        raw={"material": "keystore"},
    )


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class ContainerScanner:
    """Detects cryptographic material shipped inside a container image."""

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "container"
    view: View = "shipped"

    def supports(self, target: Target) -> bool:
        return target.kind == "image"

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        pack = _load_library_pack(ctx.knowledge_dir)
        layers = _open_image(target.ref)

        for layer in layers:
            yield from self._scan_layer(layer, pack)

    def _scan_layer(
        self, layer: _Layer, pack: dict[str, LibraryFact]
    ) -> Iterator[Finding]:
        for path, data in _layer_entries(layer):
            if path == DPKG_STATUS_PATH:
                yield from _library_findings(
                    _parse_dpkg_status(data.decode("utf-8", "replace")),
                    name_key="package",
                    version_key="version",
                    source_key="source",
                    pack=pack,
                    layer=layer,
                    path=path,
                    detail="dpkg status",
                )
                continue

            if path == APK_INSTALLED_PATH:
                yield from _library_findings(
                    _parse_apk_installed(data.decode("utf-8", "replace")),
                    name_key="P",
                    version_key="V",
                    source_key="o",
                    pack=pack,
                    layer=layer,
                    path=path,
                    detail="apk installed",
                )
                continue

            yield from self._scan_material(data, layer, path)

    def _scan_material(
        self, data: bytes, layer: _Layer, path: str
    ) -> Iterator[Finding]:
        suffix = Path(path).suffix.lower()

        if suffix in KEYSTORE_SUFFIXES or data[:4] in _KEYSTORE_MAGIC:
            keystore = _keystore_finding(data, layer, path)
            if keystore is not None:
                yield keystore
            return

        if _PEM_PRIVATE_KEY in data:
            key = _key_finding(data, layer, path)
            if key is not None:
                yield key

        yield from _certificate_findings(data, layer, path)
