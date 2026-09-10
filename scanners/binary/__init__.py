"""Scanner D -- cryptography in compiled binaries, and what could not be read.

There is no source here, no manifest and no config file. There is a symbol
table that may have been stripped, an import table that may be empty because
the code is statically linked, byte patterns that may be a coincidence, and a
string that may be a version banner or a log message. **Every technique in this
module is a heuristic**, and the design follows from admitting that rather than
working around it.

Three consequences shape the whole scanner:

* **Nothing is ever confidence 1.0.** The source scanner reads a declaration
  and can be certain of what it read; this one infers. Each technique carries a
  fixed confidence set by how much the evidence actually proves, and a finding
  carries the technique alongside it so the number can be argued with.
* **Coverage is reported, not implied.** A stripped binary yields fewer
  findings, and a scanner that returns fewer findings without saying so has
  reported a clean artefact. :meth:`BinaryScanner.coverage` answers "what could
  I read here?" separately from "what did I find?", and the two are different
  questions.
* **Techniques disagree, and that is kept.** A symbol table entry and an
  S-box are different kinds of evidence for the same AES; both are emitted,
  scored differently, and left for the correlator rather than merged into one
  averaged claim.

The five techniques, strongest first:

======================  ====  ==========================================
technique               conf  what it actually proves
======================  ====  ==========================================
``pem``                 0.95  a key or certificate is embedded verbatim
``symbol``              0.90  the linker resolved this named API
``oid``                 0.85  the binary can NAME this algorithm
``version-string``      0.80  a library banner is present in the image
``constant``            0.60  a table associated with this algorithm exists
======================  ====  ==========================================

``pem`` outranks ``symbol`` because an embedded PEM block is the one thing here
that is genuinely parsed rather than inferred -- the bytes decode to a
certificate or they do not. It is still below 1.0 because presence in the image
is not use at runtime.

**No secret key material is ever stored** (CLAUDE.md). An embedded private key
is recorded by presence and a public fingerprint; its bytes never enter a
Finding, and ``tests/test_scanner_binary.py`` plants a sentinel to prove it.
Scanner D is the sixth and last family under that discipline.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.logs import get_logger
from core.scanner import ScanContext, Target
from core.schema import (
    AssetType,
    Evidence,
    Finding,
    Occurrence,
    Primitive,
    Usage,
    View,
)
from scanners.libraries import index_for, is_pqc_capable

__all__ = [
    "TECHNIQUE_CONFIDENCE",
    "BinaryScanner",
    "CoverageReport",
    "encode_oid",
]

_log = get_logger("scanner.binary")

_VIEW: View = "shipped"

#: What replaces a snippet that could carry key material. Same string the
#: source and container scanners use, asserted verbatim by the tests.
REDACTED = "<redacted key material>"

#: Confidence per technique. Fixed, not computed: a longer S-box match is the
#: same evidence as a short one, and letting a technique raise its own score
#: would move every downstream band in the same direction without anyone
#: deciding to. See the module docstring for what each number means.
TECHNIQUE_CONFIDENCE: dict[str, float] = {
    "pem": 0.95,
    "symbol": 0.90,
    "oid": 0.85,
    "version-string": 0.80,
    "constant": 0.60,
}

#: Knowledge packs, relative to ``ScanContext.knowledge_dir``.
SYMBOL_PACK = Path("symbols.yaml")
OID_PACK = Path("oids.yaml")
CONSTANT_PACK = Path("constants.yaml")

#: A binary larger than this is not read. Four hundred megabytes of firmware
#: image is a different problem with a different tool.
MAX_BINARY_BYTES = 400 * 1024 * 1024

#: Directories never walked: build caches and version control hold object files
#: that are not what anybody means by "what this system ships".
SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv"}
)

#: Magic numbers. A file is a candidate only if it starts with one of these --
#: cheaper than asking LIEF about every file in a tree, and it is what keeps a
#: directory of source from being handed to a binary parser.
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)

#: ``RSA_new@OPENSSL_3.0.0`` -> ``RSA_new``. ELF exposes both spellings of the
#: same symbol and they must collapse to one finding.
_VERSION_SUFFIX = re.compile(r"@+.*$")

#: ``OpenSSL 3.0.13 30 Jan 2024`` -> the library and its version. Deliberately
#: narrow: a looser pattern turns every log line mentioning a version into a
#: library finding.
_VERSION_BANNERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("OpenSSL", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("GnuTLS", re.compile(rb"GnuTLS\s+(\d+\.\d+\.\d+)")),
    ("libgcrypt", re.compile(rb"libgcrypt\s+(\d+\.\d+\.\d+)")),
    ("Mbed TLS", re.compile(rb"[Mm]bed\s?TLS\s+(\d+\.\d+\.\d+)")),
    ("wolfSSL", re.compile(rb"wolfSSL\s+(\d+\.\d+\.\d+)")),
    ("NSS", re.compile(rb"NSS\s+(\d+\.\d+(?:\.\d+)?)")),
)

#: PEM banners worth recording, and what each one IS.
_PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----",
    re.DOTALL,
)

#: Banner labels that mean "this is a private key". Anything matching is
#: recorded by presence and fingerprint only.
_PRIVATE_LABELS = ("PRIVATE KEY",)


class BinaryPackMissingError(RuntimeError):
    """A knowledge pack the binary scanner needs is not where it should be."""


class LiefUnavailableError(RuntimeError):
    """LIEF is not importable, so no binary can be parsed."""


# ---------------------------------------------------------------------------
# Coverage: what could be read, reported separately from what was found
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """What this scanner could and could not read in one binary.

    Separate from the findings on purpose. "Six findings" and "six findings,
    and the symbol table was stripped so the count is a floor" are different
    statements, and only the second one is safe to act on.
    """

    path: str
    format: str
    #: True when the binary has no static symbol table -- `strip` removed it.
    #: The DYNAMIC table usually survives, which is why a stripped binary is
    #: degraded rather than opaque.
    stripped: bool
    imported_symbols: int
    exported_symbols: int
    sections: int
    #: Techniques that ran. Always all five: a technique that found nothing
    #: still ran, and the distinction matters when nothing is reported.
    techniques: tuple[str, ...]
    #: Prose, for a human. Empty means nothing was lost.
    limitations: tuple[str, ...] = ()


def _import_lief() -> Any:
    try:
        import lief
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise LiefUnavailableError(
            "LIEF is not installed, so the binary scanner cannot parse anything. "
            "Install it (pip install lief) or remove this scanner from the scan."
        ) from exc
    # LIEF logs parse warnings to stderr by default; a truncated file is
    # handled here and reported through the logger, not by shouting.
    with_logging = getattr(lief, "logging", None)
    if with_logging is not None:
        with_logging.disable()
    return lief


# ---------------------------------------------------------------------------
# Knowledge packs
# ---------------------------------------------------------------------------


def _load(knowledge_dir: Path, pack: Path, key: str) -> list[dict[str, Any]]:
    path = knowledge_dir / pack
    if not path.is_file():
        raise BinaryPackMissingError(
            f"the binary scanner's {key} pack is missing: {path} does not exist. "
            f"Set ECDAT_KNOWLEDGE_DIR or restore knowledge/{pack.name}."
        )
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: list[dict[str, Any]] = document.get(key) or []
    return entries


def encode_oid(dotted: str) -> bytes:
    """A dotted OID arc as a complete DER OBJECT IDENTIFIER TLV.

    ``1.2.840.113549.1.1.11`` -> ``06 09 2a 86 48 86 f7 0d 01 01 0b``.

    Encoded here rather than stored as hex in the pack: the dotted form is what
    the registry publishes and what a reviewer can check against it, and a
    hand-transcribed byte string is a place for an error nobody would notice.
    """
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2:
        raise ValueError(f"an OID needs at least two arcs: {dotted!r}")

    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunks))
    return bytes([0x06, len(body)]) + bytes(body)


@dataclass(frozen=True, slots=True)
class _Packs:
    """Everything the techniques match against, loaded once per scan."""

    symbols: dict[str, dict[str, Any]]
    oids: tuple[tuple[bytes, dict[str, Any]], ...]
    constants: tuple[tuple[bytes, dict[str, Any]], ...]
    libraries: dict[str, Any] = field(default_factory=dict)


def _packs(knowledge_dir: Path) -> _Packs:
    symbols = {
        str(entry["symbol"]): entry
        for entry in _load(knowledge_dir, SYMBOL_PACK, "symbols")
    }
    oids = tuple(
        (encode_oid(str(entry["oid"])), entry)
        for entry in _load(knowledge_dir, OID_PACK, "oids")
    )
    constants = tuple(
        (bytes.fromhex("".join(str(entry["bytes"]).split())), entry)
        for entry in _load(knowledge_dir, CONSTANT_PACK, "constants")
    )
    # The same distro pack the container scanner reads, so a version banner in
    # a binary and a package version in an image get the same answer about
    # PQC capability. Two readers of one pack is how those two drift apart.
    libraries = index_for(knowledge_dir, "distro")
    return _Packs(symbols=symbols, oids=oids, constants=constants, libraries=libraries)


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class BinaryScanner:
    """Finds cryptography in compiled ELF and PE binaries (ADR-0025).

    **Target kind.** ``directory`` -- walked for ELF/PE files, or pointed
    straight at one binary. There is deliberately no new ``binary`` target
    kind: ``TargetKind`` is a closed vocabulary threaded through the schema,
    the API, the CLI and the store, and widening it for one scanner would be a
    schema change to express something ``directory`` already says. ``image`` is
    NOT claimed -- the container scanner owns image targets, and wiring it to
    hand its layer contents here is a follow-up (ADR-0025).
    """

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "binary"
    view: View = _VIEW

    SUPPORTED_KINDS = frozenset({"directory"})

    def supports(self, target: Target) -> bool:
        return target.kind in self.SUPPORTED_KINDS

    # -- coverage --------------------------------------------------------

    def coverage(self, path: Path, _ctx: ScanContext) -> CoverageReport:
        """What could be read in one binary. See :class:`CoverageReport`.

        Takes a ``ScanContext`` it does not currently use, so the signature
        matches :meth:`scan` and stays stable when a coverage check needs a
        knowledge pack -- a per-format expectation table, say.
        """
        lief = _import_lief()
        binary = _parse(lief, path)
        if binary is None:
            return CoverageReport(
                path=str(path),
                format="unknown",
                stripped=False,
                imported_symbols=0,
                exported_symbols=0,
                sections=0,
                techniques=tuple(TECHNIQUE_CONFIDENCE),
                limitations=(
                    f"{path.name} could not be parsed as an ELF or PE binary, so "
                    "NOTHING was read from it. This is not a clean result.",
                ),
            )

        imported = list(_imported_names(binary))
        exported = [s.name for s in getattr(binary, "exported_symbols", [])]
        stripped = not _static_symbols(binary)

        limitations: list[str] = []
        if stripped:
            limitations.append(
                "the static symbol table has been removed (strip): local and "
                "statically linked cryptographic routines are invisible, and "
                "the symbol technique can only see what is still imported "
                "dynamically. The finding count here is a FLOOR, not a total."
            )
        if not imported:
            limitations.append(
                "the binary imports no symbols at all, so it is statically "
                "linked or has no dynamic dependencies: the strongest technique "
                "contributes nothing and only byte-level evidence (constants, "
                "OIDs, embedded PEM, version banners) is available."
            )
        return CoverageReport(
            path=str(path),
            format=str(getattr(binary, "format", "unknown")).rsplit(".", 1)[-1],
            stripped=stripped,
            imported_symbols=len(imported),
            exported_symbols=len(exported),
            sections=len(getattr(binary, "sections", [])),
            techniques=tuple(TECHNIQUE_CONFIDENCE),
            limitations=tuple(limitations),
        )

    # -- scanning --------------------------------------------------------

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        lief = _import_lief()
        packs = _packs(ctx.knowledge_dir)
        root = Path(target.ref)

        for path in _candidates(root):
            binary = _parse(lief, path)
            if binary is None:
                # Somebody else's data, and it may be hostile or truncated. Log
                # it with the reason and carry on: one unreadable file must not
                # end a scan of a directory (ADR-0003).
                _log.warning(
                    "binary_unparseable: %s (not a readable ELF or PE)",
                    path,
                    extra={"event": "binary_unparseable", "path": str(path)},
                )
                continue

            report = self.coverage(path, ctx)
            if report.limitations:
                for note in report.limitations:
                    _log.info(
                        "binary_coverage_limited: %s -- %s",
                        path,
                        note,
                        extra={"event": "binary_coverage_limited", "path": str(path)},
                    )

            try:
                data = path.read_bytes()
            except OSError as exc:  # pragma: no cover - permissions
                _log.warning("binary_unreadable: %s (%s)", path, exc)
                continue

            yield from _symbol_findings(binary, path, packs)
            yield from _pem_findings(data, path)
            yield from _oid_findings(data, path, packs)
            yield from _version_findings(data, path, packs)
            yield from _constant_findings(data, path, packs)


# ---------------------------------------------------------------------------
# Walking and parsing
# ---------------------------------------------------------------------------


def _candidates(root: Path) -> list[Path]:
    """Every file under ``root`` that starts with a binary magic number.

    Sorted, so the CBOM never depends on filesystem walk order.
    """
    if root.is_file():
        return [root] if _looks_binary(root) else []
    if not root.is_dir():
        return []

    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.parts):
            continue
        try:
            if path.stat().st_size > MAX_BINARY_BYTES:
                continue
        except OSError:
            continue
        if _looks_binary(path):
            found.append(path)
    return sorted(found)


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return (
        head.startswith(_ELF_MAGIC)
        or head.startswith(_PE_MAGIC)
        or head in _MACHO_MAGICS
    )


def _parse(lief: Any, path: Path) -> Any:
    """A parsed binary, or ``None`` when the file is not really one.

    LIEF returns a degenerate object rather than ``None`` for a truncated
    header -- an ELF with an invalid class and no sections -- so "did it
    parse?" is answered by whether the result has any structure, not by whether
    a call returned something.
    """
    try:
        binary = lief.parse(str(path))
    except Exception:
        return None
    if binary is None:
        return None
    if not getattr(binary, "sections", None):
        return None
    return binary


def _static_symbols(binary: Any) -> list[Any]:
    """The `.symtab` entries, which `strip` removes and `.dynsym` survives.

    LIEF renamed this accessor between major versions -- 0.x called it
    `static_symbols`, 1.x calls it `symtab_symbols` -- and a `getattr` default
    of `[]` over the wrong name reports EVERY binary as stripped. That is the
    worst possible direction for this particular field to fail in: it would
    make the scanner claim degraded coverage it does not have, and a reader who
    checked one unstripped binary would stop trusting the flag. Both names are
    tried, and the pin in requirements.txt says why the version matters.
    """
    for accessor in ("symtab_symbols", "static_symbols"):
        symbols = getattr(binary, accessor, None)
        if symbols is None:
            continue
        try:
            return list(symbols)
        except Exception as exc:  # an accessor may raise on a partial file
            _log.debug(
                "symbol_table_unreadable via %s (%s)",
                accessor,
                type(exc).__name__,
                extra={"event": "symbol_table_unreadable", "accessor": accessor},
            )
            continue
    return []


def _imported_names(binary: Any) -> Iterator[str]:
    """Imported symbol names, from ELF and PE, with version suffixes stripped."""
    seen: set[str] = set()
    for symbol in getattr(binary, "imported_symbols", []) or ():
        name = _VERSION_SUFFIX.sub("", str(symbol.name))
        if name and name not in seen:
            seen.add(name)
            yield name
    # PE keeps its imports under `imports` (one entry per DLL), not under
    # `imported_symbols`.
    for library in getattr(binary, "imports", []) or ():
        for entry in getattr(library, "entries", []) or ():
            name = _VERSION_SUFFIX.sub("", str(getattr(entry, "name", "") or ""))
            if name and name not in seen:
                seen.add(name)
                yield name


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _finding(
    *,
    path: Path,
    technique: str,
    locus: str,
    algorithm: str,
    primitive: str,
    usage: str,
    asset_type: str = "algorithm",
    params: dict[str, Any] | None = None,
    snippet: str | None = None,
    detail: str,
    raw: dict[str, Any] | None = None,
) -> Finding:
    """One binary finding, with its technique and confidence attached.

    ``configurable`` is always False. Changing what a compiled binary does
    means rebuilding it, which is exactly the migration-effort statement
    ADR-0008 wants -- a config edit and a rebuild are not the same cost.
    """
    extra: dict[str, Any] = {"technique": technique, "binary": path.name}
    extra.update(raw or {})
    return Finding(
        scanner_id="binary",
        view=_VIEW,
        asset_type=_as_asset_type(asset_type),
        primitive=_as_primitive(primitive),
        algorithm=algorithm,
        params=dict(params or {}),
        usage=_as_usage(usage),
        configurable=False,
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view=_VIEW,
                    locator=f"{path}#{locus}",
                    detail=detail,
                    snippet=snippet,
                )
            ]
        ),
        confidence=TECHNIQUE_CONFIDENCE[technique],
        raw=extra,
    )


def _as_asset_type(value: str) -> AssetType:
    return value  # type: ignore[return-value]


def _as_primitive(value: str) -> Primitive:
    return value  # type: ignore[return-value]


def _as_usage(value: str) -> Usage:
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Technique: SYMBOLS (0.90)
# ---------------------------------------------------------------------------


def _symbol_findings(binary: Any, path: Path, packs: _Packs) -> Iterator[Finding]:
    """The strongest technique: the linker resolved this named API.

    Still not 1.0 -- a resolved import is not a reached call site, and a
    library that imports a symbol on one code path imports it for every path.
    """
    for name in sorted(set(_imported_names(binary))):
        entry = packs.symbols.get(name)
        if entry is None:
            continue
        yield _finding(
            path=path,
            technique="symbol",
            locus=name,
            algorithm=str(entry["algorithm"]),
            primitive=str(entry["primitive"]),
            usage=str(entry["usage"]),
            params=dict(entry.get("params") or {}),
            detail=f"symbol={name}",
            snippet=f"imported symbol {name}",
            raw={
                "symbol": name,
                "library": entry.get("library"),
                "knowledge_source": entry.get("note"),
            },
        )


# ---------------------------------------------------------------------------
# Technique: EMBEDDED PEM (0.95)
# ---------------------------------------------------------------------------


def _pem_findings(data: bytes, path: Path) -> Iterator[Finding]:
    """Embedded certificates and keys.

    The only technique here that genuinely PARSES rather than infers -- a DER
    blob decodes to a certificate or it does not -- which is why it carries the
    highest confidence in the pack. It is still below 1.0: present in the image
    is not in use at runtime, and a build may embed a certificate it never
    loads.

    A PRIVATE KEY is recorded by presence and a fingerprint of its own bytes.
    The bytes themselves never enter a Finding, and the fingerprint is a digest
    rather than any part of the key, so it identifies the artefact across scans
    without carrying it.
    """
    for match in _PEM_BLOCK.finditer(data):
        label = match.group(1).decode("ascii", "replace").strip()
        offset = match.start()
        body = match.group(0)

        if any(marker in label for marker in _PRIVATE_LABELS):
            digest = hashlib.blake2b(body, digest_size=16).hexdigest()
            yield _finding(
                path=path,
                technique="pem",
                locus=f"offset+{offset}",
                algorithm="unknown",
                primitive="unknown",
                usage="unknown",
                asset_type="key",
                params={"pem_label": label, "fingerprint": digest},
                snippet=REDACTED,
                detail=f"pem={label}",
                raw={"pem_label": label},
            )
            continue

        yield from _certificate_finding(body, label, offset, path)


def _certificate_finding(
    body: bytes, label: str, offset: int, path: Path
) -> Iterator[Finding]:
    """A parsed certificate, or an honest "present but unparsed"."""
    parsed = _parse_certificate(body)
    if parsed is None:
        yield _finding(
            path=path,
            technique="pem",
            locus=f"offset+{offset}",
            algorithm="unknown",
            primitive="unknown",
            usage="unknown",
            asset_type="certificate",
            params={"pem_label": label, "resolved": False},
            # Redacted even though a certificate is public: a snippet is not a
            # place for a blob, and the fields worth having are in `params`.
            snippet=REDACTED,
            detail=f"pem={label} (unparsed)",
            raw={"pem_label": label},
        )
        return

    yield _finding(
        path=path,
        technique="pem",
        locus=f"offset+{offset}",
        algorithm=parsed["algorithm"],
        primitive=parsed["primitive"],
        usage="unknown",
        asset_type="certificate",
        params={
            key: value
            for key, value in parsed.items()
            if key not in {"algorithm", "primitive"}
        },
        snippet=REDACTED,
        detail=f"pem={label}",
        raw={"pem_label": label},
    )


def _parse_certificate(body: bytes) -> dict[str, Any] | None:
    """Subject, validity and public-key facts, or ``None`` if it will not parse."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        certificate = x509.load_pem_x509_certificate(body)
    except Exception:
        return None

    public_key = certificate.public_key()
    facts: dict[str, Any] = {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial": f"{certificate.serial_number:x}",
        "valid_from": certificate.not_valid_before_utc.date().isoformat(),
        "valid_to": certificate.not_valid_after_utc.date().isoformat(),
    }
    signature_algorithm = getattr(certificate.signature_hash_algorithm, "name", None)
    if signature_algorithm:
        facts["signature_hash"] = signature_algorithm

    if isinstance(public_key, rsa.RSAPublicKey):
        facts["key_size"] = public_key.key_size
        return {"algorithm": "RSA", "primitive": "pke", **facts}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        facts["curve"] = public_key.curve.name
        facts["key_size"] = public_key.curve.key_size
        return {"algorithm": "EC", "primitive": "unknown", **facts}
    return {"algorithm": "unknown", "primitive": "unknown", **facts}


# ---------------------------------------------------------------------------
# Technique: OIDs (0.85)
# ---------------------------------------------------------------------------


def _oid_findings(data: bytes, path: Path, packs: _Packs) -> Iterator[Finding]:
    """ASN.1 algorithm identifiers found verbatim in the image.

    Below a symbol on purpose. The bytes are unambiguous -- nothing else
    encodes to the same OID TLV -- but their presence means the binary can NAME
    the algorithm, not that it uses it: a TLS library ships the whole table
    whether or not any of it is reached.
    """
    for encoded, entry in packs.oids:
        offset = data.find(encoded)
        if offset < 0:
            continue
        yield _finding(
            path=path,
            technique="oid",
            locus=f"offset+{offset}",
            algorithm=str(entry["algorithm"]),
            primitive=str(entry["primitive"]),
            usage=str(entry["usage"]),
            params=dict(entry.get("params") or {}),
            detail=f"oid={entry['oid']}",
            snippet=f"DER OID {entry['oid']} ({entry.get('name', '')})".strip(),
            raw={
                "oid": str(entry["oid"]),
                "oid_name": entry.get("name"),
                "knowledge_source": entry.get("note"),
            },
        )


# ---------------------------------------------------------------------------
# Technique: VERSION STRINGS (0.80)
# ---------------------------------------------------------------------------


def _version_findings(data: bytes, path: Path, packs: _Packs) -> Iterator[Finding]:
    """A library banner, cross-referenced against the same pack the container
    scanner uses.

    Reading the banner rather than merely recording it is the point: the
    version is what decides whether the shipped library can do ML-KEM at all,
    and `knowledge/libraries.yaml` already holds that floor with its citation
    and its verified flag (ADR-0017). An unverified floor produces no
    capability verdict, exactly as it does for an image.
    """
    for library, pattern in _VERSION_BANNERS:
        match = pattern.search(data)
        if match is None:
            continue
        version = match.group(1).decode("ascii", "replace")
        params: dict[str, Any] = {"version": version, "library": library}

        fact = packs.libraries.get(library.lower())
        if fact is not None:
            capable = is_pqc_capable(fact, version)
            if capable is not None:
                params["pqc_capable"] = capable
            if fact.eol is not None:
                params["eol"] = fact.eol

        yield _finding(
            path=path,
            technique="version-string",
            locus=f"offset+{match.start()}",
            algorithm=library,
            primitive="unknown",
            usage="unknown",
            asset_type="library",
            params=params,
            detail=f"version-banner={library} {version}",
            snippet=match.group(0).decode("ascii", "replace"),
            raw={
                "library": library,
                "version": version,
                "knowledge_source": getattr(fact, "source", None),
            },
        )


# ---------------------------------------------------------------------------
# Technique: CONSTANTS (0.60)
# ---------------------------------------------------------------------------


def _constant_findings(data: bytes, path: Path, packs: _Packs) -> Iterator[Finding]:
    """Well-known constant tables -- the weakest technique, and deliberately so.

    A constant table is the only evidence that survives a statically linked,
    stripped binary, which is why it exists at all. It is also the one that can
    be wrong: 32 bytes of a substitution table can appear in a codec or a
    compression dictionary, and finding them proves the code is PRESENT, never
    that it runs. Hence 0.6, fixed -- a longer match of the same table is the
    same evidence.
    """
    for pattern, entry in packs.constants:
        offset = data.find(pattern)
        if offset < 0:
            continue
        yield _finding(
            path=path,
            technique="constant",
            locus=f"offset+{offset}",
            algorithm=str(entry["algorithm"]),
            primitive=str(entry["primitive"]),
            usage=str(entry["usage"]),
            detail=f"constant={entry['name']}",
            snippet=f"{entry['name']} table at offset {offset}",
            raw={
                "constant": str(entry["name"]),
                "endianness": entry.get("endianness"),
                "knowledge_source": entry.get("note"),
            },
        )
