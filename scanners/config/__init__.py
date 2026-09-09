"""Scanner E -- configuration files: the endpoint-oriented declared view.

ADR-0012 made config-declared against observed the primary drift axis and then
had to admit nothing produced the config side. This is that producer, and it is
what lets R2/R3/R4 run against a real parser rather than hand-built components.

**Parsers, not Semgrep.** The source scanner's rule-pack design is right for
code, where the interesting thing is a call site and the grammar is enormous.
Config is the opposite: small, structured grammars where the interesting thing
is a *directive inside a block*. Semgrep's generic mode would match text without
understanding nesting, and nesting is exactly what carries the endpoint.

**The endpoint is the join key.** ``ssl_ecdh_curve X25519MLKEM768`` inside
``server { listen 443; }`` is a fact about that endpoint and no other. A parser
that attributed it to the file would silently ruin the correlator's join while
every other test still passed, which is why the endpoint is in the answer key
and why the fixture has two server blocks with different crypto.

**Global configs get a scope marker, not a fake endpoint.** sshd and
openssl.cnf apply to a daemon or a whole system, so they carry
``sshd@<system>`` / ``openssl@<system>``. Inventing ``:22`` for sshd would let
it be joined against an unrelated TLS handshake.

Read-only and offline: it opens files and parses text.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from core.logs import get_logger
from core.scanner import ScanContext, Target
from core.schema import AssetType, Evidence, Finding, Occurrence, Primitive, View
from scanners.config.nginx import ServerBlock, parse_nginx
from scanners.config.openssl_cnf import parse_openssl_cnf
from scanners.config.sshd import parse_sshd

__all__ = ["ConfigScanner", "canonical_group", "global_scope"]

_log = get_logger("scanner.config")

#: Filenames and shapes this scanner recognises. Kept explicit rather than
#: "any .conf": walking a repo and parsing everything that ends in .conf as
#: nginx would produce confident nonsense.
NGINX_NAMES = ("nginx.conf",)
NGINX_DIRS = ("conf.d", "sites-available", "sites-enabled", "snippets")
SSHD_NAMES = ("sshd_config",)
OPENSSL_NAMES = ("openssl.cnf", "openssl.conf")

#: Directories never worth walking.
_SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__", "vendor"})

#: A file larger than this is not a config file we wrote a parser for.
MAX_CONFIG_BYTES = 4 * 1024 * 1024

#: Post-quantum markers in a group label. Deliberately the SAME table as
#: ADR-0011's observed side: a declared hybrid and an observed hybrid must
#: agree about being hybrid, or the correlator compares two different ideas.
_PQ_MARKERS = ("MLKEM", "ML-KEM", "KYBER", "FRODO", "BIKE", "HQC")

#: Group-name aliases -> the spelling OpenSSL itself reports, because that is
#: what the observed view carries (ADR-0011 reads SSL_group_to_name).
_GROUP_ALIASES = {
    "P-256": "prime256v1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
    "X25519": "x25519",
    "X448": "x448",
}

_VIEW: View = "declared"


def global_scope(daemon: str, system: str | None) -> str:
    """The scope marker for a config with no per-endpoint block.

    Deliberately not shaped like ``host:port``: sshd applies to a daemon, and
    letting it look like an endpoint would let the correlator join it against
    a TLS handshake it has nothing to do with.
    """
    return f"{daemon}@{system or 'system'}"


def canonical_group(name: str) -> str:
    """A group name in the spelling the observed view will report.

    The join in ADR-0012 compares these as strings, so a declared ``P-256`` and
    an observed ``prime256v1`` must become the same token or the comparison
    silently never matches.
    """
    cleaned = name.strip()
    return _GROUP_ALIASES.get(cleaned.upper(), cleaned)


def _is_hybrid(group: str) -> bool:
    return any(marker in group.upper() for marker in _PQ_MARKERS)


def _lowest_version(versions: list[str]) -> str | None:
    order = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
    ranked = [v for v in order if v in versions]
    return ranked[0] if ranked else (versions[0] if versions else None)


class ConfigScanner:
    """Reads TLS/SSH policy out of configuration files (ADR-0013)."""

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "config"
    view: View = "declared"

    SUPPORTED_KINDS = frozenset({"repo", "directory"})

    def supports(self, target: Target) -> bool:
        return target.kind in self.SUPPORTED_KINDS

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:  # noqa: ARG002
        root = Path(target.ref)
        if not root.is_dir():
            return

        # Sorted, so the CBOM does not depend on filesystem walk order.
        for path in sorted(self._config_files(root)):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                _log.warning(
                    "config_unreadable: %s (%s)",
                    path,
                    exc,
                    extra={"event": "config_unreadable", "path": str(path)},
                )
                continue

            name = path.name
            if name in SSHD_NAMES:
                yield from self._from_sshd(text, path, target)
            elif name in OPENSSL_NAMES:
                yield from self._from_openssl(text, path, target)
            else:
                yield from self._from_nginx(text, path)

    def _config_files(self, root: Path) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file() or _SKIP_DIRS & set(path.parts):
                continue
            try:
                if path.stat().st_size > MAX_CONFIG_BYTES:
                    continue
            except OSError:
                continue

            name = path.name
            if (
                name in SSHD_NAMES
                or name in OPENSSL_NAMES
                or name in NGINX_NAMES
                or (path.suffix == ".conf" and set(path.parts) & set(NGINX_DIRS))
            ):
                yield path

    # -- construction ----------------------------------------------------

    def _finding(
        self,
        *,
        asset_type: AssetType,
        primitive: Primitive,
        algorithm: str,
        params: dict[str, Any],
        path: Path,
        line: int,
        detail: str,
        snippet: str,
    ) -> Finding:
        return Finding(
            scanner_id=self.id,
            view=_VIEW,
            asset_type=asset_type,
            primitive=primitive,
            algorithm=algorithm,
            params=params,
            usage="unknown",
            # Config is by definition changeable without a code edit. This is
            # the one view where `configurable` is knowably True, and it feeds
            # the migration-effort estimate in ADR-0008.
            configurable=True,
            evidence=Evidence(
                occurrences=[
                    Occurrence(
                        view=_VIEW,
                        locator=f"{path}:{line}",
                        detail=detail,
                        snippet=snippet,
                    )
                ]
            ),
            confidence=1.0,
            raw={"format": detail.split()[0], "path": str(path)},
        )

    # -- nginx -----------------------------------------------------------

    def _from_nginx(self, text: str, path: Path) -> Iterator[Finding]:
        for block in parse_nginx(text):
            yield from self._from_nginx_block(block, path)

    def _from_nginx_block(self, block: ServerBlock, path: Path) -> Iterator[Finding]:
        endpoint = block.endpoint()
        directives = block.directives

        protocols = directives.get("ssl_protocols")
        ciphers = directives.get("ssl_ciphers")
        if protocols is not None or ciphers is not None:
            params: dict[str, Any] = {"endpoint": endpoint}
            line = 0
            if protocols is not None:
                versions = protocols[0].split()
                params["versions"] = ",".join(versions)
                minimum = _lowest_version(versions)
                if minimum:
                    params["min_version"] = minimum
                line = protocols[1]
            if ciphers is not None:
                # nginx separates with ':'; the CBOM (and R4) use ','.
                params["cipher_suites"] = ",".join(
                    part for part in ciphers[0].split(":") if part
                )
                line = line or ciphers[1]
            yield self._finding(
                asset_type="protocol",
                primitive="unknown",
                algorithm="TLS",
                params=params,
                path=path,
                line=line,
                detail="nginx ssl_protocols/ssl_ciphers",
                snippet=(protocols or ciphers or ("", 0))[0],
            )

        curve = directives.get("ssl_ecdh_curve")
        if curve is not None:
            # nginx allows a ':'-separated list; the first is what a peer that
            # supports it will get, and it is the declaration that matters.
            first = next(
                (part for part in curve[0].split(":") if part.strip()), curve[0]
            )
            group = canonical_group(first)
            yield self._finding(
                asset_type="algorithm",
                primitive="key-agreement",
                algorithm=group,
                params={
                    "endpoint": endpoint,
                    "group": group,
                    "hybrid": _is_hybrid(group),
                    "groups": ",".join(
                        canonical_group(p) for p in curve[0].split(":") if p.strip()
                    ),
                },
                path=path,
                line=curve[1],
                detail="nginx ssl_ecdh_curve",
                snippet=curve[0],
            )

        certificate = directives.get("ssl_certificate")
        if certificate is not None:
            yield self._finding(
                asset_type="certificate",
                primitive="unknown",
                algorithm="unknown",
                params={
                    "endpoint": endpoint,
                    "path": certificate[0],
                    # The file is referenced, not read: parsing it is the
                    # container scanner's job and it may not be in this tree.
                    "resolved": False,
                },
                path=path,
                line=certificate[1],
                detail="nginx ssl_certificate",
                snippet=certificate[0],
            )

    # -- sshd ------------------------------------------------------------

    def _from_sshd(self, text: str, path: Path, target: Target) -> Iterator[Finding]:
        endpoint = global_scope("sshd", target.system)
        for algorithm, primitive, value, line in parse_sshd(text):
            yield self._finding(
                asset_type="algorithm",
                primitive=primitive,  # type: ignore[arg-type]
                algorithm=algorithm,
                params={"endpoint": endpoint, "algorithms": value},
                path=path,
                line=line,
                detail="sshd_config",
                snippet=value,
            )

    # -- openssl.cnf -----------------------------------------------------

    def _from_openssl(self, text: str, path: Path, target: Target) -> Iterator[Finding]:
        endpoint = global_scope("openssl", target.system)
        entries = parse_openssl_cnf(text)

        groups = entries.get("groups")
        if groups is not None:
            first = next((p for p in groups[0].split(":") if p.strip()), groups[0])
            group = canonical_group(first)
            yield self._finding(
                asset_type="algorithm",
                primitive="key-agreement",
                algorithm=group,
                params={
                    "endpoint": endpoint,
                    "group": group,
                    "hybrid": _is_hybrid(group),
                    "groups": ",".join(
                        canonical_group(p) for p in groups[0].split(":") if p.strip()
                    ),
                },
                path=path,
                line=groups[1],
                detail="openssl.cnf Groups",
                snippet=groups[0],
            )

        minimum = entries.get("minprotocol")
        maximum = entries.get("maxprotocol")
        cipher_string = entries.get("cipherstring") or entries.get("ciphersuites")
        if minimum or maximum or cipher_string:
            params = {"endpoint": endpoint}
            line = 0
            if minimum:
                params["min_version"] = minimum[0]
                line = minimum[1]
            if maximum:
                params["max_version"] = maximum[0]
                line = line or maximum[1]
            if cipher_string:
                params["cipher_suites"] = ",".join(
                    p for p in cipher_string[0].split(":") if p
                )
                line = line or cipher_string[1]
            yield self._finding(
                asset_type="protocol",
                primitive="unknown",
                algorithm="TLS",
                params=params,
                path=path,
                line=line,
                detail="openssl.cnf system_default_sect",
                snippet=(minimum or maximum or cipher_string or ("", 0))[0],
            )
