"""nginx fix templates: retired protocol versions, and a classical-only group.

Both edit exactly one directive inside the ``server {}`` block the finding came
from, because that is the scope the config scanner attributed it to. A fix that
rewrote the whole file, or that added a directive at the top of ``http {}``,
would silently change endpoints nobody asked about -- and ADR-0013 built the
block-aware parser precisely so a directive is never confused about which
listener it belongs to.
"""

from __future__ import annotations

from core.scanner import Target
from core.schema import Finding
from correlate.fixit.patch import make_unified_diff
from correlate.fixit.template import (
    Precondition,
    check_site,
    read_site,
    rewrite_directive,
    site_of,
)

__all__ = ["AddHybridGroup", "WeakProtocol"]

#: Protocol versions no current guidance permits for new traffic.
WEAK_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

#: What ``ssl_protocols`` becomes. TLS 1.3 only, rather than "1.2 and 1.3":
#: TLS 1.2 still negotiates static-RSA-era cipher suites and has no hybrid key
#: exchange, so a roadmap-driven fix that stopped at 1.2 would need doing again.
TARGET_PROTOCOL = "TLSv1.3"

#: The hybrid group. X25519MLKEM768 combines X25519 with ML-KEM-768, so it is
#: no weaker than today's classical exchange even if ML-KEM is broken -- which
#: is what makes it deployable now rather than after the transition.
HYBRID_GROUP = "X25519MLKEM768"


def _is_nginx(finding: Finding) -> bool:
    return finding.scanner_id == "config" and finding.raw.get("format") == "nginx"


class WeakProtocol:
    """``ssl_protocols`` naming a retired version -> TLS 1.3 only."""

    id: str = "nginx-weak-protocol"
    scanner_to_reverify: str = "config"
    source: str = (
        "NIST SP 800-52 Rev. 2 s3.1 (TLS 1.2 minimum; TLS 1.3 recommended); "
        "RFC 8996 (TLS 1.0 and 1.1 are deprecated, MUST NOT be used); "
        "RFC 8446 for TLS 1.3. nginx directive: ssl_protocols."
    )

    def matches(self, finding: Finding) -> bool:
        if not _is_nginx(finding) or finding.asset_type != "protocol":
            return False
        declared = str(finding.params.get("versions", ""))
        # Exact tokens, never a substring test: "TLSv1" is a prefix of
        # "TLSv1.3", and a prefix match here would report a modern endpoint as
        # broken and then "fix" it.
        return bool(WEAK_VERSIONS & {v.strip() for v in declared.split(",")})

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        verdict, site, text = check_site(finding, target, expect="ssl_protocols")
        if not verdict.ok or site is None or text is None:
            return verdict
        line = text.splitlines()[site.line - 1]
        if rewrite_directive(line, TARGET_PROTOCOL) is None:
            return Precondition.refused(
                f"{site.relative_path}:{site.line} is not a single-line nginx "
                f"directive, so its value cannot be replaced in place"
            )
        return Precondition.met()

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = site_of(finding, target)
        text = read_site(target, site) if site is not None else None
        if site is None or text is None:  # pragma: no cover - preconditions ran
            return ""
        lines = text.splitlines()
        replacement = rewrite_directive(lines[site.line - 1], TARGET_PROTOCOL)
        if replacement is None:  # pragma: no cover - preconditions ran
            return ""
        lines[site.line - 1] = replacement
        new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return make_unified_diff(site.relative_path, text, new)


class AddHybridGroup:
    """``ssl_ecdh_curve`` offering only classical groups -> hybrid ML-KEM.

    Fires only where a group is already declared. An endpoint with no
    ``ssl_ecdh_curve`` at all produces no key-agreement finding, so there is
    nothing to attach a fix to -- and inventing a directive for a block ECDAT
    never inspected is exactly the guess this tool refuses to make.
    """

    id: str = "nginx-add-hybrid-group"
    scanner_to_reverify: str = "config"
    source: str = (
        "NIST FIPS 203 (ML-KEM); OpenSSL 3.5.0 CHANGES.md (2025-04-08) ships "
        "ML-KEM and the X25519MLKEM768 hybrid group; "
        "draft-kwiatkowski-tls-ecdhe-mlkem defines the group for TLS 1.3. "
        "The shipped OpenSSL floor is knowledge/libraries.yaml "
        "(OpenSSL pqc_capable_from: 3.5.0)."
    )

    def matches(self, finding: Finding) -> bool:
        return (
            _is_nginx(finding)
            and finding.primitive == "key-agreement"
            and finding.params.get("hybrid") is False
        )

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        verdict, site, text = check_site(finding, target, expect="ssl_ecdh_curve")
        if not verdict.ok or site is None or text is None:
            return verdict
        line = text.splitlines()[site.line - 1]
        if HYBRID_GROUP in line:
            return Precondition.refused(
                f"{site.relative_path}:{site.line} already offers {HYBRID_GROUP}"
            )
        if rewrite_directive(line, HYBRID_GROUP) is None:
            return Precondition.refused(
                f"{site.relative_path}:{site.line} is not a single-line nginx "
                f"directive, so its value cannot be replaced in place"
            )
        return Precondition.met()

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = site_of(finding, target)
        text = read_site(target, site) if site is not None else None
        if site is None or text is None:  # pragma: no cover - preconditions ran
            return ""
        lines = text.splitlines()
        replacement = rewrite_directive(lines[site.line - 1], HYBRID_GROUP)
        if replacement is None:  # pragma: no cover - preconditions ran
            return ""
        lines[site.line - 1] = replacement
        new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return make_unified_diff(site.relative_path, text, new)
