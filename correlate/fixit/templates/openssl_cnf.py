"""``openssl.cnf`` fix template: the system-wide TLS policy.

One template, two directives, because they are one decision. ``Groups`` and
``MinProtocol`` both live in ``[system_default_sect]`` and both describe what
every OpenSSL-linked process on the host will negotiate; splitting them into
two templates would mean two fixes racing to edit the same section.

**Scope, not endpoint.** ADR-0013 gives this file the scope marker
``openssl@<system>`` rather than a ``host:port``, so a fix here is a statement
about the whole machine. That is why ``Groups`` is *prepended to* rather than
*replaced with* the hybrid group: a system-wide policy that suddenly offers one
group would break every peer that cannot speak it.
"""

from __future__ import annotations

from core.scanner import Target
from core.schema import Finding
from correlate.fixit.patch import make_unified_diff
from correlate.fixit.template import (
    Precondition,
    check_site,
    read_site,
    rewrite_assignment,
    site_of,
)

__all__ = ["OpenSslCnfGroups"]

HYBRID_GROUP = "X25519MLKEM768"
MINIMUM_PROTOCOL = "TLSv1.2"

#: Versions below the floor NIST SP 800-52 Rev. 2 sets.
WEAK_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

_GROUPS = "Groups"
_MIN_PROTOCOL = "MinProtocol"


def _is_openssl_cnf(finding: Finding) -> bool:
    return finding.scanner_id == "config" and finding.raw.get("format") == "openssl.cnf"


def _directive_for(finding: Finding) -> str | None:
    """Which of the two directives this finding is about, if either."""
    if finding.primitive == "key-agreement" and finding.params.get("hybrid") is False:
        return _GROUPS
    if (
        finding.asset_type == "protocol"
        and str(finding.params.get("min_version", "")) in WEAK_VERSIONS
    ):
        return _MIN_PROTOCOL
    return None


def _new_group_list(existing: str) -> str:
    """The hybrid group first, then everything already offered, de-duplicated.

    Order is the preference order OpenSSL sends, so putting the hybrid group
    first is what makes it actually get negotiated; keeping the rest is what
    stops the fix from being an outage.
    """
    groups = [part.strip() for part in existing.split(":") if part.strip()]
    ordered = [HYBRID_GROUP]
    ordered.extend(group for group in groups if group != HYBRID_GROUP)
    return ":".join(ordered)


class OpenSslCnfGroups:
    """Raise ``MinProtocol``, or put a hybrid group at the head of ``Groups``."""

    id: str = "openssl-cnf-groups"
    scanner_to_reverify: str = "config"
    source: str = (
        "NIST FIPS 203 (ML-KEM); OpenSSL 3.5.0 CHANGES.md (2025-04-08) for "
        "ML-KEM and the X25519MLKEM768 group; NIST SP 800-52 Rev. 2 s3.1 and "
        "RFC 8996 for the TLS 1.2 floor. Directives: Groups and MinProtocol in "
        "the OpenSSL ssl_conf system_default section."
    )

    def matches(self, finding: Finding) -> bool:
        return _is_openssl_cnf(finding) and _directive_for(finding) is not None

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        directive = _directive_for(finding)
        if directive is None:  # pragma: no cover - matches() ran first
            return Precondition.refused("this finding names neither directive")

        verdict, site, text = check_site(finding, target, expect=directive)
        if not verdict.ok or site is None or text is None:
            return verdict

        line = text.splitlines()[site.line - 1]
        value = (
            _new_group_list(line.partition("=")[2])
            if directive == _GROUPS
            else MINIMUM_PROTOCOL
        )
        replacement = rewrite_assignment(line, value)
        if replacement is None:
            return Precondition.refused(
                f"{site.relative_path}:{site.line} is not a 'Key = value' line"
            )
        if replacement == line:
            return Precondition.refused(
                f"{site.relative_path}:{site.line} already satisfies this fix"
            )
        return Precondition.met()

    def make_diff(self, finding: Finding, target: Target) -> str:
        directive = _directive_for(finding)
        site = site_of(finding, target)
        text = read_site(target, site) if site is not None else None
        if directive is None or site is None or text is None:  # pragma: no cover
            return ""

        lines = text.splitlines()
        line = lines[site.line - 1]
        value = (
            _new_group_list(line.partition("=")[2])
            if directive == _GROUPS
            else MINIMUM_PROTOCOL
        )
        replacement = rewrite_assignment(line, value)
        if replacement is None:  # pragma: no cover - preconditions ran
            return ""
        lines[site.line - 1] = replacement
        new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return make_unified_diff(site.relative_path, text, new)
