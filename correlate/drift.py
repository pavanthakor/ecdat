"""The drift rules: where the three views disagree, and why.

Four rules, ordered by how much has to be true for them to fire. R1 leads
because it is the most reliable finding in the whole tool: a config asking for
a post-quantum group against a shipped OpenSSL that has no ML-KEM compiled into
it is provably broken from the image alone, with nothing running and no
handshake to catch.

Two rules bind every rule here, and both are about not lying:

* **A missing view is a COVERAGE GAP, never drift.** Telling an operator their
  config disagrees with runtime when there is no runtime observation at all is
  the fastest way to make the whole report ignorable. Absence is reported as
  absence.
* **A partial observation yields a weaker claim, not a hard one.** When the
  process never asked libssl for its negotiated group (ADR-0011), the honest
  finding is "declared hybrid, observed UNCONFIRMED" -- a real signal at lower
  confidence. Calling it a downgrade would be a false positive of exactly the
  kind that teaches people to disbelieve a tool.

Peer attribution comes from the EVIDENCE, not the identity. ADR-0002's
``_drop_position`` folds a client and a server on one host into a single
component, so "the server negotiated classical" is read from the occurrence
detail rather than from which component matched.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from correlate.identity import Correlated, component_params

__all__ = [
    "KIND_CIPHER_OUTSIDE_SET",
    "KIND_DECLARED_PQC_OBSERVED_CLASSICAL",
    "KIND_DECLARED_PQC_UNCONFIRMED",
    "KIND_PROTOCOL_DOWNGRADE",
    "KIND_SHIPPED_CANNOT_DO_DECLARED",
    "Drift",
    "detect",
]

KIND_SHIPPED_CANNOT_DO_DECLARED = "shipped-cannot-do-declared"
KIND_DECLARED_PQC_OBSERVED_CLASSICAL = "declared-pqc-observed-classical"
KIND_DECLARED_PQC_UNCONFIRMED = "declared-pqc-observed-unconfirmed"
KIND_PROTOCOL_DOWNGRADE = "protocol-downgrade"
KIND_CIPHER_OUTSIDE_SET = "cipher-outside-declared-set"

#: Confidence for a claim backed by two positive observations, versus one
#: backed by an absence. The gap is what stops the honest-partial signal from
#: being read as a hard finding.
_CONFIDENCE_CONFIRMED = 1.0
_CONFIDENCE_UNCONFIRMED = 0.5

#: Post-quantum markers in a group label, matching ADR-0011's table.
_PQ_MARKERS = ("MLKEM", "ML-KEM", "KYBER", "FRODO", "BIKE", "HQC")

#: TLS versions in ascending order, so "below the declared minimum" is a
#: comparison rather than a string test.
_TLS_ORDER = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")

#: ML-KEM arrived in OpenSSL 3.5.0 (FIPS 203). knowledge/libraries.yaml is the
#: authority; this is only used to phrase the cause when the pack's floor is
#: not carried on the component.
_PQC_FLOOR_HINT = "3.5.0"


@dataclass(frozen=True, slots=True)
class Drift:
    """One disagreement between views, with both sides and the cause."""

    kind: str
    #: The bom-ref of the component the drift is written onto -- the one whose
    #: stated intent is not being met.
    affected: str
    declared: str
    observed: str
    cause: str
    #: ``(view, locator)`` for each contributing view. A drift claim that
    #: cannot cite a sighting from each side is not a claim.
    evidence: tuple[tuple[str, str], ...] = ()
    #: Which peers were seen doing it, from the occurrence detail.
    peers: tuple[str, ...] = ()
    confidence: float = _CONFIDENCE_CONFIRMED


def _is_hybrid(params: Mapping[str, str], name: str) -> bool:
    """Whether this key exchange is post-quantum hybrid.

    An EXPLICIT ``hybrid`` flag is authoritative in both directions. The name
    heuristic is only a fallback for components that carry no flag -- letting
    it override a stated ``False`` would mean a scanner could not correct us.
    """
    stated = params.get("hybrid", "").lower()
    if stated in ("true", "false"):
        return stated == "true"
    label = f"{params.get('group', '')} {name}".upper()
    return any(marker in label for marker in _PQ_MARKERS)


def _version_rank(version: str) -> int | None:
    normalised = version.strip().replace("TLS ", "TLSv").replace("_", ".")
    for index, known in enumerate(_TLS_ORDER):
        if normalised.lower() == known.lower():
            return index
    return None


def _locator(component: Mapping[str, Any]) -> str:
    occurrences = component.get("evidence", {}).get("occurrences", [])
    return str(occurrences[0].get("location", "?")) if occurrences else "?"


def peers_from(components: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    """Which processes were seen, read from occurrence detail.

    Client and server on one host fold into one component (ADR-0002), so this
    is the only place the peer survives. The snippet the agent writes is
    ``"<comm> via <libssl path>"``, appended to the detail by the normaliser.
    """
    peers: list[str] = []
    for component in components:
        for occurrence in component.get("evidence", {}).get("occurrences", []):
            context = str(occurrence.get("additionalContext", ""))
            match = re.search(r"::\s*(\S+)\s+via\s", context)
            if match and match.group(1) not in peers:
                peers.append(match.group(1))
    return tuple(peers)


def _evidence(*groups: Sequence[Mapping[str, Any]]) -> tuple[tuple[str, str], ...]:
    from correlate.identity import component_view

    cited: list[tuple[str, str]] = []
    for components in groups:
        for component in components:
            view = component_view(component) or "unknown"
            entry = (view, _locator(component))
            if entry not in cited:
                cited.append(entry)
    return tuple(cited)


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


def _r1_shipped_cannot_do_declared(group: Correlated) -> list[Drift]:
    """A hybrid group is configured; the shipped library cannot provide it.

    Leads, because it needs nothing running. A repo and an image are enough.
    """
    libraries = [
        c
        for c in group.shipped
        if component_params(c).get("version")
        and component_params(c).get("pqc_capable") is not None
    ]
    if not libraries:
        # pqc_capable ABSENT means the knowledge pack does not know (ADR-0006).
        # Unknown is not incapable, and must not produce a finding.
        return []

    drifts: list[Drift] = []
    for declared in group.declared:
        params = component_params(declared)
        if not _is_hybrid(params, str(declared.get("name", ""))):
            continue
        wanted = params.get("group") or str(declared.get("name", ""))

        for library in libraries:
            library_params = component_params(library)
            if library_params.get("pqc_capable", "").lower() != "false":
                continue
            version = library_params.get("version", "?")
            name = library.get("name", "the shipped library")
            drifts.append(
                Drift(
                    kind=KIND_SHIPPED_CANNOT_DO_DECLARED,
                    affected=str(declared.get("bom-ref", "")),
                    declared=wanted,
                    observed=f"{name} {version} (not PQC-capable)",
                    cause=(
                        f"shipped {name} {version} lacks ML-KEM, which arrived "
                        f"in {name} {_PQC_FLOOR_HINT}; the configured group "
                        f"{wanted} cannot be negotiated by this build"
                    ),
                    evidence=_evidence([declared], [library]),
                )
            )
    return drifts


def _observed_group_state(group: Correlated) -> tuple[str | None, bool]:
    """``(group name, was it actually read)`` for the observed key exchange."""
    partial = False
    for component in group.observed:
        params = component_params(component)
        name = params.get("group")
        if name:
            return name, True
        if params.get("enrichment") in ("partial", "none"):
            partial = True
    return None, not partial


def _r2_declared_pqc_versus_observed(group: Correlated) -> list[Drift]:
    """The headline. Needs a live handshake."""
    if not group.observed:
        return []

    hybrid_declarations = [
        c
        for c in group.declared
        if _is_hybrid(component_params(c), str(c.get("name", "")))
    ]
    if not hybrid_declarations:
        return []

    observed_name, was_read = _observed_group_state(group)
    peers = peers_from(group.observed)
    drifts: list[Drift] = []

    for declared in hybrid_declarations:
        params = component_params(declared)
        wanted = params.get("group") or str(declared.get("name", ""))

        if observed_name is None:
            if was_read:
                # Nothing observed and nothing said about it: no claim.
                continue
            # HONEST PARTIAL. The process never asked libssl for its group, so
            # we know a handshake happened and NOT what it agreed. Saying
            # "downgrade" here would be a false positive.
            drifts.append(
                Drift(
                    kind=KIND_DECLARED_PQC_UNCONFIRMED,
                    affected=str(declared.get("bom-ref", "")),
                    declared=wanted,
                    observed="unconfirmed (group not read)",
                    cause=(
                        f"{wanted} is configured and a handshake was observed, "
                        "but the process never asked libssl which group it "
                        "negotiated, so the group could not be confirmed. This "
                        "is NOT evidence of a downgrade -- it is evidence the "
                        "configuration is unverified at runtime."
                    ),
                    evidence=_evidence([declared], group.observed),
                    peers=peers,
                    confidence=_CONFIDENCE_UNCONFIRMED,
                )
            )
            continue

        if _is_hybrid({"group": observed_name}, observed_name):
            continue

        drifts.append(
            Drift(
                kind=KIND_DECLARED_PQC_OBSERVED_CLASSICAL,
                affected=str(declared.get("bom-ref", "")),
                declared=wanted,
                observed=observed_name,
                cause=(
                    f"the configuration declares the hybrid post-quantum group "
                    f"{wanted}, but the observed handshake negotiated "
                    f"{observed_name}, which is classical. Traffic protected by "
                    "this endpoint is exposed to harvest-now-decrypt-later "
                    "despite the configuration."
                ),
                evidence=_evidence([declared], group.observed),
                peers=peers,
            )
        )
    return drifts


def _r3_protocol_downgrade(group: Correlated) -> list[Drift]:
    observed_versions = [
        (component_params(c).get("version"), c)
        for c in group.observed
        if component_params(c).get("version")
    ]
    if not observed_versions:
        return []

    drifts: list[Drift] = []
    for declared in group.declared:
        params = component_params(declared)
        minimum = params.get("min_version") or params.get("version")
        if not minimum:
            continue
        floor = _version_rank(minimum)
        if floor is None:
            continue

        for version, component in observed_versions:
            rank = _version_rank(str(version))
            if rank is None or rank >= floor:
                continue
            drifts.append(
                Drift(
                    kind=KIND_PROTOCOL_DOWNGRADE,
                    affected=str(declared.get("bom-ref", "")),
                    declared=minimum,
                    observed=str(version),
                    cause=(
                        f"the configuration requires {minimum} or better, but "
                        f"the observed handshake negotiated {version}"
                    ),
                    evidence=_evidence([declared], [component]),
                    peers=peers_from([component]),
                )
            )
    return drifts


def _r4_cipher_outside_set(group: Correlated) -> list[Drift]:
    observed_suites = [
        (component_params(c).get("cipher_suite"), c)
        for c in group.observed
        if component_params(c).get("cipher_suite")
    ]
    if not observed_suites:
        return []

    drifts: list[Drift] = []
    for declared in group.declared:
        raw = component_params(declared).get("cipher_suites")
        if not raw:
            continue
        allowed = {part.strip() for part in raw.split(",") if part.strip()}
        if not allowed:
            continue

        for suite, component in observed_suites:
            if suite in allowed:
                continue
            drifts.append(
                Drift(
                    kind=KIND_CIPHER_OUTSIDE_SET,
                    affected=str(declared.get("bom-ref", "")),
                    declared=", ".join(sorted(allowed)),
                    observed=str(suite),
                    cause=(
                        f"the observed handshake negotiated {suite}, which is "
                        "not in the configured cipher suite list"
                    ),
                    evidence=_evidence([declared], [component]),
                    peers=peers_from([component]),
                )
            )
    return drifts


#: In report order. R1 leads: it is the most reliable and needs nothing running.
_RULES = (
    _r1_shipped_cannot_do_declared,
    _r2_declared_pqc_versus_observed,
    _r3_protocol_downgrade,
    _r4_cipher_outside_set,
)


def detect(group: Correlated) -> list[Drift]:
    """Every disagreement in one correlated group, in rule order.

    Returns ``[]`` for a group with a missing view. That is not a silent
    failure -- ``Correlated.missing_views`` reports it as coverage, and
    conflating "we did not look" with "they disagree" is the error this whole
    module is arranged to avoid.
    """
    found: list[Drift] = []
    for rule in _RULES:
        found.extend(rule(group))
    return found
