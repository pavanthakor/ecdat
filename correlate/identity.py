"""Cross-view identity: which components are talking about the same thing.

ADR-0002 keeps a declared, a shipped and an observed sighting of one algorithm
as three separate components, deliberately -- merging them would destroy the
disagreement drift detection exists to find. This module does the opposite job:
it decides which of those separate components are *about the same endpoint*, so
they can be compared without being merged.

**The primary axis is config-declared against observed.** A config file says
what a service should negotiate; a handshake says what it did. That is the
story, and both are endpoint-oriented, so they correlate on
``(system, endpoint, role)``.

**Source-code declared findings are a SECONDARY signal.** `rsa.generate_private_key`
in `app/keys.py` is not attached to a listening socket; it correlates on
``(system, role)`` only, and answers a different question -- declared versus
shipped -- rather than the config-versus-runtime one.

**Components that share no key are simply uncorrelated.** They are reported as
coverage, never forced together. A join invented to produce a comparison is a
comparison nobody should believe.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ANY_ENDPOINT",
    "Correlated",
    "CorrelationKey",
    "component_params",
    "component_view",
    "group_components",
]

#: Stand-in endpoint for a view that does not name one.
#:
#: The observed view does not know which listening socket it belongs to -- a
#: uprobe sees a process and a thread, not an nginx server block. Rather than
#: refuse to correlate at all, such a component joins every endpoint in its
#: system. That is a deliberate over-join, and its limit is stated in ADR-0012:
#: when a system exposes several endpoints with DIFFERENT configurations, an
#: unattributed observation cannot be assigned to one of them, and the
#: correlator says so rather than picking.
ANY_ENDPOINT = "*"

#: Roles that participate in the config-vs-runtime join. Everything else is
#: correlated on system and role alone.
_TLS_ROLE = "tls"

#: Views, in the order a report should read them.
VIEW_ORDER = ("declared", "shipped", "observed")


@dataclass(frozen=True, slots=True)
class CorrelationKey:
    """What makes two components comparable."""

    system: str
    endpoint: str
    role: str

    def compatible(self, other: CorrelationKey) -> bool:
        """Whether two keys describe the same thing.

        ``ANY_ENDPOINT`` matches any endpoint in the same system and role --
        that is what lets an observed handshake reach the config that produced
        it.
        """
        if self.system != other.system or self.role != other.role:
            return False
        return ANY_ENDPOINT in (self.endpoint, other.endpoint) or (
            self.endpoint == other.endpoint
        )


@dataclass
class Correlated:
    """Every component that is about one endpoint, split by view."""

    key: CorrelationKey
    declared: list[Mapping[str, Any]] = field(default_factory=list)
    shipped: list[Mapping[str, Any]] = field(default_factory=list)
    observed: list[Mapping[str, Any]] = field(default_factory=list)

    def by_view(self, view: str) -> list[Mapping[str, Any]]:
        return {
            "declared": self.declared,
            "shipped": self.shipped,
            "observed": self.observed,
        }[view]

    @property
    def views(self) -> set[str]:
        return {v for v in VIEW_ORDER if self.by_view(v)}

    @property
    def missing_views(self) -> set[str]:
        """Reported as COVERAGE. Never as drift -- see ADR-0012."""
        return set(VIEW_ORDER) - self.views

    @property
    def is_complete(self) -> bool:
        return not self.missing_views


def component_params(component: Mapping[str, Any]) -> dict[str, str]:
    """``ecdat:param:X`` properties as a plain mapping."""
    return {
        prop["name"].removeprefix("ecdat:param:"): prop["value"]
        for prop in component.get("properties", [])
        if prop.get("name", "").startswith("ecdat:param:")
    }


def component_view(component: Mapping[str, Any]) -> str | None:
    for prop in component.get("properties", []):
        if prop.get("name") == "ecdat:view":
            value = str(prop["value"])
            return value if value in VIEW_ORDER else None
    return None


def _is_source_declared(params: Mapping[str, str]) -> bool:
    """Whether a declared component came from source code rather than config.

    Source findings carry a file:line locator and no endpoint; a config finding
    names the socket it configures. The distinction matters because only the
    latter is comparable with a handshake -- ``rsa.generate_private_key`` in
    ``app/keys.py`` is not attached to a listening port.
    """
    return "endpoint" not in params


def correlation_key(component: Mapping[str, Any], system: str) -> CorrelationKey | None:
    """The key a component correlates on, or None if it correlates on nothing."""
    view = component_view(component)
    if view is None:
        return None

    params = component_params(component)
    role = params.get("role", _TLS_ROLE)
    # Peer is deliberately NOT part of the key: ADR-0002's _drop_position folds
    # client and server into one component, so which peer drifted is read from
    # the occurrence detail instead (see correlate.drift.peers_from).
    role = role.removesuffix("-server").removesuffix("-client") or _TLS_ROLE

    endpoint = params.get("endpoint")
    if endpoint is None and view == "declared" and _is_source_declared(params):
        # Source-code declared: a secondary signal, correlated on system+role.
        endpoint = ANY_ENDPOINT
    return CorrelationKey(system=system, endpoint=endpoint or ANY_ENDPOINT, role=role)


def group_components(
    components: Iterable[Mapping[str, Any]], system: str
) -> list[Correlated]:
    """Group components into comparable sets, deterministically.

    Concrete endpoints get their own group. A component that names no endpoint
    joins every concrete group for its role -- and, when there are none, forms
    a group of its own so a single-view scan is still reported as coverage.
    """
    keyed: list[tuple[CorrelationKey, Mapping[str, Any]]] = []
    for component in components:
        key = correlation_key(component, system)
        if key is not None:
            keyed.append((key, component))

    concrete = sorted(
        {key.endpoint for key, _ in keyed if key.endpoint != ANY_ENDPOINT}
    )
    roles = sorted({key.role for key, _ in keyed})

    groups: dict[CorrelationKey, Correlated] = {}

    def bucket(key: CorrelationKey) -> Correlated:
        return groups.setdefault(key, Correlated(key=key))

    for role in roles:
        for endpoint in concrete or [ANY_ENDPOINT]:
            bucket(CorrelationKey(system=system, endpoint=endpoint, role=role))

    for key, component in keyed:
        view = component_view(component)
        assert view is not None  # noqa: S101 - keyed only holds viewed components
        for group_key, group in groups.items():
            if group_key.compatible(key):
                group.by_view(view).append(component)

    # Sorted twice over, because determinism has two enemies here: the order
    # groups were created in, and the order components appeared in the
    # document. Evidence lists are built from these, so an unsorted group makes
    # the output depend on scanner ordering.
    for group in groups.values():
        for view in VIEW_ORDER:
            group.by_view(view).sort(
                key=lambda c: str(c.get("bom-ref", c.get("name", "")))
            )
    return [groups[key] for key in sorted(groups, key=lambda k: (k.role, k.endpoint))]


def sort_components(components: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Components in a stable order, for deterministic reporting."""
    return sorted(components, key=lambda c: str(c.get("bom-ref", c.get("name", ""))))
