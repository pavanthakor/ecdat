"""Probe event -> :class:`~core.schema.Finding`. Pure, and root-free.

Deliberately importable anywhere: no bcc, no privileges, no kernel. That is
what lets the mapping -- the part with actual logic in it -- be tested on a
laptop and in CI while the probe itself can only be proved by a human with sudo
on a real handshake (ADR-0009).

Two things this module is careful about.

**Garbage that parses.** Events arrive from a C struct read out of a kernel
buffer. A truncated read, a comm field with invalid UTF-8, a field this version
does not expect -- any of these can produce a dict that looks fine and is not.
A runtime agent that dies on one odd event stops observing, and a host that has
stopped being observed looks exactly like a host with no cryptography. So a
bad event is skipped with a logged reason and the agent keeps running.

**Absence is not a value.** The probe zero-fills the version and cipher fields
this slice, so an empty string means "not read", not "no version". Those
findings are marked ``pending_enrichment`` rather than being given an
``unknown`` that a later reader would mistake for an observation.
"""

from __future__ import annotations

import socket
from typing import Any

from core.logs import get_logger
from core.schema import AssetType, Evidence, Finding, Occurrence, Usage, View

__all__ = ["PENDING_ENRICHMENT", "PROBE_NAME", "event_to_finding"]

_log = get_logger("agent.mapping")

PROBE_NAME = "SSL_do_handshake"

#: Marks a finding whose enrichment fields were never read, as opposed to read
#: and found empty. Slice 2 removes it by actually reading them.
PENDING_ENRICHMENT = "pending_enrichment"

_VIEW: View = "observed"

#: Longest plausible value for a captured string field. A comm is 16 bytes and
#: a cipher suite name is well under this; anything longer is a bad read, not a
#: long name.
_MAX_FIELD_LEN = 128

#: Linux pids fit in this by default (/proc/sys/kernel/pid_max can be raised,
#: but not past 2^22 on 64-bit). A pid outside it is a misread struct.
_MAX_PID = 4_194_304

#: A real ``comm`` is ASCII -- the kernel copies it from the executable name.
#: A field with nothing printable in it is a misread struct, not an unusual
#: process name, and an event built on a misread struct should not be trusted
#: just because one of its other fields happened to survive.
_PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7F))


def _skip(reason: str, **fields: Any) -> None:
    """Log why an event was dropped.

    The reason goes in the MESSAGE as well as the structured extra: an operator
    watching this agent's stderr during a capture needs to read it, not query
    it.
    """
    _log.warning(
        "agent_event_skipped: %s",
        reason,
        extra={"event": "agent_event_skipped", "reason": reason, **fields},
    )


def _text(value: Any, field: str) -> str | None:
    """A clean, bounded string, or None if this field cannot be trusted.

    ``None`` in, ``None`` out and no log: absence is legitimate for the
    enrichment fields, and whether it is legitimate for a given field is the
    caller's judgement, not this function's.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        # A comm read out of a fixed-width C array is NUL-padded and holds
        # whatever the process was named, which is not guaranteed to be UTF-8.
        value = value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if not isinstance(value, str):
        _skip(f"{field} is {type(value).__name__}, expected a string", field=field)
        return None
    cleaned = value.split("\x00", 1)[0].strip()
    return cleaned[:_MAX_FIELD_LEN]


def _pid(value: Any) -> int | None:
    """A plausible process id, or None.

    ``bool`` is rejected explicitly: it is an ``int`` subclass, so ``True``
    would otherwise sail through as pid 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not 0 < value <= _MAX_PID:
        return None
    return value


def event_to_finding(event: Any, *, hostname: str | None = None) -> Finding | None:
    """Map one probe event to an observed Finding, or None if unusable.

    ``event`` is a decoded probe record -- nominally ``dict[str, Any]``, typed
    ``Any`` because it arrives from a kernel perf buffer and establishing that
    it really is a well-formed dict is this function's job, not its caller's
    precondition. Typing it as a dict would let mypy delete the very check the
    garbage-event tests exercise.

    Returns ``None`` -- never raises -- for an event that cannot be trusted, and
    logs why. The caller drains a kernel buffer in a loop; one bad record must
    cost one record, not the agent.

    ``hostname`` is injectable so the mapping stays deterministic under test;
    it defaults to this host.
    """
    if not isinstance(event, dict):
        _skip(f"event is {type(event).__name__}, expected a dict")
        return None

    pid = _pid(event.get("pid"))
    if pid is None:
        _skip(
            f"pid {event.get('pid')!r} is not a plausible process id",
            field="pid",
        )
        return None

    if "comm" not in event:
        _skip("comm is absent; the event struct was not fully read", field="comm")
        return None

    comm = _text(event.get("comm"), "comm")
    if comm is None:
        return None
    if not any(character in _PRINTABLE for character in comm):
        # Not a strange process name -- a misread struct. Dropping the whole
        # event is right: if comm is garbage, the other fields were read from
        # the same bytes and have no better claim to being correct.
        _skip(
            "comm contains no printable characters; the event struct looks misread",
            field="comm",
        )
        return None

    # Enrichment fields, for when slice 2 fills them in.
    #
    # Two different kinds of "nothing" have to stay apart here. A field of the
    # WRONG TYPE means the event cannot be trusted and the whole thing is
    # dropped. A field that is absent or EMPTY is the probe's zero-filled C
    # array -- not read, which is exactly what slice 1 expects, and not a
    # reason to discard a perfectly good handshake observation.
    enriched: dict[str, str | None] = {}
    for field in ("observed_version", "observed_cipher"):
        raw = event.get(field)
        if raw is not None and not isinstance(raw, str | bytes):
            _skip(f"{field} is {type(raw).__name__}, expected a string", field=field)
            return None
        enriched[field] = _text(raw, field) or None

    version = enriched["observed_version"]
    cipher = enriched["observed_cipher"]

    host = hostname if hostname is not None else socket.gethostname()
    libssl_path = _text(event.get("libssl_path"), "libssl_path") or "unknown"

    params: dict[str, Any] = {}
    asset_type: AssetType = "protocol"
    algorithm = "TLS"
    usage: Usage = "unknown"

    if version is not None:
        params["version"] = version
    if cipher is not None:
        # A negotiated suite names concrete primitives, so it is an algorithm
        # asset rather than a bare protocol observation.
        asset_type = "algorithm"
        algorithm = cipher
        params["cipher_suite"] = cipher
        usage = "key-exchange"
    if version is None and cipher is None:
        params[PENDING_ENRICHMENT] = True

    detail = (
        f"probe={PROBE_NAME} "
        f"observed_version={version or 'pending'} "
        f"observed_cipher={cipher or 'pending'}"
    )

    return Finding(
        scanner_id="runtime",
        view=_VIEW,
        asset_type=asset_type,
        primitive="unknown",
        algorithm=algorithm,
        params=params,
        usage=usage,
        # A negotiated protocol is not a code-level choice, so "hard-coded" and
        # "configurable" are both wrong. Unknown is the honest answer.
        configurable=None,
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view=_VIEW,
                    locator=f"host:{host}:pid{pid}",
                    detail=detail,
                    # Never a payload: the probe reads none, and there is no
                    # code path here by which one could arrive.
                    snippet=f"{comm} via {libssl_path}",
                )
            ]
        ),
        # The handshake itself was directly observed, so the claim "a TLS
        # handshake happened here" is certain. The uncertainty in this slice is
        # about what was NOT read, and that is carried by pending_enrichment
        # rather than by discounting a fact we actually saw.
        confidence=1.0,
        raw={
            "probe": PROBE_NAME,
            "phase": _text(event.get("phase"), "phase") or "unknown",
            "comm": comm,
            "libssl_path": libssl_path,
        },
    )
