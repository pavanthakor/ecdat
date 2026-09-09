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

__all__ = [
    "ENRICHMENT_FULL",
    "ENRICHMENT_NONE",
    "ENRICHMENT_PARTIAL",
    "PENDING_ENRICHMENT",
    "PROBE_NAME",
    "event_to_finding",
    "event_to_findings",
]

_log = get_logger("agent.mapping")

PROBE_NAME = "SSL_do_handshake"

#: Marks a finding whose enrichment fields were never read, as opposed to read
#: and found empty.
PENDING_ENRICHMENT = "pending_enrichment"

#: How much of the negotiated detail was actually read. Written onto every
#: observed finding, because "we did not read it" and "there was nothing to
#: read" are different claims and a reader must be able to tell them apart.
ENRICHMENT_FULL = "full"
ENRICHMENT_PARTIAL = "partial"
ENRICHMENT_NONE = "none"

#: A negotiated value longer than this is a bad read, not a long name. The
#: longest real TLS suite name is around 45 characters.
_MAX_ENRICHMENT_LEN = 96

#: Substrings that identify the symmetric primitive inside a TLS suite name.
#: Deliberately a short, explicit table: guessing a primitive from a name we do
#: not recognise would be exactly the invention this module refuses to make.
_SUITE_PRIMITIVES: tuple[tuple[str, str], ...] = (
    ("CHACHA20", "stream-cipher"),
    ("AES", "block-cipher"),
    ("CAMELLIA", "block-cipher"),
    ("ARIA", "block-cipher"),
    ("3DES", "block-cipher"),
    ("DES", "block-cipher"),
    ("RC4", "stream-cipher"),
    ("NULL", "unknown"),
)

#: Post-quantum names that appear inside a HYBRID group label. A group carrying
#: one of these is doing classical AND post-quantum key agreement together,
#: which is the state a migration is aiming for -- and the thing the correlator
#: compares a declared intent against.
_PQ_GROUP_MARKERS = ("MLKEM", "ML-KEM", "KYBER", "FRODO", "BIKE", "HQC")


def _clean_enrichment(value: Any, field: str) -> tuple[str | None, str | None]:
    """``(value, reason-it-was-refused)``. Never guesses, never raises.

    A value read from the wrong address is bytes, and bytes are not a cipher
    name. Anything non-printable, over-long, or of the wrong type is refused
    with a reason rather than passed on to be believed.
    """
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, f"{field} was {type(value).__name__}, expected a string"

    text = value.split("\x00", 1)[0].strip()
    if not text:
        return None, f"{field} was empty"
    if len(text) > _MAX_ENRICHMENT_LEN:
        return None, f"{field} was {len(text)} characters; a bad read, not a name"
    if not all(character in _PRINTABLE for character in text):
        return None, f"{field} contained non-printable bytes; a bad read"
    return text, None


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


def _finding(
    *,
    asset_type: AssetType,
    primitive: str,
    algorithm: str,
    params: dict[str, Any],
    usage: Usage,
    host: str,
    pid: int,
    detail: str,
    snippet: str,
    raw: dict[str, Any],
) -> Finding:
    """One observed artefact. All artefacts from one handshake share a locator."""
    return Finding(
        scanner_id="runtime",
        view=_VIEW,
        asset_type=asset_type,
        primitive=primitive,  # type: ignore[arg-type]
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
                    # Never a payload: the probe reads no plaintext, and there
                    # is no code path here by which one could arrive.
                    snippet=snippet,
                )
            ]
        ),
        # What was seen was directly observed. The uncertainty is about what was
        # NOT read, and that is carried by `enrichment` rather than by
        # discounting a fact we actually saw.
        confidence=1.0,
        raw=raw,
    )


def _suite_primitive(suite: str) -> str:
    upper = suite.upper()
    for marker, primitive in _SUITE_PRIMITIVES:
        if marker in upper:
            return primitive
    # Recognised as a suite, but not as one whose primitive we know. Saying
    # "unknown" is the honest answer; picking the most likely one is not.
    return "unknown"


def event_to_findings(event: Any, *, hostname: str | None = None) -> list[Finding]:
    """Every artefact one observed handshake reveals.

    A TLS handshake negotiates three separate cryptographic facts, and each is
    its own artefact in the CBOM:

    * the **protocol version** -- always emitted, because the handshake itself
      is the observation;
    * the **cipher suite** -- a symmetric artefact, emitted only when read;
    * the **key-exchange group** -- a key-agreement artefact, emitted only when
      read. This is the one the correlator's drift beat turns on: a repo that
      declares a hybrid post-quantum group against a process observed
      negotiating a classical one.

    Anything not cleanly readable is ABSENT and the reason is recorded. There
    is no code path here that produces a value we did not read.

    Returns ``[]`` -- never raises -- for an event that cannot be trusted at
    all, and logs why. The caller drains a kernel buffer in a loop; one bad
    record must cost one record, not the agent.
    """
    if not isinstance(event, dict):
        _skip(f"event is {type(event).__name__}, expected a dict")
        return []

    pid = _pid(event.get("pid"))
    if pid is None:
        _skip(f"pid {event.get('pid')!r} is not a plausible process id", field="pid")
        return []

    if "comm" not in event:
        _skip("comm is absent; the event struct was not fully read", field="comm")
        return []
    comm = _text(event.get("comm"), "comm")
    if comm is None:
        return []
    if not any(character in _PRINTABLE for character in comm):
        _skip(
            "comm contains no printable characters; the event struct looks misread",
            field="comm",
        )
        return []

    host = hostname if hostname is not None else socket.gethostname()
    libssl_path = _text(event.get("libssl_path"), "libssl_path") or "unknown"
    phase = _text(event.get("phase"), "phase") or "unknown"
    retval = event.get("retval")

    # Nothing is negotiated at entry, and nothing is agreed when the handshake
    # failed. Reporting a suite for either would be a claim the wire does not
    # support.
    negotiated = phase == "return" and retval == 1
    reasons: list[str] = []
    if not negotiated:
        reasons.append(
            "handshake had not completed successfully; nothing was negotiated"
            if phase != "return"
            else f"handshake returned {retval!r}; nothing was negotiated"
        )

    values: dict[str, str | None] = {}
    for field in ("observed_version", "observed_cipher", "observed_group"):
        raw_value = event.get(field) if negotiated else None
        cleaned, reason = _clean_enrichment(raw_value, field)
        if reason is not None and raw_value is not None:
            # A wrong-TYPE field means the record itself is untrustworthy; a
            # merely unreadable one is an honest gap.
            if not isinstance(raw_value, str):
                _skip(reason, field=field)
                return []
            reasons.append(reason)
        values[field] = cleaned

    version = values["observed_version"]
    suite = values["observed_cipher"]
    group = values["observed_group"]

    supplied_reason = _text(event.get("enrichment_reason"), "enrichment_reason")
    if supplied_reason:
        reasons.insert(0, supplied_reason)

    read = [v for v in (version, suite, group) if v]
    missing = [
        name
        for name, value in (("version", version), ("cipher", suite), ("group", group))
        if not value
    ]
    if len(read) == 3:
        enrichment = ENRICHMENT_FULL
    elif read:
        enrichment = ENRICHMENT_PARTIAL
        if not reasons:
            # A gap with no stated cause is still a gap, and a reader must not
            # have to guess whether it was unreadable or simply never asked for.
            reasons.append(
                f"{', '.join(missing)} not read: the process did not ask "
                "libssl for them"
            )
    else:
        enrichment = ENRICHMENT_NONE
        if negotiated and not reasons:
            reasons.append(
                "no accessor was called by the process, so libssl was never "
                "asked for the negotiated values"
            )

    shared: dict[str, Any] = {"enrichment": enrichment}
    if enrichment != ENRICHMENT_FULL and reasons:
        shared["enrichment_reason"] = "; ".join(dict.fromkeys(reasons))
    if enrichment == ENRICHMENT_NONE:
        shared[PENDING_ENRICHMENT] = True

    detail = (
        f"probe={PROBE_NAME} "
        f"observed_version={version or 'pending'} "
        f"observed_cipher={suite or 'pending'} "
        f"observed_group={group or 'pending'}"
    )
    snippet = f"{comm} via {libssl_path}"
    raw = {
        "probe": PROBE_NAME,
        "phase": phase,
        "comm": comm,
        "libssl_path": libssl_path,
        "enrichment": enrichment,
    }

    findings: list[Finding] = []

    protocol_params: dict[str, Any] = dict(shared)
    if version:
        protocol_params["version"] = version
    findings.append(
        _finding(
            asset_type="protocol",
            primitive="unknown",
            algorithm="TLS",
            params=protocol_params,
            usage="unknown",
            host=host,
            pid=pid,
            detail=detail,
            snippet=snippet,
            raw=raw,
        )
    )

    if suite:
        suite_params: dict[str, Any] = dict(shared)
        suite_params["cipher_suite"] = suite
        if version:
            suite_params["version"] = version
        findings.append(
            _finding(
                asset_type="algorithm",
                primitive=_suite_primitive(suite),
                algorithm=suite,
                params=suite_params,
                usage="encrypt",
                host=host,
                pid=pid,
                detail=detail,
                snippet=snippet,
                raw=raw,
            )
        )

    if group:
        group_params: dict[str, Any] = dict(shared)
        group_params["group"] = group
        if version:
            group_params["version"] = version
        if any(marker in group.upper() for marker in _PQ_GROUP_MARKERS):
            # A hybrid group is the migration's destination, and the fact the
            # correlator compares a declared intent against.
            group_params["hybrid"] = True
        findings.append(
            _finding(
                asset_type="algorithm",
                primitive="key-agreement",
                algorithm=group,
                params=group_params,
                usage="key-exchange",
                host=host,
                pid=pid,
                detail=detail,
                snippet=snippet,
                raw=raw,
            )
        )

    return findings


def event_to_finding(event: Any, *, hostname: str | None = None) -> Finding | None:
    """The PRINCIPAL artefact of one event -- the protocol -- or None.

    Kept for callers that want a single Finding. Use
    :func:`event_to_findings` to get the cipher and group artefacts too.
    """
    findings = event_to_findings(event, hostname=hostname)
    return findings[0] if findings else None
