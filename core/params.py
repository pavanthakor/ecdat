"""Canonical types for the params that identify an artefact (ADR-0029).

``Finding.params`` is deliberately untyped at the scanner layer: a scanner
reports what it saw, and the knowledge packs give meaning to the keys they care
about. But params are **identifying** -- they go into the blake2b digest that
becomes the CycloneDX ``bom-ref`` -- so two scanners that disagree about a
TYPE disagree about the artefact:

    key_size: 2048    (source scanner: ast.literal_eval gives an int)
    key_size: "2048"  (container scanner: read out of a version string)

Same RSA-2048, two bom-refs, an inventory that double-counts. Nothing made
those agree and nothing noticed, because both are plausible in isolation.

This module is the one place that says what a known param IS. The canonical
form is applied at the normaliser boundary, BEFORE ``finding_identity`` runs
(``core.cbom._group_findings``), so the digest is computed over canonical
values and the two spellings collapse.

**Two rules, and the second matters as much as the first.**

* A KNOWN param is coerced to its canonical type.
* An UNKNOWN param passes through **unchanged**. A param no pack has declared
  has no canonical type to coerce to, and guessing one would invent a fact --
  it would also make adding a param to a rule a change to ``core/``.

A value that will not coerce is **left as written**, never dropped and never
turned into ``None``. ``key_size: "unknown"`` is a real thing a scanner
reports; losing it would lose the fact, and raising would end a scan over
somebody else's malformed input.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["CANONICAL_TYPES", "CanonicalType", "canonicalise_params"]


@dataclass(frozen=True, slots=True)
class CanonicalType:
    """The canonical form of one param, and why it is that form."""

    #: Returns the canonical value, or raises for a value it cannot convert.
    #: Raising is how "leave it alone" is signalled -- see
    #: :func:`canonicalise_params`.
    coerce: Callable[[Any], Any]
    #: The reason this key has this type. Asserted non-empty by the tests: a
    #: table of coercions with no reasons is a table nobody can review.
    why: str


# ---------------------------------------------------------------------------
# Coercions
# ---------------------------------------------------------------------------


def _to_int(value: Any) -> int:
    if isinstance(value, bool):  # bool is an int subclass; not a key size
        raise TypeError("a boolean is not a key size")
    if isinstance(value, int):
        return value
    return int(str(value).strip())


def _to_upper(value: Any) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError("empty")
    return text.upper()


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "on"}:
        return True
    if text in {"false", "no", "0", "off"}:
        return False
    raise ValueError(f"not a boolean: {value!r}")


def _to_date(value: Any) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value).strip())


#: The many spellings one curve arrives under. OpenSSL says ``prime256v1``,
#: SECG says ``secp256r1``, NIST and the TLS registry say ``P-256``, and Java
#: says ``secp256r1`` too -- all the same curve, and four bom-refs without this.
#: NIST names are canonical because that is what the policy packs and NIST IR
#: 8547 are written in.
_CURVE_ALIASES = {
    "prime256v1": "P-256",
    "secp256r1": "P-256",
    "p256": "P-256",
    "p-256": "P-256",
    "nistp256": "P-256",
    "secp384r1": "P-384",
    "prime384v1": "P-384",
    "p384": "P-384",
    "p-384": "P-384",
    "nistp384": "P-384",
    "secp521r1": "P-521",
    "p521": "P-521",
    "p-521": "P-521",
    "nistp521": "P-521",
    "secp256k1": "secp256k1",
    "curve25519": "X25519",
    "x25519": "X25519",
    "ed25519": "Ed25519",
    "curve448": "X448",
    "x448": "X448",
    "ed448": "Ed448",
}


def _to_curve(value: Any) -> str:
    text = str(value).strip()
    canonical = _CURVE_ALIASES.get(text.lower())
    if canonical is None:
        # Not an alias this table knows. Keep the spelling rather than
        # inventing a normalisation: an unrecognised curve is a fact, and
        # mangling it would make it unrecognisable to a reviewer too.
        raise KeyError(text)
    return canonical


#: ``TLSv1.2``, ``tlsv1.2``, ``TLSV1_2`` -> ``TLSv1.2``. The underscore form is
#: what OpenSSL's ``PROTOCOL_TLSv1_2`` leaves behind after the source scanner
#: strips its prefix.
_VERSION = re.compile(r"^(TLS|SSL)V?(\d+)[._](\d+)$", re.IGNORECASE)
_VERSION_MAJOR = re.compile(r"^(TLS|SSL)V?(\d+)$", re.IGNORECASE)


def _to_version(value: Any) -> str:
    text = str(value).strip()
    match = _VERSION.match(text)
    if match:
        family, major, minor = match.groups()
        return f"{family.upper()}v{major}.{minor}"
    match = _VERSION_MAJOR.match(text)
    if match:
        family, major = match.groups()
        return f"{family.upper()}v{major}"
    raise KeyError(text)


# ---------------------------------------------------------------------------
# THE TABLE. One place. Extend it as the packs grow a param.
# ---------------------------------------------------------------------------

CANONICAL_TYPES: dict[str, CanonicalType] = {
    "key_size": CanonicalType(
        coerce=_to_int,
        why=(
            "int. The policy engine compares it numerically -- the symmetric "
            "rule in ADR-0029 is `key_size: {max: 128}` -- and a string makes "
            "that comparison silently never match. It is also the param most "
            "likely to arrive both ways: the source scanner literal-evals an "
            "int, everything reading text gets a str."
        ),
    ),
    "mode": CanonicalType(
        coerce=_to_upper,
        why=(
            "upper-case str. NIST SP 800-38A/38D name modes in capitals (GCM, "
            "CBC, ECB) and the packs match on those names; `gcm` from a Node "
            "suite string and `GCM` from a JCA transformation are one mode."
        ),
    ),
    "curve": CanonicalType(
        coerce=_to_curve,
        why=(
            "canonical NIST name. One curve has four common spellings -- "
            "prime256v1 (OpenSSL), secp256r1 (SECG/Java), P-256 (NIST, TLS "
            "registry) -- and without this the same key is four artefacts. "
            "NIST names are canonical because the policy packs and NIST IR "
            "8547 are written in them."
        ),
    ),
    "version": CanonicalType(
        coerce=_to_version,
        why=(
            "canonical protocol str. `TLSv1.2`, `tlsv1.2` and the `TLSv1_2` "
            "left by OpenSSL's PROTOCOL_ constants are one protocol version, "
            "and the TLS rules match on the RFC spelling."
        ),
    ),
    "valid_to": CanonicalType(
        coerce=_to_date,
        why=(
            "date. A certificate expiry is compared against a deadline, and "
            "comparing an ISO string to a date silently fails or throws "
            "depending on which side is which."
        ),
    ),
    "valid_from": CanonicalType(
        coerce=_to_date,
        why="date, for the same reason as valid_to.",
    ),
    "hybrid": CanonicalType(
        coerce=_to_bool,
        why=(
            "bool. Whether a key exchange carries a post-quantum half is a "
            'yes/no fact, and `"false"` is truthy in Python -- a string here '
            "would report every classical group as hybrid."
        ),
    ),
    "pqc_capable": CanonicalType(
        coerce=_to_bool,
        why="bool, for the same truthiness reason as hybrid.",
    ),
    "flagged": CanonicalType(
        coerce=_to_bool,
        why=(
            "bool. Set by the rule packs' `critical` flag and `mode_flags`, "
            "and read by the reports as a yes/no."
        ),
    ),
    "version_is_range": CanonicalType(
        coerce=_to_bool,
        why="bool. The deps scanner's honest-range marker (ADR-0021).",
    ),
}


def canonicalise_params(params: Mapping[str, Any]) -> dict[str, Any]:
    """Coerce known params to their canonical types; pass unknown ones through.

    Applied before :func:`core.identity.finding_identity`, so the identity hash
    is computed over canonical values and two spellings of one artefact become
    one component.

    Idempotent: a canonical value coerces to itself, which matters because a
    stored CBOM is re-normalised on a re-score.
    """
    canonical: dict[str, Any] = {}
    for name, value in params.items():
        entry = CANONICAL_TYPES.get(name)
        if entry is None:
            canonical[name] = value
            continue
        try:
            canonical[name] = entry.coerce(value)
        except (TypeError, ValueError, KeyError):
            # The value does not fit its canonical type. Keep it as written:
            # `key_size: "unknown"` is a real report, and losing it or raising
            # over it would be worse than an artefact that stays distinct.
            canonical[name] = value
    return canonical
