"""Findings in, a validated CycloneDX 1.6 CBOM out.

This is the seam ADR-0001 describes: everything upstream speaks Finding,
everything downstream reads the CBOM. A document only leaves here if it
validates against the official CycloneDX 1.6 JSON schema shipped with
cyclonedx-python-lib, so no later slice has to wonder whether the store is
well-formed.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from core.cbom import build_cbom
from core.scanner import Target
from core.schema import Finding

__all__ = [
    "CbomValidationError",
    "SchemaValidationUnavailableError",
    "normalise",
    "serialise_cbom",
    "validate_cbom_json",
]

_SCHEMA_VERSION = SchemaVersion.V1_6
_INDENT = 2


class CbomValidationError(ValueError):
    """A produced document is not a valid CycloneDX 1.6 CBOM."""


class SchemaValidationUnavailableError(RuntimeError):
    """The schema validator itself could not run, so nothing was checked."""


def serialise_cbom(bom: Bom) -> str:
    """Render a Bom as CycloneDX 1.6 JSON, with a trailing newline."""
    outputter = make_outputter(bom, OutputFormat.JSON, _SCHEMA_VERSION)
    return outputter.output_as_string(indent=_INDENT) + "\n"


def validate_cbom_json(cbom_json: str) -> None:
    """Raise unless ``cbom_json`` validates against the official 1.6 schema."""
    try:
        errors = JsonStrictValidator(_SCHEMA_VERSION).validate_str(cbom_json)
    except MissingOptionalDependencyException as exc:  # pragma: no cover
        raise SchemaValidationUnavailableError(
            "CycloneDX schema validation requires the optional 'jsonschema' "
            "dependency: install cyclonedx-python-lib[validation]. Refusing to "
            "emit an unvalidated CBOM."
        ) from exc
    if errors is not None:
        raise CbomValidationError(
            f"produced document does not validate against CycloneDX 1.6: {errors}"
        )


def normalise(
    findings: Iterable[Finding],
    target: Target,
    *,
    serial_number: uuid.UUID | None = None,
    timestamp: datetime | None = None,
) -> tuple[Bom, str]:
    """Dedup, build, serialise and validate. Returns the Bom and its JSON."""
    bom = build_cbom(findings, target, serial_number=serial_number, timestamp=timestamp)
    cbom_json = serialise_cbom(bom)
    validate_cbom_json(cbom_json)
    return bom, cbom_json
