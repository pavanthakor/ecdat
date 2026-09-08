"""A scanner that detects nothing.

TEMPORARY. This plugin exists only to prove the pipe end to end -- scanner ->
finding -> normaliser -> CBOM -> store -> API -- before any real detection
exists. It looks at nothing, reads nothing, and returns the same hand-written
RSA-2048 finding for every target.

DELETE THIS PACKAGE when Scanner A (source scanning) lands. Nothing outside
tests and the CLI/API default scanner list should ever depend on it.
"""

from __future__ import annotations

from collections.abc import Iterator

from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence, View

__all__ = ["StubScanner"]


class StubScanner:
    """Yields one fixed finding, whatever it is pointed at."""

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "stub"
    view: View = "declared"

    def supports(self, target: Target) -> bool:  # noqa: ARG002 - detects nothing
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:  # noqa: ARG002
        yield Finding(
            scanner_id=self.id,
            view="declared",
            asset_type="algorithm",
            primitive="signature",
            algorithm="RSA",
            params={"key_size": 2048},
            usage="sign",
            configurable=False,
            evidence=Evidence(
                occurrences=[
                    Occurrence(
                        view="declared",
                        locator="stub/example.py:1",
                        detail="rule=stub-fixed-finding@0",
                        snippet="private_key.sign(payload, PKCS1v15(), SHA256())",
                    )
                ]
            ),
            confidence=1.0,
            raw={"note": "fixed finding from the stub scanner; not a detection"},
        )
