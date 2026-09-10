"""ECDAT core: the shared data contract every other package speaks (ADR-0001)."""

from __future__ import annotations

__all__ = ["ECDAT_VERSION"]

#: The tool's own version, recorded on every scan row alongside the engine
#: versions that produced it (ADR-0017). A stored CBOM should be able to say
#: which build of ECDAT reached its conclusions, not only which semgrep did.
ECDAT_VERSION = "0.1.0"
