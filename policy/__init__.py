"""Policy: scoring, bands and deadlines, expressed as signed data packs.

Scoring lives here and nowhere else. The normaliser records what IS
(ADR-0002) -- structural, definitional facts about an algorithm. This package
decides what that MEANS, which is an assessment, changes as guidance changes,
and must be re-runnable over an old CBOM without rescanning anything.
"""

from __future__ import annotations

__all__: list[str] = []
