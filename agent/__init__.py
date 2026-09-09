"""The ECDAT runtime agent: the `observed` view.

A separate process, not an in-process :class:`~core.scanner.Scanner`. It needs
root to attach eBPF probes, and the scan path deliberately does not. Wiring its
findings into the store and the correlator is a later slice; slice 1 proves one
probe attaches and delivers an event (ADR-0009).
"""

from __future__ import annotations

__all__: list[str] = []
