"""The shipped fix templates. THIS IS THE LIST.

Adding a template is one import and one entry in :data:`DEFAULT_TEMPLATES` --
the same explicit-registration shape as ``core/registry.py``, and for the same
reason: a reader can answer "what can ECDAT fix?" by reading one block, and
mypy can see that every entry satisfies :class:`~correlate.fixit.template.
FixTemplate`.

**Why these four, and only these four.** A template ships when a *registered*
scanner can re-read the file it edits, because ADR-0015 verifies a fix by
re-scanning a sandbox copy rather than by trusting the template. The four here
are covered by two producers -- ``config`` parses nginx and ``openssl.cnf``,
``source`` runs the Python rule pack -- so each one's edit is confirmed by the
same code that found the problem.

``dockerfile-base-bump`` and ``dep-bump`` are deliberately absent. Nothing in
ECDAT reads a Dockerfile or a dependency manifest yet (``scanners/deps`` is an
empty directory), so a diff bumping a base image or a pinned library version
could be generated but never confirmed. Shipping an unverifiable fix would
contradict the one decision this slice exists to enforce. Both are in
PUNCHLIST, blocked on their producer scanner.
"""

from __future__ import annotations

from correlate.fixit.template import FixTemplate
from correlate.fixit.templates.nginx import AddHybridGroup, WeakProtocol
from correlate.fixit.templates.openssl_cnf import OpenSslCnfGroups
from correlate.fixit.templates.source_md5 import Md5ToSha256

__all__ = ["DEFAULT_TEMPLATES"]

#: Ordered by id, so template selection cannot depend on import order. The
#: first match wins, and the ids are disjoint by construction: no two templates
#: below claim the same finding.
DEFAULT_TEMPLATES: tuple[FixTemplate, ...] = (
    Md5ToSha256(),
    AddHybridGroup(),
    WeakProtocol(),
    OpenSslCnfGroups(),
)
