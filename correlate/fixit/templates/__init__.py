"""The shipped fix templates. THIS IS THE LIST.

Adding a template is one import and one entry in :data:`DEFAULT_TEMPLATES` --
the same explicit-registration shape as ``core/registry.py``, and for the same
reason: a reader can answer "what can ECDAT fix?" by reading one block, and
mypy can see that every entry satisfies :class:`~correlate.fixit.template.
FixTemplate`.

**Why these five, and only these five.** A template ships when a *registered*
scanner can re-read the file it edits, because ADR-0015 verifies a fix by
re-scanning a sandbox copy rather than by trusting the template. The five here
are covered by three producers -- ``config`` parses nginx and ``openssl.cnf``,
``source`` runs the Python rule pack, ``deps`` reads dependency manifests -- so
each one's edit is confirmed by the same code that found the problem.

``dep-bump`` was absent until Scanner B (ADR-0021) gave it that producer, which
is the whole of what unblocked it. It arrives carrying a second gate of its own
(ADR-0022): a bump is proposed only to a ``pqc_capable_from`` the pack has
verified, so today it declines every library in the shipped pack. A template
that refuses is still a template that ships; one that cannot be re-verified is
not.

``dockerfile-base-bump`` is still deliberately absent. Nothing in ECDAT parses
a Dockerfile, so a diff bumping a base image could be generated but never
confirmed, and shipping an unverifiable fix would contradict the one decision
ADR-0015 exists to enforce. It stays in PUNCHLIST, blocked on its producer
scanner.
"""

from __future__ import annotations

from correlate.fixit.template import FixTemplate
from correlate.fixit.templates.dep_bump import DepBump
from correlate.fixit.templates.nginx import AddHybridGroup, WeakProtocol
from correlate.fixit.templates.openssl_cnf import OpenSslCnfGroups
from correlate.fixit.templates.source_md5 import Md5ToSha256

__all__ = ["DEFAULT_TEMPLATES"]

#: Ordered by id, so template selection cannot depend on import order. The
#: first match wins, and the ids are disjoint by construction: no two templates
#: below claim the same finding.
DEFAULT_TEMPLATES: tuple[FixTemplate, ...] = (
    DepBump(),
    Md5ToSha256(),
    AddHybridGroup(),
    WeakProtocol(),
    OpenSslCnfGroups(),
)
