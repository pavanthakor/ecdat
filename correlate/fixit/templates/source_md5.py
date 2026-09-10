"""``hashlib.md5(`` -> ``hashlib.sha256(``, but only where that is the fix.

This is the template that has to refuse most often, and refusing is the
feature. MD5 appears in three broadly different jobs and the correct
replacement differs in each:

* **integrity** -- a checksum over a file, a payload, a cache key. SHA-256 is a
  drop-in improvement and this template makes that edit.
* **password storage** -- SHA-256 is *also broken here*, just faster. The right
  answer is a memory-hard KDF (Argon2id, scrypt, PBKDF2), which is a change to
  the storage format and the verification path, not a one-token substitution.
  A one-line "fix" would look like remediation, close the finding, and leave
  the credentials exactly as recoverable as before.
* **anything else** -- unknown. ECDAT says so.

So the classification is deliberately asymmetric. A password marker is
DISQUALIFYING and is checked first: ``legacy_digest(password)`` contains both a
password marker and the word "digest", and it must be refused, not rewritten.
An integrity marker is REQUIRED to proceed, so the default for an unrecognised
call site is refusal rather than an edit. Pillar 3's whole claim is that a
recommendation is usage-aware; a fix that guessed usage would undo it.
"""

from __future__ import annotations

import re

from core.scanner import Target
from core.schema import Finding
from correlate.fixit.patch import make_unified_diff
from correlate.fixit.template import (
    Precondition,
    check_site,
    read_site,
    site_of,
)

__all__ = ["Md5ToSha256"]

CALL = "hashlib.md5("
REPLACEMENT = "hashlib.sha256("

#: Lines either side of the call site that count as its context. Wide enough to
#: catch the enclosing `def` and the variable the digest is assigned to,
#: narrow enough that an unrelated function below does not vote.
CONTEXT_BEFORE = 6
CONTEXT_AFTER = 2

#: Any of these in context means "this is a credential", and the template
#: declines. Checked BEFORE the integrity markers and beats them outright.
PASSWORD_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "credential",
    "login",
    "secret",
    "salt",
    "argon2",
    "bcrypt",
    "scrypt",
    "pbkdf2",
)

#: At least one of these must be in context for the edit to go ahead.
INTEGRITY_MARKERS = (
    "checksum",
    "digest",
    "etag",
    "fingerprint",
    "integrity",
    "content_hash",
    "cache_key",
    "manifest",
    "payload",
    "artefact",
    "artifact",
    "chunk",
)

#: ``.hexdigest()`` and ``.digest()`` are on essentially every MD5 line ever
#: written, so they carry no information about what the hash is FOR. Removed
#: before the integrity vote; a variable genuinely named ``digest`` survives.
_METHOD_NOISE = re.compile(r"\.(?:hex)?digest\s*\(")


def _context(text: str, line: int) -> str:
    lines = text.splitlines()
    start = max(0, line - 1 - CONTEXT_BEFORE)
    end = min(len(lines), line + CONTEXT_AFTER)
    return "\n".join(lines[start:end]).lower()


class Md5ToSha256:
    """Replace MD5 with SHA-256 where -- and only where -- MD5 is a checksum."""

    id: str = "md5-to-sha256"
    scanner_to_reverify: str = "source"
    source: str = (
        "RFC 6151 (MD5 collision attacks; MUST NOT be used where collision "
        "resistance is required); NIST SP 800-131A Rev. 2 Table 8 (MD5 "
        "disallowed); FIPS 180-4 for SHA-256. For the password case: NIST "
        "SP 800-63B s5.1.1.2 requires a memory-hard, salted, iterated KDF, "
        "which SHA-256 is not."
    )

    def matches(self, finding: Finding) -> bool:
        return (
            finding.scanner_id == "source"
            and finding.algorithm == "MD5"
            and finding.primitive == "hash"
        )

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        verdict, site, text = check_site(finding, target, expect=CALL)
        if not verdict.ok or site is None or text is None:
            # `expect` failing is the `hashlib.new("md5", ...)` form as well as
            # a moved line. Both are honest refusals: this template rewrites
            # one spelling and does not pretend to handle the other.
            return verdict

        context = _context(text, site.line)
        seen = [marker for marker in PASSWORD_MARKERS if marker in context]
        if seen:
            return Precondition.refused(
                f"not applicable: {site.relative_path}:{site.line} hashes what "
                f"looks like a password (context mentions {', '.join(seen)}). "
                f"Swapping MD5 for SHA-256 here would leave a fast unsalted "
                f"digest over a credential; password storage needs a "
                f"memory-hard KDF -- Argon2id, scrypt or PBKDF2 "
                f"(NIST SP 800-63B s5.1.1.2). ECDAT will not propose the "
                f"cheaper edit that merely closes the finding."
            )

        without_noise = _METHOD_NOISE.sub("(", context)
        if not any(marker in without_noise for marker in INTEGRITY_MARKERS):
            return Precondition.refused(
                f"not applicable: the usage of the MD5 call at "
                f"{site.relative_path}:{site.line} could not be determined from "
                f"its call site -- it names neither a credential nor an "
                f"integrity check. The correct replacement depends on that "
                f"usage, so ECDAT declines rather than guessing."
            )
        return Precondition.met()

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = site_of(finding, target)
        text = read_site(target, site) if site is not None else None
        if site is None or text is None:  # pragma: no cover - preconditions ran
            return ""
        lines = text.splitlines()
        # Only the cited line. A file with several MD5 calls yields several
        # findings, and each gets its own separately-verified fix.
        lines[site.line - 1] = lines[site.line - 1].replace(CALL, REPLACEMENT)
        new = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        return make_unified_diff(site.relative_path, text, new)
