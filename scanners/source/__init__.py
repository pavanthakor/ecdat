"""Scanner A -- source crypto detection, with Semgrep as the engine.

The division of labour is the point of this design (ADR-0004):

* **Semgrep holds the matching.** It has the grammars, the pattern language
  and the performance work already done. ECDAT does not re-implement any of it.
* **The rule packs hold the knowledge.** ``knowledge/rules/<language>/*.yaml``
  carries the algorithm name, primitive, usage and cited quantum note for every
  pattern. Adding a detection means adding YAML, not Python -- and since
  ADR-0023, so does adding a LANGUAGE: semgrep is pointed at
  ``knowledge/rules/`` and each rule's own ``languages:`` decides which files
  it reads. Python, Go and JavaScript/TypeScript ship today.
* **This module holds nothing but the mapping.** Semgrep JSON in,
  :class:`~core.schema.Finding` out.

Semgrep runs as a subprocess over ``--json`` rather than through its Python
package. The CLI's JSON contract is stable across releases in a way the
internal API is not, and a subprocess keeps the scan path isolated: a
segfaulting matcher takes down a child process, not the scan.

**Offline.** Every invocation passes ``--metrics off`` and
``--disable-version-check``, and ``SEMGREP_SEND_METRICS=off`` is forced into the
child environment. The rule pack is a local directory, never a registry
identifier, so semgrep has no reason to open a socket. (Semgrep 1.176.1 has no
``--offline`` flag; ``--metrics off`` is the supported spelling.)

**Read-only.** The target is passed as a path to a subprocess that only reads.
Nothing here writes inside the target.

**No secret key material.** Snippets pass through :func:`_redact` on the way
out. Rules that match key material declare ``redact: true`` and lose their
snippet entirely; independently of that, any line carrying a PEM banner or a
long byte-string literal is redacted, because a rule about the *cipher* can
match the same line a key literal sits on. See PUNCHLIST #3.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast, get_args

from core.logs import get_logger
from core.scanner import CoverageGap, ScanContext, Target
from core.schema import (
    AssetType,
    Evidence,
    Finding,
    Occurrence,
    Primitive,
    Usage,
    View,
)

__all__ = [
    "PINNED_SEMGREP_VERSION",
    "RulePackContractError",
    "RulePackMissingError",
    "SemgrepFailedError",
    "SemgrepOutputError",
    "SemgrepUnavailableError",
    "SourceScanError",
    "SourceScanner",
]

_log = get_logger("source")

#: The id every source finding -- and every coverage gap -- carries.
SCANNER_ID = "source"

#: The semgrep executable. Module-level so tests can point it at nothing.
SEMGREP_BINARY = "semgrep"

#: The engine version this rule pack and its recall/precision fixtures were
#: scored against (ADR-0004, ADR-0017). ECDAT's determinism promise -- same
#: input + same knowledge packs -> byte-identical CBOM -- holds WITHIN a
#: matching engine and is not claimed across engines, because the matcher is an
#: external binary whose results can legitimately change between releases.
#:
#: requirements.txt pins this exact version and a test asserts the two agree.
#: A scan run against a different installed version is NOT refused -- a
#: teammate on a slightly different patch should not be blocked -- but the
#: mismatch is written onto the scan row, so a surprising result can be traced
#: to the engine that produced it rather than argued about.
PINNED_SEMGREP_VERSION = "1.176.1"

#: Where the rule packs live, relative to ``ScanContext.knowledge_dir``. The
#: directory holds one sub-pack per language (``python/``, ``go/``,
#: ``javascript/``) and semgrep is pointed at the parent, because every rule
#: already declares its own ``languages:`` and applies only to files of that
#: language. One config root rather than one per language means adding a
#: language is adding YAML, which is the promise knowledge/rules/README.md
#: makes (ADR-0023).
RULE_SUBDIR = Path("rules")

#: A whole-repo scan is minutes, not hours; past this something is wrong.
SEMGREP_TIMEOUT_SECONDS = 900

#: Every rule message starts with this. The message is the capture channel:
#: semgrep interpolates metavariables into ``message`` but not into
#: ``metadata``, and semgrep OSS emits no ``metavars`` block at all, so this is
#: the only way a rule can hand a captured value back. See knowledge/rules/README.md.
MESSAGE_PREFIX = "ecdat|"

#: What replaces a snippet that could carry key material. Asserted verbatim by
#: tests/test_scanner_source.py.
REDACTED = "<redacted key material>"

#: Params whose captured value is a symbolic constant (``modes.GCM(iv)``,
#: ``PROTOCOL_TLSv1``, ``ec.SECP256R1()``) rather than a plain literal.
_SYMBOL_PARAMS = frozenset({"mode", "curve", "version"})

#: Stripped from a normalised symbol: the library prefix is noise, the tail is
#: the fact. ``MODE_CBC`` -> ``CBC``, ``PROTOCOL_TLSv1`` -> ``TLSv1``.
_SYMBOL_PREFIXES = ("MODE_", "PROTOCOL_")

#: Confidence for a match whose captured value could not be resolved to a
#: constant. The detection is certain; the parameter is not.
_UNRESOLVED_CONFIDENCE = 0.6

#: A byte string at least this long is treated as possible key material. Eight
#: bytes is a DES key -- the shortest thing worth protecting.
_KEY_LITERAL_MIN_BYTES = 8

#: A LANGUAGE-NEUTRAL opaque blob: this many characters of unbroken
#: alphanumeric text inside a quoted literal, with no separator, space or
#: punctuation anywhere in it.
#:
#: Twenty-four, arrived at by what it must NOT eat rather than what it must
#: catch. Eight caught `PKCS5Padding`; sixteen caught `PBKDF2WithHmacSHA256`,
#: a real `SecretKeyFactory` argument. Twenty-four clears both and still
#: catches every key worth the name -- an AES-128 key is 32 hex characters and
#: 24 base64, an AES-256 key twice that.
_OPAQUE_LITERAL_MIN_CHARS = 24

_ASSET_TYPES = frozenset(get_args(AssetType))
_PRIMITIVES = frozenset(get_args(Primitive))
_USAGES = frozenset(get_args(Usage))

_BARE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PEM_BANNER = re.compile(r"-----BEGIN[A-Z0-9 ]*-----")
_BYTES_LITERAL = re.compile(
    r"(?:rb|br|b|RB|BR|B)(['\"])((?:\\.|(?!\1).)*)\1",
)

#: A quoted literal whose WHOLE content is one unbroken alphanumeric run,
#: optionally base64-padded. Anchored to the entire literal on purpose: a `/`,
#: `-`, `_`, `.` or space anywhere in it disqualifies the match, which is what
#: keeps JCA transformations ("AES/CBC/PKCS5Padding",
#: "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"), Node suite strings ("aes-256-gcm")
#: and prose out of it.
#:
#: `/` is deliberately NOT in the alphabet even though base64 uses it -- the
#: JCA transformation grammar is built on `/`, and protecting a slash-bearing
#: base64 key here would cost every Java cipher finding its evidence. Such a
#: key is still covered by its own rule's `redact: true`; this layer is the
#: backstop for the rule that does not know a key is there.
_OPAQUE_LITERAL = re.compile(
    rf"(['\"])([A-Za-z0-9+]{{{_OPAQUE_LITERAL_MIN_CHARS},}}={{0,2}})\1",
)


class SourceScanError(RuntimeError):
    """Base class for conditions that make a source scan impossible."""


class SemgrepUnavailableError(SourceScanError):
    """The semgrep binary is not on PATH."""


class SemgrepFailedError(SourceScanError):
    """Semgrep ran but exited with a failure status."""


class SemgrepOutputError(SourceScanError):
    """Semgrep produced something that is not the JSON document we expect."""


class RulePackMissingError(SourceScanError):
    """The Python rule pack is not where the knowledge directory says it is."""


class RulePackContractError(SourceScanError):
    """A rule's metadata does not satisfy the knowledge-pack contract."""


# ---------------------------------------------------------------------------
# Running semgrep
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def installed_semgrep_version() -> str | None:
    """The version of the semgrep on PATH, or ``None`` if there isn't one.

    Cached: this forks a process, and a scan should not pay for it twice.
    Returns ``None`` rather than raising -- a missing engine is reported on the
    scan row, and the scan itself fails later and more informatively when a
    scanner that actually needs semgrep tries to run it.
    """
    binary = shutil.which(SEMGREP_BINARY)
    if binary is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell, fixed binary
            [binary, "--version", "--disable-version-check"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    # `semgrep --version` prints the bare version on one line.
    first = completed.stdout.strip().splitlines()
    return first[0].strip() if first else None


def _run_semgrep(rules_dir: Path, target_path: Path) -> str:
    """Run semgrep over ``target_path`` with ``rules_dir`` and return stdout.

    Raises rather than returning empty output: a scanner that silently reports
    nothing because its engine is missing is worse than one that fails, because
    "no crypto found" is a conclusion someone will act on.
    """
    binary = shutil.which(SEMGREP_BINARY)
    if binary is None:
        raise SemgrepUnavailableError(
            f"the {SEMGREP_BINARY!r} binary is not on PATH; the source scanner "
            "cannot run. Install semgrep (pip install semgrep) or remove this "
            "scanner from the scan."
        )

    command = [
        binary,
        "scan",
        "--metrics",
        "off",  # no telemetry: the scan path makes no outbound calls
        "--disable-version-check",  # ditto -- this one phones the registry
        "--no-rewrite-rule-ids",  # keep bare rule ids, not path-prefixed ones
        "--no-git-ignore",  # a .gitignore must not hide crypto from an audit
        "--quiet",
        "--json",
        "--config",
        str(rules_dir),
        str(target_path),
    ]

    environment = dict(os.environ)
    environment["SEMGREP_SEND_METRICS"] = "off"

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell, fixed binary
            command,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepFailedError(
            f"semgrep did not finish within {SEMGREP_TIMEOUT_SECONDS}s on {target_path}"
        ) from exc

    # 0 = clean, 1 = findings. Anything else is a real failure.
    if completed.returncode not in (0, 1):
        raise SemgrepFailedError(
            f"semgrep exited {completed.returncode} on {target_path}: "
            f"{completed.stderr.strip()[:500]}"
        )
    return completed.stdout


#: The per-file PARSE errors semgrep reports at ``level: warn`` (ADR-0033).
#:
#: An ALLOWLIST, deliberately. Only these are tolerated, so an error type
#: nobody listed -- a new semgrep failure mode, an internal matching error, an
#: out-of-memory -- fails loud rather than being quietly skipped. STEP 0
#: observed "Syntax error" (the file is rejected whole: Python, Java, most
#: TypeScript) and "PartialParsing" (the parser recovered: Go, some TS) on
#: semgrep 1.176.1; the other three names are the same family in semgrep's
#: output schema. Were one misspelt here, the cost would be a loud failure,
#: never a silent skip.
_UNPARSED_TYPES = frozenset(
    {"Syntax error", "Lexical error", "Other syntax error", "AST builder error"}
)
_PARTIAL_TYPE = "PartialParsing"


@dataclass(frozen=True, slots=True)
class SemgrepOutput:
    """Semgrep's JSON, read: the results, and what it could not parse."""

    results: list[dict[str, Any]]
    #: One gap per file semgrep examined and could not fully parse.
    gaps: tuple[CoverageGap, ...]
    #: Files semgrep examined (``paths.scanned``). That list INCLUDES files
    #: that failed to parse -- which is exactly why a gap is read from the
    #: errors and never inferred from it: believing "scanned" would record a
    #: file nobody read as a file that came back clean.
    examined: int


def _error_type(error: dict[str, Any]) -> str:
    """Semgrep's ``type`` is a string -- or ``[name, locations]`` for
    PartialParsing, which carries where parsing gave up."""
    raw = error.get("type")
    if isinstance(raw, list) and raw and isinstance(raw[0], str):
        return raw[0]
    return raw if isinstance(raw, str) else ""


def _per_file_parse_gap(error: dict[str, Any]) -> CoverageGap | None:
    """The coverage gap a TOLERABLE error describes, or ``None`` if it is fatal.

    Tolerable means all three at once: ``level: warn``, a parse type on the
    allowlist, and a named file. Missing any one, the error is not a statement
    about one file's syntax, and treating it as a skip would hide it.
    """
    if error.get("level") != "warn":
        return None
    path = error.get("path")
    if not isinstance(path, str) or not path:
        return None
    kind = _error_type(error)
    if kind in _UNPARSED_TYPES:
        return CoverageGap(scanner=SCANNER_ID, path=path, kind="unparsed", reason=kind)
    if kind == _PARTIAL_TYPE:
        return CoverageGap(
            scanner=SCANNER_ID, path=path, kind="partially-parsed", reason=kind
        )
    return None


def _parse_semgrep_json(payload: str) -> SemgrepOutput:
    """Read semgrep's JSON: results, per-file parse gaps -- or fail loudly.

    Before ADR-0033 EVERY entry in ``errors`` except a Timeout was fatal, so a
    single unparseable file (a Juice Shop challenge snippet) discarded the
    results semgrep had already produced for every other file. Semgrep itself
    skips such a file and exits 0; the blindness was ours. A per-file parse
    error is now a recorded gap; everything else is still an exception.
    """
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SemgrepOutputError(
            f"semgrep did not return JSON: {payload.strip()[:200]!r}"
        ) from exc

    if not isinstance(document, dict) or "results" not in document:
        raise SemgrepOutputError(
            "semgrep JSON has no 'results' key; the output contract has changed"
        )

    results = document["results"]
    if not isinstance(results, list):
        raise SemgrepOutputError("semgrep 'results' is not a list")

    gaps: dict[str, CoverageGap] = {}
    fatal: list[dict[str, Any]] = []
    for error in document.get("errors", []):
        if not isinstance(error, dict) or error.get("type") == "Timeout":
            continue  # unchanged from before ADR-0033 -- see PUNCHLIST
        gap = _per_file_parse_gap(error)
        if gap is None:
            fatal.append(error)
        elif gap.path not in gaps or gap.kind == "unparsed":
            # One gap per file; "unparsed" outranks "partially-parsed".
            gaps[gap.path] = gap

    if fatal:
        # A rule that did not run, a config that did not load, an error with no
        # file: a silent hole in the inventory, so it is fatal, not a skip.
        messages = "; ".join(str(e.get("message", e))[:200] for e in fatal[:3])
        raise SemgrepOutputError(
            f"semgrep reported errors that are not per-file parse errors: {messages}"
        )

    scanned = (document.get("paths") or {}).get("scanned") or []
    examined = len(scanned) if isinstance(scanned, list) else 0
    return SemgrepOutput(
        results=cast(list[dict[str, Any]], results),
        gaps=tuple(sorted(gaps.values(), key=lambda g: g.path)),
        # Never fewer than the files it failed on, even if `paths` is absent.
        examined=max(examined, len(gaps)),
    )


# ---------------------------------------------------------------------------
# Captured values: resolving, normalising, classifying
# ---------------------------------------------------------------------------


def _try_literal(text: str) -> tuple[bool, Any]:
    """``(True, value)`` if ``text`` is a Python literal, else ``(False, None)``."""
    try:
        return True, ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return False, None


def _is_resolved(text: str) -> bool:
    """Whether a captured value pins the parameter at authoring time.

    Resolved: a literal (``2048``, ``"RS256"``), a constructor or attribute
    reference (``ec.SECP256R1()``, ``modes.GCM``), or an ALL_CAPS name, which
    by Python convention is a module constant and so still requires a code edit
    to change.

    Unresolved: a lowercase or mixed-case bare name, which is the shape of a
    value read from config at runtime.

    This is a convention, not dataflow. An ALL_CAPS name assigned from
    ``os.environ`` is genuinely configurable and will be misread as hard-coded;
    resolving that needs constant propagation. Recorded in ADR-0004.
    """
    resolved, _ = _try_literal(text)
    if resolved:
        return True
    if "(" in text or "." in text:
        return True
    if _BARE_NAME.match(text):
        return text == text.upper()
    return False


def _as_symbol(text: str) -> str:
    """``ec.SECP256R1()`` -> ``SECP256R1``; ``MODE_CBC`` -> ``CBC``."""
    ok, literal = _try_literal(text)
    if ok and isinstance(literal, str):
        return literal

    value = text.split("(", 1)[0].strip()
    value = value.rsplit(".", 1)[-1]
    for prefix in _SYMBOL_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _normalise_param(name: str, text: str) -> Any:
    """Turn one captured metavariable into a CBOM-ready parameter value."""
    stripped = text.strip()
    if name in _SYMBOL_PARAMS:
        return _as_symbol(stripped)

    ok, literal = _try_literal(stripped)
    if ok and isinstance(literal, int | float | str | bool):
        return literal
    return stripped


def _capture_map(metadata: dict[str, Any], rule_id: str) -> dict[str, str]:
    """Ordered ``param_name -> $METAVAR`` for a rule.

    ``keysize_metavar`` is sugar for ``capture: {key_size: $X}``; it is spelled
    out separately because key size is the parameter almost every asymmetric
    rule needs and naming it explicitly keeps those rules readable.
    """
    captures: dict[str, str] = {}

    keysize = metadata.get("keysize_metavar")
    if keysize is not None:
        if not isinstance(keysize, str):
            raise RulePackContractError(
                f"rule {rule_id}: keysize_metavar must be a string, got {keysize!r}"
            )
        captures["key_size"] = keysize

    declared = metadata.get("capture") or {}
    if not isinstance(declared, dict):
        raise RulePackContractError(
            f"rule {rule_id}: 'capture' must be a mapping of param -> $METAVAR"
        )
    for name, metavar in declared.items():
        if not isinstance(name, str) or not isinstance(metavar, str):
            raise RulePackContractError(
                f"rule {rule_id}: 'capture' entries must be string -> string"
            )
        captures[name] = metavar

    return captures


def _parse_captures(message: str, names: Sequence[str], rule_id: str) -> dict[str, str]:
    """Read the values semgrep interpolated into the rule's message.

    The message is authored as ``ecdat|<name>=$METAVAR|<name>=$METAVAR``, in the
    same order as the rule's ``capture`` mapping, so the values can be pulled
    back out with a regex built from the declared names.
    """
    if not message.startswith(MESSAGE_PREFIX):
        raise RulePackContractError(
            f"rule {rule_id}: message must start with {MESSAGE_PREFIX!r}; "
            f"got {message[:60]!r}"
        )

    body = message[len(MESSAGE_PREFIX) :]
    if not names:
        return {}

    parts = [
        rf"{re.escape(name)}=(?P<{name}>.*{'?' if index < len(names) - 1 else ''})"
        for index, name in enumerate(names)
    ]
    match = re.fullmatch(r"\|".join(parts), body, flags=re.DOTALL)
    if match is None:
        raise RulePackContractError(
            f"rule {rule_id}: message {body!r} does not carry the declared "
            f"captures {list(names)}; message and 'capture' must agree"
        )
    return match.groupdict()


# ---------------------------------------------------------------------------
# Redaction -- PUNCHLIST #3
# ---------------------------------------------------------------------------


def _redact(line: str, *, always: bool) -> str:
    """Return a snippet safe to store.

    Two layers. A rule that knows it matches key material sets ``redact: true``
    and its snippet is dropped outright. Independently, any line is scrubbed if
    it carries a PEM banner, a Python byte-string literal long enough to be a
    key, or an opaque quoted blob in any language -- because a rule about a
    *cipher* or a *digest* frequently matches the very line a key literal sits
    on, and that rule has no idea the key is there.

    The third case is what makes the second layer language-neutral. The
    byte-literal net only ever recognised Python's ``b"..."`` spelling, so a
    Java or JavaScript key sitting on a matched line was protected only by its
    own rule remembering ``redact: true`` -- and a DIFFERENT rule matching the
    same line remembered nothing. ``tests/test_rules_java.py`` plants exactly
    that: a sentinel hashed by ``MessageDigest.getInstance("MD5")`` on one
    line, where the digest rule is the one that must not carry it out.
    """
    if always:
        return REDACTED

    text = line.strip()
    if _PEM_BANNER.search(text):
        return REDACTED

    def _scrub_bytes(match: re.Match[str]) -> str:
        body = match.group(2)
        if len(body) >= _KEY_LITERAL_MIN_BYTES:
            return 'b"<redacted>"'
        return match.group(0)

    scrubbed = _BYTES_LITERAL.sub(_scrub_bytes, text)

    def _scrub_opaque(match: re.Match[str]) -> str:
        quote = match.group(1)
        return f"{quote}<redacted>{quote}"

    return _OPAQUE_LITERAL.sub(_scrub_opaque, scrubbed)


def _read_line(path: Path, number: int, cache: dict[Path, list[str]]) -> str:
    """The source line a match starts on.

    Read here rather than taken from semgrep's ``extra.lines``, which reports
    ``"requires login"`` in the OSS build. Reading it ourselves is also what
    puts redaction under our control rather than the engine's.
    """
    lines = cache.get(path)
    if lines is None:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        cache[path] = lines

    if 1 <= number <= len(lines):
        return lines[number - 1]
    return ""


# ---------------------------------------------------------------------------
# Mapping one semgrep result to one Finding
# ---------------------------------------------------------------------------


def _require(metadata: dict[str, Any], key: str, rule_id: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value:
        raise RulePackContractError(
            f"rule {rule_id}: metadata.{key} is required and must be a "
            f"non-empty string; got {value!r}"
        )
    return value


def _vocabulary(value: str, allowed: frozenset[str], field: str, rule_id: str) -> str:
    if value not in allowed:
        raise RulePackContractError(
            f"rule {rule_id}: metadata.{field}={value!r} is not one of "
            f"{sorted(allowed)}"
        )
    return value


def _finding(
    result: dict[str, Any], cache: dict[Path, list[str]], scanner_id: str
) -> Finding:
    check_id = str(result.get("check_id", ""))
    rule_id = check_id.rsplit(".", 1)[-1]
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise RulePackContractError(f"rule {rule_id}: metadata must be a mapping")

    algorithm = _require(metadata, "algorithm", rule_id)
    primitive = _vocabulary(
        _require(metadata, "primitive", rule_id), _PRIMITIVES, "primitive", rule_id
    )
    usage = _vocabulary(_require(metadata, "usage", rule_id), _USAGES, "usage", rule_id)
    asset_type = _vocabulary(
        str(metadata.get("asset_type", "algorithm")),
        _ASSET_TYPES,
        "asset_type",
        rule_id,
    )
    _require(metadata, "quantum_note", rule_id)

    captures = _capture_map(metadata, rule_id)
    raw_values = _parse_captures(str(extra.get("message", "")), list(captures), rule_id)

    params: dict[str, Any] = {}
    resolved = True
    for name, text in raw_values.items():
        params[name] = _normalise_param(name, text)
        resolved = resolved and _is_resolved(text.strip())

    flags = metadata.get("flags") or []
    if "critical" in flags:
        params["flagged"] = True

    # A mode the rule pack singles out (ECB) is flagged the same way, so the
    # policy engine does not have to know mode names to find it.
    mode_flags = metadata.get("mode_flags") or {}
    if isinstance(mode_flags, dict) and params.get("mode") in mode_flags:
        params["flagged"] = True

    path = Path(str(result.get("path", "")))
    line = int((result.get("start") or {}).get("line", 0))
    snippet = _redact(
        _read_line(path, line, cache), always=bool(metadata.get("redact"))
    )

    view: View = "declared"
    return Finding(
        scanner_id=scanner_id,
        view=view,
        asset_type=cast(AssetType, asset_type),
        primitive=cast(Primitive, primitive),
        algorithm=algorithm,
        params=params,
        usage=cast(Usage, usage),
        configurable=not resolved,
        evidence=Evidence(
            occurrences=[
                Occurrence(
                    view=view,
                    locator=f"{path}:{line}",
                    detail=f"rule={rule_id}",
                    snippet=snippet or None,
                )
            ]
        ),
        confidence=1.0 if resolved else _UNRESOLVED_CONFIDENCE,
        raw={"rule_id": rule_id, "check_id": check_id, "captures": raw_values},
    )


# ---------------------------------------------------------------------------
# Dataflow annotations -- ADR-0026
# ---------------------------------------------------------------------------

#: A rule carrying this metadata key does not describe a cryptographic
#: artefact. It reports something ABOUT one that another rule already found,
#: and the scanner applies it as a correction instead of emitting a Finding.
ANNOTATES = "annotates"

#: "The value reaching this call site came from the environment, so the
#: artefact is configurable" (ADR-0026).
ANNOTATE_CONFIGURABLE = "configurable"

#: "The key generated at this line is used for X in the same function, so its
#: usage is X rather than unknown" (ADR-0030). The value is read from the
#: rule's `metadata.usage`.
ANNOTATE_USAGE = "usage"

ANNOTATION_KINDS = frozenset({ANNOTATE_CONFIGURABLE, ANNOTATE_USAGE})


def _site(result: dict[str, Any]) -> tuple[str, int]:
    """``(path, line)`` -- what an annotation and its finding must share.

    The line is the SINK's line for a taint rule and the match line for a
    pattern rule, and for the call sites this applies to they are the same
    line: `rsa.generate_private_key(..., key_size=BITS)` is both.
    """
    return (
        str(result.get("path", "")),
        int((result.get("start") or {}).get("line", 0)),
    )


def _partition(
    results: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split semgrep's results into ANNOTATIONS and detections.

    An annotation is a rule whose metadata declares `annotates:`. It never
    becomes a Finding -- see :data:`ANNOTATES` and ADR-0026 for why a
    configurability verdict cannot be one.
    """
    annotations: list[dict[str, Any]] = []
    detections: list[dict[str, Any]] = []
    for result in results:
        metadata = (result.get("extra") or {}).get("metadata") or {}
        kind = metadata.get(ANNOTATES) if isinstance(metadata, dict) else None
        if kind in ANNOTATION_KINDS:
            annotations.append(result)
        elif kind is not None:
            raise RulePackContractError(
                f"rule {result.get('check_id')!r}: unknown annotation kind "
                f"{kind!r}; the scanner knows {sorted(ANNOTATION_KINDS)}"
            )
        else:
            detections.append(result)
    return annotations, detections


def _annotation_kind(result: dict[str, Any]) -> str:
    metadata = (result.get("extra") or {}).get("metadata") or {}
    return str(metadata.get(ANNOTATES, ""))


def _usage_annotations(
    annotations: Sequence[dict[str, Any]],
) -> dict[tuple[str, int], str]:
    """``(path, line) -> usage`` from every use-site refinement rule.

    Where two refinements land on one keygen -- a key that both signs and
    wraps, which is a real and bad pattern -- the FIRST in sorted rule order
    wins deterministically rather than the last one seen. Reporting one of two
    true usages is a limit; reporting a different one on each run would be a
    determinism break.
    """
    chosen: dict[tuple[str, int], str] = {}
    for result in sorted(annotations, key=lambda r: str(r.get("check_id", ""))):
        if _annotation_kind(result) != ANNOTATE_USAGE:
            continue
        metadata = (result.get("extra") or {}).get("metadata") or {}
        usage = str(metadata.get("usage", "")).strip()
        if not usage:
            raise RulePackContractError(
                f"rule {result.get('check_id')!r}: annotates usage but "
                f"metadata.usage is missing"
            )
        chosen.setdefault(_site(result), _vocabulary(usage, _USAGES, "usage", ""))
    return chosen


def _mark_configurable(finding: Finding) -> Finding:
    """Apply a dataflow configurability verdict to a finding.

    Two fields move, and both for the same reason -- the verdict replaces a
    guess with evidence:

    * ``configurable`` becomes True. The shape heuristic reads `RSA_BITS` as a
      resolved constant because it is ALL_CAPS; dataflow says it came from
      `os.environ`. This flag feeds the crypto-agility score and the Mosca Y
      estimate, so it is the whole point of the rule.
    * ``confidence`` returns to 1.0 where the heuristic had docked it to
      :data:`_UNRESOLVED_CONFIDENCE` for an unresolved lower-case name. The
      penalty exists because the scanner did not know what the value was; here
      it does know where it came from, which is the question `configurable`
      asks.
    """
    return finding.model_copy(update={"configurable": True, "confidence": 1.0})


def _refine_usage(finding: Finding, usage: str) -> Finding:
    """Apply a use-site usage verdict to a keygen finding (ADR-0030).

    `usage` is what decides the post-quantum target -- ML-DSA for signing,
    ML-KEM for key transport -- so a keygen left at `unknown` produces correct
    but unactionable advice. The use site in the same function is evidence, and
    this is where it lands.

    `usage` is IDENTIFYING, so this changes the artefact's bom-ref. That is the
    point: a signing key and a transport key generated by identical calls in
    different functions ARE different artefacts with different migrations, and
    collapsing them was the old behaviour.
    """
    return finding.model_copy(update={"usage": cast(Usage, usage)})


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class SourceScanner:
    """Detects cryptographic use in source code (ADR-0004, ADR-0023).

    Python, Go and JavaScript/TypeScript today. The rule-metadata contract was
    proved on one language before the pack was widened, and the widening added
    no scanner code: Go and JS/TS are rule files against the same contract.
    Java, C/C++, Rust and C# are still unscanned -- see PUNCHLIST.
    """

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = SCANNER_ID
    view: View = "declared"

    #: The engine version this plugin was verified against. Read by the
    #: orchestrator through `getattr`, so this stays an OPTIONAL capability
    #: rather than something every scanner has to implement -- most plugins
    #: are pure Python and have no external engine to pin.
    pinned_engine_version: str = PINNED_SEMGREP_VERSION

    def engine_version(self) -> str | None:
        """The semgrep actually installed, or ``None`` if it is missing."""
        return installed_semgrep_version()

    #: Target kinds this plugin can say anything about.
    SUPPORTED_KINDS = frozenset({"repo", "directory"})

    def supports(self, target: Target) -> bool:
        return target.kind in self.SUPPORTED_KINDS

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        rules_dir = ctx.knowledge_dir / RULE_SUBDIR
        if not rules_dir.is_dir():
            raise RulePackMissingError(
                f"the source rule packs are missing: {rules_dir} does not exist. "
                "Set ECDAT_KNOWLEDGE_DIR or restore knowledge/rules/."
            )

        output = _parse_semgrep_json(_run_semgrep(rules_dir, Path(target.ref)))
        results = output.results

        # One unparseable file must not blind the scan (ADR-0033): it is
        # LOGGED, and RECORDED where the orchestrator will write it into the
        # document -- never dropped, and never counted as a clean file.
        if output.gaps:
            unparsed = [g.path for g in output.gaps if g.kind == "unparsed"]
            partial = [g.path for g in output.gaps if g.kind == "partially-parsed"]
            _log.warning(
                "source_files_unparsed",
                extra={
                    "event": "source_files_unparsed",
                    "target_ref": target.ref,
                    "examined": output.examined,
                    "unparsed_count": len(unparsed),
                    "partially_parsed_count": len(partial),
                    "nothing_parsed": len(unparsed) >= output.examined,
                    "unparsed": unparsed[:20],
                    "partially_parsed": partial[:20],
                },
            )
        if ctx.coverage is not None:
            ctx.coverage.record(self.id, output.examined, output.gaps)

        # Semgrep does not promise an order; the CBOM promises determinism.
        ordered = sorted(
            results,
            key=lambda r: (
                str(r.get("path", "")),
                int((r.get("start") or {}).get("line", 0)),
                int((r.get("start") or {}).get("col", 0)),
                str(r.get("check_id", "")),
            ),
        )

        annotations, detections = _partition(ordered)
        configurable_sites = {
            _site(r)
            for r in annotations
            if _annotation_kind(r) == ANNOTATE_CONFIGURABLE
        }
        refined_usage = _usage_annotations(annotations)

        cache: dict[Path, list[str]] = {}
        for result in detections:
            finding = _finding(result, cache, self.id)
            site = _site(result)
            if site in configurable_sites:
                finding = _mark_configurable(finding)
            usage = refined_usage.get(site)
            if usage is not None and finding.usage == "unknown":
                # Only ever refines an UNKNOWN. A rule that already read the
                # usage off the API is the better evidence, and a refinement
                # that overrode it would let a use site in the same function
                # rewrite a fact the call itself stated.
                finding = _refine_usage(finding, usage)
            yield finding
