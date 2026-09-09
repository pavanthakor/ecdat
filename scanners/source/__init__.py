"""Scanner A -- Python source crypto detection, with Semgrep as the engine.

The division of labour is the point of this design (ADR-0004):

* **Semgrep holds the matching.** It has the Python grammar, the pattern
  language and the performance work already done. ECDAT does not re-implement
  any of it.
* **The rule pack holds the knowledge.** ``knowledge/rules/python/*.yaml``
  carries the algorithm name, primitive, usage and cited quantum note for every
  pattern. Adding a detection means adding YAML, not Python.
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
from pathlib import Path
from typing import Any, cast, get_args

from core.scanner import ScanContext, Target
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
    "RulePackContractError",
    "RulePackMissingError",
    "SemgrepFailedError",
    "SemgrepOutputError",
    "SemgrepUnavailableError",
    "SourceScanError",
    "SourceScanner",
]

#: The semgrep executable. Module-level so tests can point it at nothing.
SEMGREP_BINARY = "semgrep"

#: Where the Python rule pack lives, relative to ``ScanContext.knowledge_dir``.
RULE_SUBDIR = Path("rules") / "python"

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

_ASSET_TYPES = frozenset(get_args(AssetType))
_PRIMITIVES = frozenset(get_args(Primitive))
_USAGES = frozenset(get_args(Usage))

_BARE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PEM_BANNER = re.compile(r"-----BEGIN[A-Z0-9 ]*-----")
_BYTES_LITERAL = re.compile(
    r"(?:rb|br|b|RB|BR|B)(['\"])((?:\\.|(?!\1).)*)\1",
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


def _parse_semgrep_json(payload: str) -> list[dict[str, Any]]:
    """Pull the results array out of semgrep's JSON, or fail loudly."""
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

    # Rule-level errors mean a rule did not run. That is a silent hole in the
    # inventory, so it is fatal rather than a warning.
    fatal = [
        error
        for error in document.get("errors", [])
        if isinstance(error, dict) and error.get("type") != "Timeout"
    ]
    if fatal:
        messages = "; ".join(str(e.get("message", e))[:200] for e in fatal[:3])
        raise SemgrepOutputError(f"semgrep reported rule errors: {messages}")

    return cast(list[dict[str, Any]], results)


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
    it carries a PEM banner or a byte-string literal long enough to be a key --
    because a rule about a *cipher* frequently matches the very line a key
    literal sits on, and that rule has no idea the key is there.
    """
    if always:
        return REDACTED

    text = line.strip()
    if _PEM_BANNER.search(text):
        return REDACTED

    def _scrub(match: re.Match[str]) -> str:
        body = match.group(2)
        if len(body) >= _KEY_LITERAL_MIN_BYTES:
            return 'b"<redacted>"'
        return match.group(0)

    return _BYTES_LITERAL.sub(_scrub, text)


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
# The plugin
# ---------------------------------------------------------------------------


class SourceScanner:
    """Detects cryptographic use in Python source (ADR-0004).

    Python only, deliberately: the rule-metadata contract is proved on one
    language before the pack is widened. Other languages are new rule files
    against the same contract, not new scanner code.
    """

    # Annotated, not just assigned: the Scanner protocol declares `view: View`,
    # and a bare assignment infers `str`, which does not conform.
    id: str = "source"
    view: View = "declared"

    #: Target kinds this plugin can say anything about.
    SUPPORTED_KINDS = frozenset({"repo", "directory"})

    def supports(self, target: Target) -> bool:
        return target.kind in self.SUPPORTED_KINDS

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        rules_dir = ctx.knowledge_dir / RULE_SUBDIR
        if not rules_dir.is_dir():
            raise RulePackMissingError(
                f"the Python rule pack is missing: {rules_dir} does not exist. "
                "Set ECDAT_KNOWLEDGE_DIR or restore knowledge/rules/python/."
            )

        results = _parse_semgrep_json(_run_semgrep(rules_dir, Path(target.ref)))

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

        cache: dict[Path, list[str]] = {}
        for result in ordered:
            yield _finding(result, cache, self.id)
