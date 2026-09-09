"""The scanner registry: one source of truth for which plugins exist.

Before this existed, ``api/app.py`` and ``cli.py`` each carried their own
hard-coded list of scanners, so adding a plugin meant editing three files and
forgetting one of them was silent. The registry makes "which scanners are
there" a question with exactly one answer, and these tests pin that.

The last section is codebase hygiene rather than behaviour: the stub scanner
was deleted in this slice, and an assertion is cheaper than remembering.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

from core import registry
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding, View
from scanners.source import SourceScanner

REPO_ROOT = Path(__file__).resolve().parent.parent


class FakeScanner:
    """A protocol-satisfying plugin that detects nothing. Test-local only."""

    def __init__(self, scanner_id: str) -> None:
        self.id = scanner_id
        self.view: View = "declared"

    def supports(self, target: Target) -> bool:
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        return iter(())


@pytest.fixture
def empty() -> registry.Registry:
    """A registry of its own, so tests never mutate the process-wide one."""
    return registry.Registry()


# --------------------------------------------------------------------------
# register / get_scanners / available_ids
# --------------------------------------------------------------------------


def test_get_scanners_with_none_returns_everything(
    empty: registry.Registry,
) -> None:
    alpha = empty.register(FakeScanner("alpha"))
    beta = empty.register(FakeScanner("beta"))

    assert empty.get_scanners(None) == [alpha, beta]


def test_get_scanners_with_ids_returns_only_those(
    empty: registry.Registry,
) -> None:
    alpha = empty.register(FakeScanner("alpha"))
    empty.register(FakeScanner("beta"))

    assert empty.get_scanners(["alpha"]) == [alpha]


def test_get_scanners_with_an_empty_list_returns_nothing(
    empty: registry.Registry,
) -> None:
    """An explicit empty selection is not the same as "no selection"."""
    empty.register(FakeScanner("alpha"))

    assert empty.get_scanners([]) == []


def test_get_scanners_raises_on_an_unknown_id(empty: registry.Registry) -> None:
    empty.register(FakeScanner("alpha"))

    with pytest.raises(registry.UnknownScannerError) as caught:
        empty.get_scanners(["nope"])

    message = str(caught.value)
    assert "nope" in message
    # The error has to say what *is* available, or it is not actionable.
    assert "alpha" in message


def test_an_unknown_id_is_reported_even_when_a_known_one_is_present(
    empty: registry.Registry,
) -> None:
    empty.register(FakeScanner("alpha"))

    with pytest.raises(registry.UnknownScannerError):
        empty.get_scanners(["alpha", "nope"])


def test_results_are_id_sorted_regardless_of_registration_order(
    empty: registry.Registry,
) -> None:
    empty.register(FakeScanner("zulu"))
    empty.register(FakeScanner("alpha"))

    assert [s.id for s in empty.get_scanners(None)] == ["alpha", "zulu"]


def test_results_are_id_sorted_regardless_of_request_order(
    empty: registry.Registry,
) -> None:
    """A CBOM must not depend on the order the caller listed its scanners."""
    empty.register(FakeScanner("zulu"))
    empty.register(FakeScanner("alpha"))

    assert [s.id for s in empty.get_scanners(["zulu", "alpha"])] == ["alpha", "zulu"]


def test_a_repeated_id_in_the_request_runs_the_scanner_once(
    empty: registry.Registry,
) -> None:
    empty.register(FakeScanner("alpha"))

    assert [s.id for s in empty.get_scanners(["alpha", "alpha"])] == ["alpha"]


def test_available_ids_is_sorted(empty: registry.Registry) -> None:
    empty.register(FakeScanner("zulu"))
    empty.register(FakeScanner("alpha"))
    empty.register(FakeScanner("mike"))

    assert empty.available_ids() == ["alpha", "mike", "zulu"]


def test_available_ids_of_an_empty_registry_is_empty(
    empty: registry.Registry,
) -> None:
    assert empty.available_ids() == []


def test_registering_a_duplicate_id_is_refused(empty: registry.Registry) -> None:
    empty.register(FakeScanner("alpha"))

    with pytest.raises(registry.DuplicateScannerError):
        empty.register(FakeScanner("alpha"))


def test_register_returns_the_scanner_so_it_can_be_used_inline(
    empty: registry.Registry,
) -> None:
    scanner = FakeScanner("alpha")

    assert empty.register(scanner) is scanner


# --------------------------------------------------------------------------
# the process-wide registry
# --------------------------------------------------------------------------


def test_the_default_registry_lists_every_built_in_scanner() -> None:
    assert registry.available_ids() == [
        "config",
        "container",
        "runtime-spool",
        "source",
    ]


def test_module_level_helpers_delegate_to_the_default_registry() -> None:
    assert [s.id for s in registry.get_scanners(None)] == [
        "config",
        "container",
        "runtime-spool",
        "source",
    ]
    assert [s.id for s in registry.get_scanners(["source"])] == ["source"]


def test_the_registered_source_scanner_is_the_real_one() -> None:
    (scanner,) = registry.get_scanners(["source"])

    assert isinstance(scanner, SourceScanner)


def test_every_registered_scanner_satisfies_the_protocol() -> None:
    for scanner in registry.get_scanners(None):
        assert isinstance(scanner, Scanner)


def test_the_default_registry_rejects_an_unknown_id() -> None:
    with pytest.raises(registry.UnknownScannerError):
        registry.get_scanners(["nope"])


# --------------------------------------------------------------------------
# the stub is gone and must stay gone
# --------------------------------------------------------------------------


def _python_sources() -> Iterator[Path]:
    for path in REPO_ROOT.rglob("*.py"):
        parts = set(path.parts)
        if parts & {".venv", "__pycache__", ".git", "node_modules"}:
            continue
        yield path


def test_the_stub_scanner_package_is_gone() -> None:
    assert not (REPO_ROOT / "scanners" / "stub").exists()
    assert not (REPO_ROOT / "tests" / "test_stub_scanner.py").exists()


def _imports_the_stub(node: ast.AST) -> bool:
    """Whether one AST node is an import of ``scanners.stub``."""
    if isinstance(node, ast.Import):
        return any(alias.name.startswith("scanners.stub") for alias in node.names)
    if isinstance(node, ast.ImportFrom) and node.module is not None:
        return node.module.startswith("scanners.stub")
    return False


def test_no_module_imports_the_stub_scanner() -> None:
    """Parsed, not grepped: a comment mentioning the stub is not an import."""
    offenders: list[str] = []

    for path in _python_sources():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # fixtures are allowed to be unparseable
            continue

        if any(_imports_the_stub(node) for node in ast.walk(tree)):
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == [], f"scanners.stub is still imported by: {offenders}"
