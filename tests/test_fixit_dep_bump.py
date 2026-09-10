"""dep-bump: a version bump ECDAT is willing to stand behind (ADR-0022).

ADR-0015 kept this template out of the shipped set for one reason: nothing
could re-verify it. Scanner B (ADR-0021) closed that gap, so the fix ships --
but it inherits a second gate on the way in.

**The honesty gate.** ADR-0017 says an unverified pack fact is demoted to a
labelled note and never scored. A fix is a stronger claim than a score: it
tells an operator to change a dependency their service is built on. So the
same rule applies harder here -- dep-bump proposes a bump ONLY to a
``pqc_capable_from`` that has been confirmed against upstream release material.
Two packs in these tests are byte-identical except for
``pqc_capable_verified``, and they produce opposite outcomes. That one bit is
the whole feature.

**No stale-hash lockfile edits.** ``package-lock.json``, ``poetry.lock`` and
``go.sum`` carry integrity hashes over the version they pin. Editing the
version and leaving the hash is a lockfile that fails on the next install --
a broken tree, shipped as remediation. dep-bump edits the manifest and says to
regenerate; where there is no manifest to edit, it declines.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence
from correlate.fixit.engine import propose_fix
from correlate.fixit.templates import DEFAULT_TEMPLATES
from correlate.fixit.templates.dep_bump import DepBump
from scanners.deps import DepsScanner

REAL_KNOWLEDGE = Path("knowledge")

#: A verified floor that does not exist in the shipped pack. Every real entry
#: is provisional (ADR-0021), which is exactly why the happy path needs a
#: fixture pack -- see `test_no_shipped_library_has_a_verified_floor_today`.
FLOOR = "42.0.0"


# ---------------------------------------------------------------------------
# Fixture packs: identical but for one bit
# ---------------------------------------------------------------------------


def write_pack(
    destination: Path,
    *,
    verified: bool,
    floor: str | None = FLOOR,
    name: str = "cryptography",
    ecosystem: str = "pypi",
    packages: Sequence[str] = ("cryptography",),
) -> Path:
    """A knowledge dir that is the real one with ``libraries.yaml`` replaced.

    Copied rather than built from nothing so the policy engine still finds
    ``data_classes.yaml`` and friends: only the fact under test changes.
    """
    destination.mkdir(parents=True, exist_ok=True)
    for entry in REAL_KNOWLEDGE.iterdir():
        if entry.is_file():
            shutil.copy2(entry, destination / entry.name)

    floor_line = "null" if floor is None else repr(floor)
    package_lines = "\n".join(f"      - {p}" for p in packages)
    (destination / "libraries.yaml").write_text(
        "libraries:\n"
        f"  - name: {name}\n"
        f"    ecosystem: {ecosystem}\n"
        "    packages:\n"
        f"{package_lines}\n"
        "    provides:\n"
        "      - RSA\n"
        f"    pqc_capable_from: {floor_line}\n"
        f"    pqc_capable_verified: {str(verified).lower()}\n"
        "    pqc_capable_source: >-\n"
        "      TEST FIXTURE PACK. Not a real capability claim; it exists so the\n"
        "      verified and provisional branches can be exercised side by side.\n"
        "    eol: null\n"
        "    source: >-\n"
        "      TEST FIXTURE PACK (tests/test_fixit_dep_bump.py).\n",
        encoding="utf-8",
    )
    return destination


@pytest.fixture
def verified_pack(tmp_path: Path) -> Path:
    return write_pack(tmp_path / "pack-verified", verified=True)


@pytest.fixture
def provisional_pack(tmp_path: Path) -> Path:
    return write_pack(tmp_path / "pack-provisional", verified=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def repo(root: Path, files: dict[str, str]) -> Path:
    """A throwaway project tree. ``files`` is ``relative path -> content``."""
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def target_for(ref: Path, **overrides: Any) -> Target:
    kwargs: dict[str, Any] = {
        "kind": "repo",
        "ref": str(ref),
        "system": "fixture",
        "data_class": "pii",
        "sector": "bfsi",
        "exposure": "internet",
    }
    kwargs.update(overrides)
    return Target(**kwargs)


def context_for(pack: Path, tmp_path: Path) -> ScanContext:
    return ScanContext(knowledge_dir=pack, scratch_dir=tmp_path / "scratch")


def use_pack(pack: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the TEMPLATE at the same pack the scanner is given.

    ``FixTemplate.preconditions`` takes no ``ScanContext`` -- the protocol
    predates this template and is not widened for it -- so the template
    resolves the knowledge dir the way every other entry point does, from the
    environment. Setting both keeps the fix and its re-verification reading one
    pack; disagreeing on that is how a fix gets proposed against a fact the
    verifier never saw.
    """
    monkeypatch.setenv("ECDAT_KNOWLEDGE_DIR", str(pack))


def deps_finding(target: Target, context: ScanContext, package: str) -> Finding:
    hits = [
        f
        for f in DepsScanner().scan(target, context)
        if f.params.get("package", "").lower() == package.lower()
    ]
    assert len(hits) == 1, f"expected one {package} finding, got {len(hits)}"
    return hits[0]


def tree_hash(root: Path) -> str:
    digest = hashlib.blake2b(digest_size=16)
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        if path.is_file():
            digest.update(path.read_bytes())
        digest.update(b"\x01")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_dep_bump_is_registered_and_re_verifies_with_the_deps_scanner() -> None:
    template = next(t for t in DEFAULT_TEMPLATES if t.id == "dep-bump")
    assert template.scanner_to_reverify == "deps"
    assert template.source.strip()


def test_dep_bump_ignores_findings_that_are_not_declared_libraries() -> None:
    """A source-scanner algorithm finding is Scanner A's, not this template's."""
    source_finding = Finding(
        scanner_id="source",
        view="declared",
        asset_type="algorithm",
        primitive="hash",
        algorithm="MD5",
        evidence=Evidence(
            occurrences=[
                Occurrence(view="declared", locator="app/hash.py:3", detail="rule=md5")
            ]
        ),
    )
    assert DepBump().matches(source_finding) is False


# ---------------------------------------------------------------------------
# The happy path: below floor -> verified bump -> re-scan clean
# ---------------------------------------------------------------------------


def test_a_below_floor_dependency_is_bumped_and_verified_by_rescan(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {"requirements.txt": "cryptography==41.0.0\nrequests==2.31.0\n"},
    )
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")
    assert finding.params["version"] == "41.0.0"
    assert finding.params["pqc_capable"] is False

    result = propose_fix(finding, target, context=context)

    assert result.applicable is True
    assert result.verified is True, result.reason
    assert result.template_id == "dep-bump"
    assert result.diff is not None
    assert "-cryptography==41.0.0" in result.diff
    assert f"+cryptography=={FLOOR}" in result.diff
    assert result.new_criticals == ()
    # The fix must say what it does NOT do.
    assert "lockfile" in result.diff.lower() or "lockfile" in result.reason.lower()


def test_the_bumped_version_is_pqc_capable_when_the_deps_scanner_re_reads_it(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The claim behind the fix, checked by the producer rather than asserted."""
    use_pack(verified_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    result = propose_fix(finding, target, context=context)
    assert result.verified is True, result.reason

    patched = repo(
        tmp_path / "patched", {"requirements.txt": f"cryptography=={FLOOR}\n"}
    )
    after = deps_finding(target_for(patched), context, "cryptography")
    assert after.params["pqc_capable"] is True


# ---------------------------------------------------------------------------
# THE HONESTY GATE
# ---------------------------------------------------------------------------


def test_a_provisional_floor_is_declined_and_produces_no_diff(
    tmp_path: Path, provisional_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same repo, the same floor, one bit different -- and no fix.

    This is the test the template exists to pass. `pqc_capable_from: 42.0.0`
    with `pqc_capable_verified: false` is a number somebody typed, not a fact
    confirmed against a changelog. Bumping to it would launder that number into
    a change an operator makes to production.
    """
    use_pack(provisional_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    context = context_for(provisional_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.verified is False
    assert result.diff is None
    assert "unverified" in result.reason.lower()
    assert "cannot propose a bump to an unconfirmed fact" in result.reason.lower()


def test_the_verified_and_provisional_packs_differ_only_in_that_one_bit(
    tmp_path: Path,
) -> None:
    """Guards the A/B above: if the packs drifted, the gate proves nothing."""
    a = (write_pack(tmp_path / "a", verified=True) / "libraries.yaml").read_text()
    b = (write_pack(tmp_path / "b", verified=False) / "libraries.yaml").read_text()
    differing = [
        (x, y) for x, y in zip(a.splitlines(), b.splitlines(), strict=True) if x != y
    ]
    assert differing == [
        ("    pqc_capable_verified: true", "    pqc_capable_verified: false")
    ]


def test_a_library_with_no_recorded_floor_is_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = write_pack(tmp_path / "pack-nofloor", verified=True, floor=None)
    use_pack(pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.diff is None
    assert "no post-quantum floor" in result.reason.lower()


def test_no_shipped_library_has_a_verified_floor_today(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The consequence of ADR-0021 written down: dep-bump declines every real
    dependency until the fifteen provisional floors are researched.

    That is the honesty gate working on the shipped pack, not a defect. When a
    floor is verified this test is the one that changes.
    """
    monkeypatch.setenv("ECDAT_KNOWLEDGE_DIR", str(REAL_KNOWLEDGE))
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    context = context_for(REAL_KNOWLEDGE, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.diff is None


# ---------------------------------------------------------------------------
# Formats: requirements.txt, package.json, go.mod
# ---------------------------------------------------------------------------


def test_a_requirements_pin_is_bumped_in_place(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {"requirements.txt": "# app deps\nrequests==2.31.0\ncryptography==41.0.0\n"},
    )
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    diff = DepBump().make_diff(finding, target)

    assert "--- a/requirements.txt" in diff
    assert "-cryptography==41.0.0" in diff
    assert f"+cryptography=={FLOOR}" in diff
    # Only the one declaration moves.
    assert "-requests==2.31.0" not in diff


def test_a_requirements_range_has_its_lower_bound_bumped_with_a_note(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography>=41.0,<43\n"})
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")
    assert finding.params["version_is_range"] is True

    template = DepBump()
    assert template.preconditions(finding, target).ok is True
    diff = template.make_diff(finding, target)

    assert "-cryptography>=41.0,<43" in diff
    assert f"+cryptography>={FLOOR},<43" in diff
    # A range bump moves the FLOOR, not the ceiling, and the ceiling may still
    # exclude the target. The note is where that is said out loud.
    assert "+#" in diff


def test_a_package_json_semver_is_bumped_keeping_its_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = write_pack(
        tmp_path / "pack-npm",
        verified=True,
        name="node-forge",
        ecosystem="npm",
        packages=("node-forge",),
    )
    use_pack(pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {
            "package.json": (
                '{\n  "name": "app",\n  "dependencies": {\n'
                '    "node-forge": "^1.3.1",\n    "lodash": "^4.17.21"\n  }\n}\n'
            )
        },
    )
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "node-forge")

    diff = DepBump().make_diff(finding, target)

    assert "--- a/package.json" in diff
    assert '-    "node-forge": "^1.3.1",' in diff
    assert f'+    "node-forge": "^{FLOOR}",' in diff
    assert '-    "lodash": "^4.17.21"' not in diff


def test_a_go_mod_require_line_is_bumped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = write_pack(
        tmp_path / "pack-go",
        verified=True,
        name="golang.org/x/crypto",
        ecosystem="go",
        packages=("golang.org/x/crypto",),
    )
    use_pack(pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {
            "go.mod": (
                "module example.com/app\n\ngo 1.22\n\nrequire (\n"
                "\tgolang.org/x/crypto v0.31.0\n"
                "\tgithub.com/gorilla/mux v1.8.1\n)\n"
            )
        },
    )
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "golang.org/x/crypto")

    diff = DepBump().make_diff(finding, target)

    assert "--- a/go.mod" in diff
    assert "-\tgolang.org/x/crypto v0.31.0" in diff
    assert f"+\tgolang.org/x/crypto v{FLOOR}" in diff
    assert "-\tgithub.com/gorilla/mux v1.8.1" not in diff


# ---------------------------------------------------------------------------
# Resolved lockfiles are never hand-edited
# ---------------------------------------------------------------------------


PACKAGE_LOCK = (
    '{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n'
    '    "": {"name": "app"},\n'
    '    "node_modules/node-forge": {\n'
    '      "version": "1.3.1",\n'
    '      "integrity": "sha512-dPEtOeMvF9VbcEz3Lw==",\n'
    '      "license": "BSD-3-Clause"\n    }\n  }\n}\n'
)


def test_a_resolved_lockfile_with_no_manifest_is_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stale-hash refusal. A bumped version beside its old integrity hash
    is a lockfile that fails on the next install."""
    pack = write_pack(
        tmp_path / "pack-npm",
        verified=True,
        name="node-forge",
        ecosystem="npm",
        packages=("node-forge",),
    )
    use_pack(pack, monkeypatch)
    root = repo(tmp_path / "project", {"package-lock.json": PACKAGE_LOCK})
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "node-forge")
    assert finding.params["manifest"] == "package-lock.json"

    before = (root / "package-lock.json").read_bytes()
    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.verified is False
    assert result.diff is None
    assert "regenerate" in result.reason.lower()
    assert (root / "package-lock.json").read_bytes() == before


def test_no_diff_ever_edits_a_resolved_lockfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Belt and braces: even asked directly, make_diff leaves the lock alone."""
    pack = write_pack(
        tmp_path / "pack-npm",
        verified=True,
        name="node-forge",
        ecosystem="npm",
        packages=("node-forge",),
    )
    use_pack(pack, monkeypatch)
    root = repo(tmp_path / "project", {"package-lock.json": PACKAGE_LOCK})
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "node-forge")

    diff = DepBump().make_diff(finding, target)

    assert "--- a/package-lock.json" not in diff
    assert "+++ b/package-lock.json" not in diff
    assert "sha512" not in diff
    assert diff == ""


def test_a_lockfile_finding_bumps_the_sibling_manifest_but_is_not_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The honest consequence of lockfile-preferred (ADR-0021).

    When a resolved lockfile exists the scanner reads IT, so bumping the
    manifest beside it cannot make the finding go away -- the lock still pins
    the old version, and only a regenerate would move it. ECDAT produces the
    manifest edit and refuses to call it verified.
    """
    pack = write_pack(
        tmp_path / "pack-npm",
        verified=True,
        name="node-forge",
        ecosystem="npm",
        packages=("node-forge",),
    )
    use_pack(pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {
            "package-lock.json": PACKAGE_LOCK,
            "package.json": (
                '{\n  "name": "app",\n  "dependencies": {\n'
                '    "node-forge": "^1.3.1"\n  }\n}\n'
            ),
        },
    )
    target = target_for(root)
    context = context_for(pack, tmp_path)
    finding = deps_finding(target, context, "node-forge")
    assert finding.params["manifest"] == "package-lock.json"

    template = DepBump()
    assert template.preconditions(finding, target).ok is True
    diff = template.make_diff(finding, target)
    assert "--- a/package.json" in diff
    # The header NAMES the lockfile, to say regenerate it. No hunk touches it.
    assert "--- a/package-lock.json" not in diff
    assert "+++ b/package-lock.json" not in diff
    assert "sha512" not in diff

    result = propose_fix(finding, target, context=context)
    assert result.applicable is True
    assert result.verified is False
    assert result.diff is None
    assert "still present" in result.reason.lower()


# ---------------------------------------------------------------------------
# Nothing to fix
# ---------------------------------------------------------------------------


def test_a_version_at_the_floor_has_nothing_to_fix(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": f"cryptography=={FLOOR}\n"})
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")
    assert finding.params["pqc_capable"] is True

    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.diff is None
    assert "already" in result.reason.lower()


def test_a_range_whose_lower_bound_is_at_the_floor_has_nothing_to_fix(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(
        tmp_path / "project", {"requirements.txt": f"cryptography>={FLOOR},<50\n"}
    )
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    result = propose_fix(finding, target, context=context)

    assert result.applicable is False
    assert result.diff is None


# ---------------------------------------------------------------------------
# Read-only, and deterministic
# ---------------------------------------------------------------------------


def test_the_real_target_is_byte_identical_after_propose_fix(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(
        tmp_path / "project",
        {
            "requirements.txt": "cryptography==41.0.0\n",
            "src/app.py": "import cryptography\n",
        },
    )
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    before = tree_hash(root)
    result = propose_fix(finding, target, context=context)
    after = tree_hash(root)

    assert result.verified is True, result.reason
    assert before == after
    assert (root / "requirements.txt").read_text() == "cryptography==41.0.0\n"


def test_propose_fix_never_opens_the_dependency_manifest_for_writing(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    real_root = root.resolve()
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    opened_for_writing: list[str] = []
    real_open = Path.open

    def guarded(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if set(mode) & set("wax+"):
            resolved = self.resolve()
            if resolved == real_root or real_root in resolved.parents:
                opened_for_writing.append(str(resolved))
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    result = propose_fix(finding, target, context=context)

    assert result.verified is True, result.reason
    assert opened_for_writing == []


def test_the_same_dependency_produces_an_identical_diff(
    tmp_path: Path, verified_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_pack(verified_pack, monkeypatch)
    root = repo(tmp_path / "project", {"requirements.txt": "cryptography==41.0.0\n"})
    target = target_for(root)
    context = context_for(verified_pack, tmp_path)
    finding = deps_finding(target, context, "cryptography")

    template = DepBump()
    first = template.make_diff(finding, target)
    second = template.make_diff(finding, target)

    assert first == second
    assert first.strip()


@pytest.fixture(autouse=True)
def _isolated_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    yield
