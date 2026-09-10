"""Scanner B -- dependencies: crypto a project declares by depending on it.

The fourth producer of the `declared` view, and the one that answers a question
the source scanner structurally cannot: *what cryptography did this project
take on by importing somebody else's?* A repo with no `hashlib` call and a
`cryptography==41.0` line in its lockfile is carrying an RSA implementation,
and only the manifest says so.

Two decisions this suite exists to pin.

**Lockfile-preferred.** A manifest range (`cryptography>=41.0,<43`) and a
lockfile pin (`42.0.5`) describe the same dependency with different certainty.
The lockfile wins, because a PQC verdict on "somewhere between 41 and 43" is a
verdict on a version nobody has. Where only a range exists it is recorded AS a
range, with a note, and the capability question is answered `unknown` rather
than guessed at either end.

**The library/algorithm boundary.** Scanner B finds third-party crypto
LIBRARIES (`asset_type="library"`); Scanner A finds algorithm CALL SITES in
source. `hashlib.md5(...)` is not a dependency and `cryptography==42.0.5` is not
a call site. They are different assets about different things, and ADR-0002's
identity keeps them apart -- asserted here, because the failure mode is one
artefact silently becoming two half-descriptions of itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from core.scanner import ScanContext, Target
from core.schema import Finding
from scanners.deps import DepsScanner

FIXTURES = Path("testdata/deps_fixtures")
KNOWLEDGE = Path("knowledge")
ANSWERS: dict[str, Any] = yaml.safe_load(
    (FIXTURES / "answer_key.yaml").read_text(encoding="utf-8")
)


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path / "scratch")


def scan(ref: Path | str, context: ScanContext, **overrides: Any) -> list[Finding]:
    kwargs: dict[str, Any] = {"kind": "repo", "ref": str(ref), "system": "fixture"}
    kwargs.update(overrides)
    return list(DepsScanner().scan(Target(**kwargs), context))


def only(findings: list[Finding], **match: Any) -> Finding:
    hits = [
        f
        for f in findings
        if all(
            (f.params.get(key[7:]) if key.startswith("params_") else getattr(f, key))
            == value
            for key, value in match.items()
        )
    ]
    assert len(hits) == 1, (
        f"expected one finding matching {match}, got "
        f"{[(f.algorithm, f.params) for f in hits]}"
    )
    return hits[0]


# ---------------------------------------------------------------------------
# The plugin contract
# ---------------------------------------------------------------------------


def test_the_scanner_declares_its_id_and_view() -> None:
    scanner = DepsScanner()

    assert scanner.id == "deps"
    assert scanner.view == "declared"


def test_it_supports_repo_and_directory_targets_only() -> None:
    scanner = DepsScanner()

    assert scanner.supports(Target(kind="repo", ref="."))
    assert scanner.supports(Target(kind="directory", ref="."))
    assert not scanner.supports(Target(kind="image", ref="x.tar"))
    assert not scanner.supports(Target(kind="spool", ref="spool-dir"))


def test_it_is_registered() -> None:
    from core import registry

    assert "deps" in registry.available_ids()
    assert any(s.id == "deps" for s in registry.get_scanners())


def test_a_directory_with_no_manifests_yields_nothing(
    tmp_path: Path, context: ScanContext
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    assert scan(empty, context) == []


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_python_lockfile_beats_the_manifest_range(context: ScanContext) -> None:
    """THE lockfile-preferred decision, on a repo carrying both.

    `requirements.txt` says `cryptography>=41.0,<43`; `poetry.lock` pins
    42.0.5. A capability verdict on a range is a verdict on a version nobody
    has installed, so the exact one wins.
    """
    findings = scan(FIXTURES / "python_repo", context)

    cryptography = only(findings, algorithm="cryptography")
    assert cryptography.params["version"] == "42.0.5"
    assert cryptography.params.get("version_is_range") is not True
    assert cryptography.params["ecosystem"] == "pypi"
    assert "poetry.lock" in cryptography.evidence.occurrences[0].locator


def test_a_manifest_only_range_is_recorded_as_a_range_with_a_note(
    tmp_path: Path, context: ScanContext
) -> None:
    """No lockfile: the range is reported AS a range, never resolved by guess."""
    repo = tmp_path / "manifest-only"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "cryptography>=41.0,<43\nrequests>=2.31\n", encoding="utf-8"
    )

    cryptography = only(scan(repo, context), algorithm="cryptography")

    assert cryptography.params["version_is_range"] is True
    assert cryptography.params["version"] == ">=41.0,<43"
    assert "range" in cryptography.params["version_note"].lower()
    # A range cannot answer the capability question, and must not pretend to.
    assert "pqc_capable" not in cryptography.params
    assert cryptography.confidence < 1.0


def test_an_exact_pin_in_a_manifest_is_not_a_range(
    tmp_path: Path, context: ScanContext
) -> None:
    repo = tmp_path / "pinned"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pyjwt==2.8.0\n", encoding="utf-8")

    pyjwt = only(scan(repo, context), algorithm="PyJWT")

    assert pyjwt.params["version"] == "2.8.0"
    assert pyjwt.params.get("version_is_range") is not True
    assert pyjwt.confidence == 1.0


def test_pipfile_lock_is_read(tmp_path: Path, context: ScanContext) -> None:
    repo = tmp_path / "pipenv"
    repo.mkdir()
    (repo / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "cryptography": {"version": "==42.0.5"},
                    "requests": {"version": "==2.31.0"},
                }
            }
        ),
        encoding="utf-8",
    )

    findings = scan(repo, context)

    assert only(findings, algorithm="cryptography").params["version"] == "42.0.5"
    assert len(findings) == 1


def test_pyproject_dependencies_are_read(tmp_path: Path, context: ScanContext) -> None:
    repo = tmp_path / "pep621"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["pynacl>=1.5", "click>=8"]\n',
        encoding="utf-8",
    )

    pynacl = only(scan(repo, context), algorithm="PyNaCl")

    assert pynacl.params["ecosystem"] == "pypi"
    assert pynacl.params["version_is_range"] is True


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


def test_package_lock_resolves_exact_versions(context: ScanContext) -> None:
    findings = scan(FIXTURES / "node_repo", context)

    forge = only(findings, algorithm="node-forge")
    assert forge.params["version"] == "1.3.1"
    assert forge.params["ecosystem"] == "npm"
    assert forge.params["package"] == "node-forge"

    jwt = only(findings, algorithm="jsonwebtoken")
    assert jwt.params["version"] == "8.5.1"


def test_package_json_ranges_are_read_when_there_is_no_lock(
    tmp_path: Path, context: ScanContext
) -> None:
    repo = tmp_path / "npm-manifest"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"crypto-js": "^4.2.0", "left-pad": "^1.3.0"}}),
        encoding="utf-8",
    )

    cryptojs = only(scan(repo, context), algorithm="crypto-js")

    assert cryptojs.params["version"] == "^4.2.0"
    assert cryptojs.params["version_is_range"] is True


def test_yarn_lock_is_read(tmp_path: Path, context: ScanContext) -> None:
    repo = tmp_path / "yarn"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        'tweetnacl@^1.0.3:\n  version "1.0.3"\n  resolved "https://x"\n\n'
        'lodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://y"\n',
        encoding="utf-8",
    )

    findings = scan(repo, context)

    assert only(findings, algorithm="tweetnacl").params["version"] == "1.0.3"
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_go_mod_requires_are_read(context: ScanContext) -> None:
    findings = scan(FIXTURES / "go_repo", context)

    crypto = only(findings, algorithm="golang.org/x/crypto")
    assert crypto.params["version"] == "0.31.0"
    assert crypto.params["ecosystem"] == "go"
    assert "go.mod" in crypto.evidence.occurrences[0].locator


def test_the_go_stdlib_is_not_a_dependency(context: ScanContext) -> None:
    """The boundary, stated as a test.

    `crypto/aes` is in the Go standard library: it appears in no manifest and
    Scanner B must never invent it. Stdlib crypto is a CALL SITE, and finding
    those is Scanner A's job.
    """
    findings = scan(FIXTURES / "go_repo", context)

    assert not any("crypto/aes" in f.algorithm for f in findings)
    assert not any(f.algorithm.startswith("crypto/") for f in findings)


# ---------------------------------------------------------------------------
# Precision: a non-crypto dependency produces NOTHING
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["python_repo", "node_repo", "go_repo"])
def test_non_crypto_dependencies_produce_no_findings(
    fixture: str, context: ScanContext
) -> None:
    """An inventory that lists `lodash` is an inventory nobody will read."""
    findings = scan(FIXTURES / fixture, context)
    decoys = set(ANSWERS["decoys"])

    hits = [
        f
        for f in findings
        if f.params.get("package") in decoys or f.algorithm in decoys
    ]
    assert hits == [], f"decoy dependencies produced findings: {hits}"


def test_every_finding_is_a_library_asset(context: ScanContext) -> None:
    for fixture in ("python_repo", "node_repo", "go_repo"):
        for finding in scan(FIXTURES / fixture, context):
            assert finding.asset_type == "library"
            assert finding.view == "declared"
            assert finding.scanner_id == "deps"
            assert finding.evidence.occurrences


# ---------------------------------------------------------------------------
# The knowledge pack decides capability (ADR-0017)
# ---------------------------------------------------------------------------


def test_a_version_below_the_pqc_floor_is_reported_not_capable(tmp_path: Path) -> None:
    pack = _pack_with(tmp_path, "cryptography", floor="99.0.0", verified=True)
    repo = tmp_path / "below"
    repo.mkdir()
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

    finding = only(scan(repo, pack), algorithm="cryptography")

    assert finding.params["pqc_capable"] is False


def test_a_version_at_or_above_the_pqc_floor_is_reported_capable(
    tmp_path: Path,
) -> None:
    pack = _pack_with(tmp_path, "cryptography", floor="42.0.0", verified=True)
    repo = tmp_path / "above"
    repo.mkdir()
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

    finding = only(scan(repo, pack), algorithm="cryptography")

    assert finding.params["pqc_capable"] is True


def test_an_unverified_floor_yields_no_capability_verdict(tmp_path: Path) -> None:
    """ADR-0017 in the deps scanner: an unconfirmed fact cannot score.

    A version filled in without a confirmed source must produce NO
    `pqc_capable` parameter -- not `false`, which is a claim.
    """
    pack = _pack_with(tmp_path, "cryptography", floor="42.0.0", verified=False)
    repo = tmp_path / "unverified"
    repo.mkdir()
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

    finding = only(scan(repo, pack), algorithm="cryptography")

    assert "pqc_capable" not in finding.params


def test_an_end_of_life_version_is_flagged(tmp_path: Path) -> None:
    pack = _pack_with(tmp_path, "cryptography", floor=None, eol="2020-01-01")
    repo = tmp_path / "eol"
    repo.mkdir()
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

    finding = only(scan(repo, pack), algorithm="cryptography")

    assert finding.params["eol"] == "2020-01-01"


def _pack_with(
    tmp_path: Path,
    package: str,
    *,
    floor: str | None,
    verified: bool = True,
    eol: str | None = None,
) -> ScanContext:
    """A knowledge dir holding one entry, so a capability rule is unambiguous."""
    knowledge = tmp_path / f"knowledge-{package}-{floor}-{verified}-{eol}"
    knowledge.mkdir(parents=True, exist_ok=True)
    (knowledge / "libraries.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "libraries": [
                    {
                        "name": "cryptography",
                        "ecosystem": "pypi",
                        "packages": [package],
                        "provides": ["RSA"],
                        "pqc_capable_from": floor,
                        "pqc_capable_verified": verified,
                        "pqc_capable_source": "test fixture",
                        "eol": eol,
                        "source": "test fixture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return ScanContext(knowledge_dir=knowledge, scratch_dir=tmp_path / "scratch")


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_a_malformed_manifest_is_skipped_not_fatal(
    context: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    """Hostile input degrades the scan, it does not end it (ADR-0003)."""
    import logging

    with caplog.at_level(logging.WARNING):
        findings = scan(FIXTURES / "broken_repo", context)

    assert findings == []
    assert any("package-lock.json" in record.getMessage() for record in caplog.records)


def test_a_malformed_manifest_does_not_stop_the_others(
    tmp_path: Path, context: ScanContext, caplog: pytest.LogCaptureFixture
) -> None:
    import logging
    import shutil

    repo = tmp_path / "mixed"
    repo.mkdir()
    shutil.copy(
        FIXTURES / "broken_repo" / "package-lock.json", repo / "package-lock.json"
    )
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        findings = scan(repo, context)

    assert only(findings, algorithm="cryptography").params["version"] == "42.0.5"


def test_vendored_and_build_directories_are_skipped(
    tmp_path: Path, context: ScanContext
) -> None:
    """A dependency's own manifest is not this project's dependency."""
    repo = tmp_path / "vendored"
    nested = repo / "node_modules" / "some-dep"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps({"dependencies": {"node-forge": "^1.3.1"}}), encoding="utf-8"
    )
    (repo / "requirements.txt").write_text("pyjwt==2.8.0\n", encoding="utf-8")

    findings = scan(repo, context)

    assert [f.algorithm for f in findings] == ["PyJWT"]


# ---------------------------------------------------------------------------
# The library / source-algorithm boundary (ADR-0002)
# ---------------------------------------------------------------------------


def test_a_library_finding_does_not_collide_with_a_source_finding(
    tmp_path: Path, context: ScanContext
) -> None:
    """`cryptography` the dependency and `RSA` the call site stay distinct.

    Same repo, both scanners, one CBOM: the library and the algorithm are
    different assets and must not merge into one component.
    """
    from core.identity import finding_identity
    from core.normalise import normalise
    from scanners.source import SourceScanner

    repo = tmp_path / "both"
    repo.mkdir()
    (repo / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")
    (repo / "keys.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    target = Target(kind="repo", ref=str(repo), system="fixture")

    deps = list(DepsScanner().scan(target, context))
    source = list(SourceScanner().scan(target, context))
    assert deps and source

    identities = {finding_identity(f, target) for f in deps + source}
    assert len(identities) == len(deps) + len(source)

    _, cbom_json = normalise(deps + source, target)
    document = json.loads(cbom_json)
    # A library is not a CycloneDX crypto asset -- the 1.6 `assetType`
    # vocabulary is algorithm/certificate/protocol/relatedCryptoMaterial -- so
    # the normaliser omits `cryptoProperties` for one and the kind lives in
    # `ecdat:asset_type`. The algorithm beside it DOES get cryptoProperties,
    # which is the shape difference this test is really about.
    kinds = {
        c["name"]: next(
            p["value"] for p in c["properties"] if p["name"] == "ecdat:asset_type"
        )
        for c in document["components"]
    }
    assert kinds["cryptography"] == "library"
    assert kinds["RSA-2048"] == "algorithm"

    library = next(c for c in document["components"] if c["name"] == "cryptography")
    algorithm = next(c for c in document["components"] if c["name"] == "RSA-2048")
    assert "cryptoProperties" not in library
    assert algorithm["cryptoProperties"]["assetType"] == "algorithm"


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


@pytest.mark.validation
def test_a_deps_scan_produces_a_schema_valid_cbom(context: ScanContext) -> None:
    from core.normalise import normalise, validate_cbom_json

    target = Target(kind="repo", ref=str(FIXTURES / "node_repo"), system="fixture")
    findings = list(DepsScanner().scan(target, context))

    _, cbom_json = normalise(findings, target)
    validate_cbom_json(cbom_json)

    document = json.loads(cbom_json)
    assert document["components"]
    for component in document["components"]:
        values = {p["name"]: p["value"] for p in component["properties"]}
        assert values["ecdat:view"] == "declared"
        assert values["ecdat:asset_type"] == "library"


def test_determinism_same_repo_same_findings(context: ScanContext) -> None:
    first = scan(FIXTURES / "python_repo", context)
    second = scan(FIXTURES / "python_repo", context)

    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


# ---------------------------------------------------------------------------
# RECALL / PRECISION against the answer key
# ---------------------------------------------------------------------------


def test_recall_and_precision_against_the_answer_key(
    context: ScanContext, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured claim, printed so it is never quoted without its basis."""
    findings: list[Finding] = []
    for fixture in ("python_repo", "node_repo", "go_repo", "broken_repo"):
        findings.extend(scan(FIXTURES / fixture, context))

    expected = ANSWERS["findings"]
    decoys = set(ANSWERS["decoys"])

    found: list[str] = []
    missed: list[str] = []
    for entry in expected:
        hit = next(
            (
                f
                for f in findings
                if f.algorithm == entry["library"]
                and f.params.get("version") == entry["version"]
                and entry["locator_contains"] in f.evidence.occurrences[0].locator
            ),
            None,
        )
        (found if hit else missed).append(entry["id"])

    decoy_hits = [
        f.params.get("package") for f in findings if f.params.get("package") in decoys
    ]

    recall = len(found) / len(expected)
    precision = 1.0 - (len(decoy_hits) / max(1, len(findings)))

    with capsys.disabled():
        print(f"\n  deps scanner vs {FIXTURES}/answer_key.yaml")
        print(f"  RECALL    {recall:6.1%}  ({len(found)}/{len(expected)} planted)")
        print(
            f"  PRECISION {precision:6.1%}  "
            f"({len(decoy_hits)} decoy hit(s) of {len(findings)} emitted)"
        )
        for miss in missed:
            print(f"    MISS {miss}")
        for hit in decoy_hits:
            print(f"    DECOY FIRED {hit}")

    assert recall >= 0.9, f"missed {missed}"
    assert precision == 1.0, f"decoys fired: {decoy_hits}"
