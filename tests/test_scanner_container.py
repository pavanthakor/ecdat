"""Scanner C: container image crypto detection, the first `shipped` view.

Two layers of test, scored differently, for the reason ADR-0006 sets out:

* **LOGIC** -- committed synthetic tarballs under
  ``testdata/images/synthetic/``. No Docker, no network, fixed inputs. These
  measure the parser, and precision is asserted at exactly 1.0.
* **INTEGRATION** -- the real ``ubuntu:22.04`` and ``alpine:3.22``, marked
  ``docker`` and skipped automatically when Docker or the image is absent.
  Must-include assertions only, because those tags move under us.

The security-critical assertions here are the negative ones: a private key is
recorded by presence, location and public-key fingerprint, and its bytes must
appear nowhere in any Finding (PUNCHLIST #3, extended from source to shipped).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import registry, store
from core.normalise import normalise, validate_cbom_json
from core.orchestrator import run_scan
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from scanners.container import ContainerScanner
from tests.factories import finding as declared_finding
from tests.factories import occurrence

SYNTHETIC_DIR = Path("testdata/images/synthetic")
ANSWER_KEY = Path("testdata/images/answer_key.yaml")
KNOWLEDGE_DIR = Path("knowledge")

ANSWERS: dict[str, Any] = yaml.safe_load(ANSWER_KEY.read_text(encoding="utf-8"))
SYNTHETIC: dict[str, Any] = ANSWERS["synthetic"]


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR,
        scratch_dir=tmp_path_factory.mktemp("container-scratch"),
    )


def _scan(name: str, context: ScanContext) -> list[Finding]:
    target = Target(kind="image", ref=str(SYNTHETIC_DIR / name), system="fixtures")
    return list(ContainerScanner().scan(target, context))


@pytest.fixture(scope="module")
def dpkg_findings(context: ScanContext) -> list[Finding]:
    return _scan("dpkg-openssl302.tar", context)


@pytest.fixture(scope="module")
def apk_findings(context: ScanContext) -> list[Finding]:
    return _scan("apk-openssl357.tar", context)


@pytest.fixture(scope="module")
def cert_findings(context: ScanContext) -> list[Finding]:
    return _scan("certs-and-key.tar", context)


def _libraries(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.asset_type == "library"]


def _only(findings: list[Finding], **match: Any) -> Finding:
    hits = [
        f
        for f in findings
        if all(
            getattr(f, key, None) == value or f.params.get(key) == value
            for key, value in match.items()
        )
    ]
    assert len(hits) == 1, f"expected exactly one finding matching {match}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------------
# Plugin contract
# --------------------------------------------------------------------------


def test_satisfies_the_scanner_protocol() -> None:
    assert isinstance(ContainerScanner(), Scanner)


def test_identity_and_view() -> None:
    scanner = ContainerScanner()
    assert scanner.id == "container"
    assert scanner.view == "shipped"


def test_supports_only_image_targets() -> None:
    scanner = ContainerScanner()
    assert scanner.supports(Target(kind="image", ref="x.tar"))
    for kind in ("repo", "directory", "host", "endpoint"):
        assert not scanner.supports(Target(kind=kind, ref="x"))


def test_registered_in_the_registry() -> None:
    assert registry.available_ids() == ["container", "source"]
    (scanner,) = registry.get_scanners(["container"])
    assert isinstance(scanner, ContainerScanner)


# --------------------------------------------------------------------------
# Package databases
# --------------------------------------------------------------------------


def test_dpkg_status_yields_openssl_302(dpkg_findings: list[Finding]) -> None:
    openssl = _only(dpkg_findings, algorithm="OpenSSL")

    assert openssl.asset_type == "library"
    assert openssl.view == "shipped"
    assert openssl.params["version"] == "3.0.2"
    assert openssl.params["package"] == "libssl3"
    assert openssl.params["package_version"] == "3.0.2-0ubuntu1.10"


def test_dpkg_status_also_finds_gnutls(dpkg_findings: list[Finding]) -> None:
    gnutls = _only(dpkg_findings, algorithm="GnuTLS")
    assert gnutls.params["version"] == "3.7.3"


def test_non_crypto_packages_are_not_reported(dpkg_findings: list[Finding]) -> None:
    """libc6 and perl-base are in the same status file and must be ignored."""
    reported = {f.params.get("package") for f in _libraries(dpkg_findings)}
    assert "libc6" not in reported
    assert "perl-base" not in reported


def test_apk_installed_yields_openssl_357(apk_findings: list[Finding]) -> None:
    libssl = _only(apk_findings, package="libssl3")

    assert libssl.algorithm == "OpenSSL"
    assert libssl.params["version"] == "3.5.7"
    assert libssl.params["package_version"] == "3.5.7-r0"


def test_apk_reports_both_openssl_packages(apk_findings: list[Finding]) -> None:
    packages = {f.params.get("package") for f in _libraries(apk_findings)}
    assert packages == {"libssl3", "libcrypto3"}


def test_apk_non_crypto_packages_are_not_reported(
    apk_findings: list[Finding],
) -> None:
    packages = {f.params.get("package") for f in _libraries(apk_findings)}
    assert "musl" not in packages
    assert "busybox" not in packages


def test_pqc_capability_is_decided_from_the_knowledge_pack(
    dpkg_findings: list[Finding], apk_findings: list[Finding]
) -> None:
    """The drift demo's whole point: 3.0.2 cannot do ML-KEM, 3.5.7 can."""
    assert _only(dpkg_findings, algorithm="OpenSSL").params["pqc_capable"] is False
    assert _only(apk_findings, package="libssl3").params["pqc_capable"] is True


# --------------------------------------------------------------------------
# Evidence: layer digests and Dockerfile instructions
# --------------------------------------------------------------------------


def test_locator_is_layer_digest_and_in_layer_path(
    dpkg_findings: list[Finding],
) -> None:
    openssl = _only(dpkg_findings, algorithm="OpenSSL")
    (occ,) = openssl.evidence.occurrences

    digest, _, path = occ.locator.partition("/")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert path == "var/lib/dpkg/status"
    assert occ.view == "shipped"


def test_layer_digest_matches_the_images_diff_id(
    dpkg_findings: list[Finding],
) -> None:
    """The digest is the real diff_id from the image config, not invented."""
    with tarfile.open(SYNTHETIC_DIR / "dpkg-openssl302.tar") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())  # type: ignore[union-attr]
        config = json.loads(tar.extractfile(manifest[0]["Config"]).read())  # type: ignore[union-attr]
    expected = set(config["rootfs"]["diff_ids"])

    for finding in dpkg_findings:
        for occ in finding.evidence.occurrences:
            assert occ.locator.split("/")[0] in expected


def test_the_creating_instruction_is_recorded(cert_findings: list[Finding]) -> None:
    certificate = _only(cert_findings, asset_type="certificate")
    assert "COPY dir:tls-material" in certificate.params["created_by"]


def test_findings_from_the_second_layer_are_found(
    cert_findings: list[Finding],
) -> None:
    """Crypto material lives only in layer 2; layer 1 must not stop the walk."""
    assert cert_findings


# --------------------------------------------------------------------------
# Certificates are parsed; keys are not
# --------------------------------------------------------------------------


def test_certificate_is_parsed(cert_findings: list[Finding]) -> None:
    certificate = _only(cert_findings, asset_type="certificate")
    params = certificate.params

    assert certificate.algorithm == "RSA"
    assert params["key_size"] == 2048
    assert params["subject_common_name"] == "api.quantumbank.invalid"
    assert params["issuer_common_name"] == "api.quantumbank.invalid"
    assert params["self_signed"] is True
    assert params["signature_algorithm"] == "sha256WithRSAEncryption"
    assert params["not_valid_before"] == "2024-01-01T00:00:00+00:00"
    assert params["not_valid_after"] == "2034-01-01T00:00:00+00:00"
    assert params["format"] == "X.509"


def test_private_key_is_recorded_by_presence_not_content(
    cert_findings: list[Finding],
) -> None:
    key = _only(cert_findings, asset_type="key")

    assert key.algorithm == "RSA"
    assert key.params["key_size"] == 2048
    assert key.params["material"] == "private-key"
    # A fingerprint of the PUBLIC key: correlatable across images, leaks nothing.
    assert key.params["public_key_fingerprint"].startswith("sha256:")
    for occ in key.evidence.occurrences:
        assert occ.snippet == "<redacted key material>"


def test_no_private_key_bytes_reach_any_finding(
    cert_findings: list[Finding],
) -> None:
    """Read the planted key out of the fixture and prove none of it escaped."""
    with tarfile.open(SYNTHETIC_DIR / "certs-and-key.tar") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())  # type: ignore[union-attr]
        layer = manifest[0]["Layers"][-1]
        with tarfile.open(fileobj=tar.extractfile(layer)) as inner:
            handle = inner.extractfile("etc/ssl/private/api.quantumbank.key")
            assert handle is not None
            key_pem = handle.read().decode("ascii")

    body = [line for line in key_pem.splitlines() if "-----" not in line and line]
    assert body, "fixture key has no body to leak"

    blob = json.dumps([f.model_dump() for f in cert_findings], default=str)
    for line in body:
        assert line not in blob, "private key material escaped into a Finding"
    for sentinel in ANSWERS["secret_sentinels"]:
        assert sentinel not in blob


def test_the_certificates_public_key_is_allowed_through(
    cert_findings: list[Finding],
) -> None:
    """Public metadata is the point; only the private half is withheld."""
    certificate = _only(cert_findings, asset_type="certificate")
    assert certificate.evidence.occurrences[0].snippet is not None
    assert "api.quantumbank.invalid" in certificate.evidence.occurrences[0].snippet


# --------------------------------------------------------------------------
# Failing loud
# --------------------------------------------------------------------------


def test_a_missing_image_raises(context: ScanContext) -> None:
    import scanners.container as container

    with pytest.raises(container.ImageUnreadableError):
        list(
            ContainerScanner().scan(
                Target(kind="image", ref="testdata/images/nope.tar"), context
            )
        )


def test_a_file_that_is_not_an_image_raises(
    context: ScanContext, tmp_path: Path
) -> None:
    import scanners.container as container

    junk = tmp_path / "not-an-image.tar"
    junk.write_bytes(b"this is not a tar archive at all")

    with pytest.raises(container.ImageUnreadableError):
        list(ContainerScanner().scan(Target(kind="image", ref=str(junk)), context))


def test_a_tar_without_a_manifest_raises(context: ScanContext, tmp_path: Path) -> None:
    import scanners.container as container

    empty = tmp_path / "empty.tar"
    with tarfile.open(empty, "w"):
        pass

    with pytest.raises(container.ImageLayoutError):
        list(ContainerScanner().scan(Target(kind="image", ref=str(empty)), context))


def test_a_missing_knowledge_pack_raises(tmp_path: Path) -> None:
    import scanners.container as container

    bare = ScanContext(knowledge_dir=tmp_path / "nothing", scratch_dir=tmp_path)
    with pytest.raises(container.LibraryPackMissingError):
        list(
            ContainerScanner().scan(
                Target(kind="image", ref=str(SYNTHETIC_DIR / "dpkg-openssl302.tar")),
                bare,
            )
        )


# --------------------------------------------------------------------------
# Offline and read-only
# --------------------------------------------------------------------------


def test_scan_makes_no_network_calls(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing in the scan path may open a socket. The air-gap guarantee.

    Patched at ``socket.socket`` rather than at a higher level on purpose: it
    catches urllib, requests, httpx and a raw connect alike, so the assertion
    survives someone later reaching for a different HTTP client.
    """
    import socket

    def forbidden(*args: object, **kwargs: object) -> object:  # noqa: ARG001
        raise AssertionError("the container scan path opened a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    assert _scan("dpkg-openssl302.tar", context)


def test_scan_does_not_modify_the_image(context: ScanContext) -> None:
    image = SYNTHETIC_DIR / "dpkg-openssl302.tar"
    before = image.read_bytes()

    _scan("dpkg-openssl302.tar", context)

    assert image.read_bytes() == before


def test_scan_is_deterministic(context: ScanContext) -> None:
    first = _scan("apk-openssl357.tar", context)
    second = _scan("apk-openssl357.tar", context)
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


# --------------------------------------------------------------------------
# End to end, and the multi-view proof
# --------------------------------------------------------------------------


@pytest.mark.validation
def test_end_to_end_image_scan_produces_a_valid_cbom(context: ScanContext) -> None:
    target = Target(
        kind="image",
        ref=str(SYNTHETIC_DIR / "dpkg-openssl302.tar"),
        system="quantumbank",
    )

    scan_id = run_scan(target, registry.get_scanners(None), context)

    record = store.get_scan(scan_id)
    assert record is not None
    validate_cbom_json(record.cbom_json)

    document = json.loads(record.cbom_json)
    names = {component["name"] for component in document["components"]}
    assert "OpenSSL" in names
    assert "GnuTLS" in names

    for component in document["components"]:
        views = [
            p["value"]
            for p in component.get("properties", [])
            if p["name"] == "ecdat:view"
        ]
        assert views == ["shipped"]


def test_the_source_scanner_skips_an_image_target() -> None:
    """Only the container scanner should have run above."""
    from scanners.source import SourceScanner

    assert not SourceScanner().supports(Target(kind="image", ref="x.tar"))


@pytest.mark.validation
def test_declared_and_shipped_stay_separate_components(
    dpkg_findings: list[Finding],
) -> None:
    """ADR-0002: the same library in two views must NOT merge into one.

    Destroying that separation would destroy the signal three-view drift
    detection exists to find.
    """
    shipped = _only(dpkg_findings, algorithm="OpenSSL")
    declared = declared_finding(
        scanner_id="source",
        view="declared",
        asset_type="library",
        primitive="unknown",
        algorithm="OpenSSL",
        params={"version": "3.0.2"},
        usage="unknown",
        occurrences=[
            occurrence(view="declared", locator="requirements.txt:4", snippet=None)
        ],
    )

    target = Target(kind="image", ref="quantumbank:1.4", system="quantumbank")
    bom, cbom_json = normalise([declared, shipped], target)

    assert len(bom.components) == 2, "declared and shipped merged into one component"
    refs = {component.bom_ref.value for component in bom.components}
    assert len(refs) == 2

    document = json.loads(cbom_json)
    views = sorted(
        p["value"]
        for component in document["components"]
        for p in component.get("properties", [])
        if p["name"] == "ecdat:view"
    )
    assert views == ["declared", "shipped"]


# --------------------------------------------------------------------------
# The score, over the synthetic set
# --------------------------------------------------------------------------


def _actual_key(finding: Finding) -> tuple[str, str, str]:
    """(asset_type, algorithm, discriminator) -- how findings are scored."""
    if finding.asset_type == "library":
        return ("library", finding.algorithm, str(finding.params.get("package")))
    path = finding.evidence.occurrences[0].locator.partition("/")[2]
    return (finding.asset_type, finding.algorithm, path)


def _expected_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    if entry["asset_type"] == "library":
        return ("library", entry["algorithm"], str(entry["package"]))
    return (entry["asset_type"], entry["algorithm"], entry["path"])


def test_recall_and_precision_over_the_synthetic_images(
    dpkg_findings: list[Finding],
    apk_findings: list[Finding],
    cert_findings: list[Finding],
    capsys: Any,
) -> None:
    produced = {
        "dpkg-openssl302.tar": dpkg_findings,
        "apk-openssl357.tar": apk_findings,
        "certs-and-key.tar": cert_findings,
    }

    expected: Counter[tuple[str, tuple[str, str, str]]] = Counter()
    for image, spec in SYNTHETIC.items():
        for entry in spec["findings"]:
            expected[(image, _expected_key(entry))] += entry["count"]

    actual: Counter[tuple[str, tuple[str, str, str]]] = Counter(
        (image, _actual_key(f))
        for image, findings in produced.items()
        for f in findings
    )

    planted = sum(expected.values())
    emitted = sum(actual.values())
    true_positives = sum(min(count, actual[key]) for key, count in expected.items())

    recall = true_positives / planted
    precision = true_positives / emitted if emitted else 0.0
    missed = sorted(str(k) for k, c in expected.items() if actual[k] < c)
    spurious = sorted(str(k) for k in actual if k not in expected)

    with capsys.disabled():
        print(f"\n  RECALL    {recall:6.1%}  ({true_positives}/{planted} planted)")
        print(f"  PRECISION {precision:6.1%}  ({true_positives}/{emitted} emitted)")
        if missed:
            print(f"  MISSED    {missed}")
        if spurious:
            print(f"  SPURIOUS  {spurious}")

    assert recall >= 0.9, f"recall {recall:.1%}; missed {missed}"
    assert precision == 1.0, f"precision {precision:.1%}; spurious {spurious}"


# --------------------------------------------------------------------------
# INTEGRATION -- real images. Skipped unless Docker and the image are present.
# --------------------------------------------------------------------------


def _docker(*args: str, timeout: int) -> subprocess.CompletedProcess[bytes] | None:
    """Run a docker command, or None if docker is not usable at all."""
    binary = shutil.which("docker")
    if binary is None:
        return None
    try:
        return subprocess.run(  # noqa: S603 - argv list, no shell, resolved path
            [binary, *args], capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _docker_available() -> bool:
    result = _docker("info", timeout=20)
    return result is not None and result.returncode == 0


def _has_image(reference: str) -> bool:
    result = _docker("image", "inspect", reference, timeout=30)
    return result is not None and result.returncode == 0


@pytest.mark.docker
@pytest.mark.parametrize("reference", sorted(ANSWERS["real_images"]))
def test_real_image_libraries(
    reference: str, context: ScanContext, tmp_path: Path, capsys: Any
) -> None:
    if not _docker_available():
        pytest.skip("docker is not available")
    if not _has_image(reference):
        pytest.skip(f"image {reference} is not present locally (docker pull it first)")

    saved = tmp_path / "image.tar"
    result = _docker("save", "-o", str(saved), reference, timeout=300)
    if result is None or result.returncode != 0:
        detail = result.stderr.decode()[:200] if result else "docker unavailable"
        pytest.skip(f"docker save failed: {detail}")

    findings = list(
        ContainerScanner().scan(Target(kind="image", ref=str(saved)), context)
    )
    libraries = _libraries(findings)

    with capsys.disabled():
        print(f"\n  {reference}: {len(libraries)} crypto libraries")
        for library in sorted(libraries, key=lambda f: str(f.params.get("package"))):
            print(
                f"    {library.params.get('package'):16s} "
                f"{library.algorithm} {library.params.get('version')} "
                f"pqc_capable={library.params.get('pqc_capable')}"
            )

    for wanted in ANSWERS["real_images"][reference]["must_include"]:
        matches = [
            f
            for f in libraries
            if f.algorithm == wanted["algorithm"]
            and f.params.get("package") == wanted["package"]
            and str(f.params.get("version", "")).startswith(wanted["version_prefix"])
        ]
        assert matches, (
            f"{reference}: expected {wanted['package']} "
            f"{wanted['algorithm']} {wanted['version_prefix']}*, got "
            f"{[(f.params.get('package'), f.params.get('version')) for f in libraries]}"
        )
        assert matches[0].params["pqc_capable"] is wanted["pqc_capable"]
        assert matches[0].view == "shipped"
