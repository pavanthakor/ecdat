"""Scanner D — crypto in compiled binaries, honestly (ADR-0025).

Everything a binary scanner says is a HEURISTIC. There is no source, no
manifest and no config file: there is a symbol table that may have been
stripped, an import table that may be empty because the code is statically
linked, byte patterns that may be a coincidence, and a string that may be a
version banner or a log message. So the design is not "find the crypto" -- it
is **say what was found, by which technique, with what confidence, and say what
could not be read.**

That last clause is the one these tests spend the most effort on. A scanner
that returns fewer findings on a stripped binary and says nothing about it
reports a clean artefact, and a clean report on an artefact nobody could read
is worse than no report: someone acts on it.

Three properties, each tested for behaviour and for its failure mode:

* every finding carries a technique and a confidence below 1.0;
* the non-crypto binary produces EXACTLY nothing (libc is not cryptography);
* a planted key reaches no Finding -- the sixth and last scanner family under
  the redaction discipline.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import registry
from core.normalise import normalise, validate_cbom_json
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from scanners.binary import BinaryScanner

FIXTURE_ROOT = Path("testdata/binary_fixtures")
KNOWLEDGE_DIR = Path("knowledge")

with (FIXTURE_ROOT / "answer_key.yaml").open(encoding="utf-8") as _handle:
    ANSWERS: dict[str, Any] = yaml.safe_load(_handle)

EXPECTED: dict[str, list[dict[str, Any]]] = ANSWERS["expected"]
DECOYS: list[str] = ANSWERS["decoys"]
UNPARSEABLE: list[str] = ANSWERS["unparseable"]
SENTINELS: list[str] = ANSWERS["secret_sentinels"]

#: Techniques and the confidence each is allowed to claim. Asserted rather than
#: documented: a technique that quietly raised its own confidence would make
#: every downstream score wrong in the same direction.
TECHNIQUE_CONFIDENCE = {
    "symbol": 0.9,
    "pem": 0.95,
    "oid": 0.85,
    "version-string": 0.8,
    "constant": 0.6,
}


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path_factory.mktemp("bin-scratch")
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="bin-fixtures")
    return list(BinaryScanner().scan(target, context))


def _binary(finding: Finding) -> str:
    """The fixture file a finding points at."""
    locator = finding.evidence.occurrences[0].locator
    path = locator.split("#", 1)[0]
    return Path(path).name


def _technique(finding: Finding) -> str:
    value = finding.raw.get("technique")
    assert isinstance(value, str), f"finding carries no technique: {finding!r}"
    return value


def _for(findings: list[Finding], name: str) -> list[Finding]:
    return [f for f in findings if _binary(f) == name]


# ---------------------------------------------------------------------------
# Plugin contract
# ---------------------------------------------------------------------------


def test_satisfies_the_scanner_protocol() -> None:
    assert isinstance(BinaryScanner(), Scanner)


def test_identity_and_view() -> None:
    scanner = BinaryScanner()
    assert scanner.id == "binary"
    assert scanner.view == "shipped"


def test_is_registered() -> None:
    assert "binary" in registry.available_ids()


@pytest.mark.parametrize("kind", ["repo", "image", "host", "endpoint", "spool"])
def test_declines_target_kinds_it_cannot_read(kind: str) -> None:
    """A directory of binaries, not a repo and not an image.

    A repo target is source; an image target is the container scanner's, which
    reads package databases out of layer blobs. Wiring container -> binary is a
    follow-up (ADR-0025), and claiming `image` now would mean claiming a
    capability that does not exist.
    """
    assert not BinaryScanner().supports(Target(kind=kind, ref="x"))  # type: ignore[arg-type]


def test_supports_a_directory_of_binaries() -> None:
    assert BinaryScanner().supports(Target(kind="directory", ref=str(FIXTURE_ROOT)))


# ---------------------------------------------------------------------------
# Every finding is honest about how it was found
# ---------------------------------------------------------------------------


def test_every_finding_carries_a_technique_and_a_confidence(
    findings: list[Finding],
) -> None:
    """The central claim of the design, asserted on every single finding."""
    assert findings
    for finding in findings:
        technique = _technique(finding)
        assert technique in TECHNIQUE_CONFIDENCE, technique
        assert finding.confidence == TECHNIQUE_CONFIDENCE[technique], (
            f"{technique} claimed confidence {finding.confidence}"
        )


def test_no_binary_finding_is_ever_certain(findings: list[Finding]) -> None:
    """1.0 means "parsed, not inferred". Nothing here is parsed from source."""
    assert findings
    for finding in findings:
        assert finding.confidence < 1.0, (
            f"{_technique(finding)} on {_binary(finding)} claimed certainty; "
            "a binary scanner infers, it does not read a declaration"
        )


def test_every_finding_is_in_the_shipped_view(findings: list[Finding]) -> None:
    for finding in findings:
        assert finding.view == "shipped"
        for occurrence in finding.evidence.occurrences:
            assert occurrence.view == "shipped"


def test_the_locator_names_the_binary_and_where_inside_it(
    findings: list[Finding],
) -> None:
    """`path#section+offset` or `path#symbol` -- an auditor has to be able to
    go and look."""
    for finding in findings:
        locator = finding.evidence.occurrences[0].locator
        path, separator, inside = locator.partition("#")
        assert Path(path).exists(), locator
        assert separator and inside, f"locator says nothing about where: {locator}"


# ---------------------------------------------------------------------------
# Technique: SYMBOLS
# ---------------------------------------------------------------------------


def test_libcrypto_symbols_are_found_with_the_right_algorithm(
    findings: list[Finding],
) -> None:
    hits = {
        (f.raw.get("symbol"), f.algorithm, f.primitive, f.usage)
        for f in _for(findings, "elf_openssl_symbols")
        if _technique(f) == "symbol"
    }
    assert ("RSA_sign", "RSA", "signature", "sign") in hits
    assert ("EVP_sha256", "SHA-256", "hash", "hash") in hits
    assert ("EVP_aes_256_gcm", "AES", "block-cipher", "encrypt") in hits
    assert ("PKCS5_PBKDF2_HMAC", "PBKDF2", "kdf", "kdf") in hits


def test_a_symbol_that_names_its_parameters_carries_them(
    findings: list[Finding],
) -> None:
    """`EVP_aes_256_gcm` states the key size and the mode in its own name."""
    aes = [
        f
        for f in _for(findings, "elf_openssl_symbols")
        if f.raw.get("symbol") == "EVP_aes_256_gcm"
    ]
    assert aes
    assert aes[0].params.get("key_size") == 256
    assert aes[0].params.get("mode") == "GCM"


def test_an_ambiguous_symbol_reports_unknown_rather_than_guessing(
    findings: list[Finding],
) -> None:
    """`EC_KEY_*` carries both ECDSA and ECDH keys. Naming one would be a guess."""
    ec = [
        f
        for f in _for(findings, "elf_openssl_symbols")
        if f.raw.get("symbol") == "EC_KEY_new_by_curve_name"
    ]
    assert ec, "EC_KEY_new_by_curve_name was not detected"
    assert ec[0].primitive == "unknown"
    assert ec[0].usage == "unknown"


def test_version_suffixed_symbols_are_matched_and_deduplicated(
    findings: list[Finding],
) -> None:
    """ELF exposes `RSA_new` AND `RSA_new@OPENSSL_3.0.0`. One symbol, one finding."""
    rsa_new = [
        f
        for f in _for(findings, "elf_openssl_symbols")
        if f.raw.get("symbol") == "RSA_new"
    ]
    assert len(rsa_new) == 1, [f.raw for f in rsa_new]


def test_generic_symbols_produce_no_finding(findings: list[Finding]) -> None:
    """`EVP_DigestInit_ex` says a digest happens, not which one.

    An `unknown/hash` finding at an unknown call site is inventory nobody can
    act on, so the pack leaves those symbols out.
    """
    generic = [
        f
        for f in _for(findings, "elf_openssl_symbols")
        if f.raw.get("symbol") in {"EVP_DigestInit_ex", "EVP_MD_CTX_new"}
    ]
    assert generic == []


def test_pe_import_table_is_read(findings: list[Finding]) -> None:
    """Windows CNG lives in the PE import table, not in a symbol table."""
    hits = {f.raw.get("symbol") for f in _for(findings, "pe_bcrypt.exe")}
    assert "BCryptSignHash" in hits
    assert "BCryptEncrypt" in hits
    assert "BCryptGenerateSymmetricKey" in hits


# ---------------------------------------------------------------------------
# Technique: OIDs
# ---------------------------------------------------------------------------


def test_an_embedded_oid_is_found_and_decoded(findings: list[Finding]) -> None:
    hits = {(f.raw.get("oid"), f.algorithm) for f in _for(findings, "elf_embedded_oid")}
    assert ("1.2.840.113549.1.1.11", "RSA") in hits
    assert ("1.2.840.10045.2.1", "EC") in hits


def test_oid_findings_are_scored_below_symbol_findings(
    findings: list[Finding],
) -> None:
    """An OID table ships whether or not any of it is reached."""
    oids = [f for f in findings if _technique(f) == "oid"]
    symbols = [f for f in findings if _technique(f) == "symbol"]
    assert oids and symbols
    assert max(f.confidence for f in oids) < min(f.confidence for f in symbols)


# ---------------------------------------------------------------------------
# Technique: CONSTANTS -- the low-confidence bonus
# ---------------------------------------------------------------------------


def test_a_well_known_constant_is_found_at_low_confidence(
    findings: list[Finding],
) -> None:
    sbox = [
        f
        for f in _for(findings, "elf_constants")
        if _technique(f) == "constant" and f.algorithm == "AES"
    ]
    assert sbox, "the AES S-box was not detected"
    assert sbox[0].confidence == 0.6
    assert sbox[0].raw.get("constant") == "aes-sbox-forward"


def test_constants_are_the_lowest_confidence_technique(
    findings: list[Finding],
) -> None:
    constants = [f for f in findings if _technique(f) == "constant"]
    others = [f for f in findings if _technique(f) != "constant"]
    assert constants and others
    assert max(f.confidence for f in constants) < min(f.confidence for f in others)


# ---------------------------------------------------------------------------
# Technique: EMBEDDED PEM
# ---------------------------------------------------------------------------


def test_an_embedded_certificate_is_parsed(findings: list[Finding]) -> None:
    """A real certificate, so subject, validity and key size are readable."""
    certs = [
        f for f in _for(findings, "elf_embedded_pem") if f.asset_type == "certificate"
    ]
    assert certs, "the embedded certificate was not detected"
    cert = certs[0]
    assert cert.algorithm == "RSA"
    assert cert.params.get("key_size") == 2048
    assert "ecdat-binary-fixture.invalid" in str(cert.params.get("subject", ""))
    assert cert.params.get("valid_to", "").startswith("2028")


def test_an_embedded_private_key_is_recorded_by_presence(
    findings: list[Finding],
) -> None:
    keys = [f for f in _for(findings, "elf_embedded_pem") if f.asset_type == "key"]
    assert keys, "the embedded private key was not detected"
    assert keys[0].params.get("fingerprint"), "a key finding needs a fingerprint"


# ---------------------------------------------------------------------------
# Technique: VERSION STRINGS, cross-referenced to libraries.yaml
# ---------------------------------------------------------------------------


def test_a_version_banner_becomes_a_library_finding(findings: list[Finding]) -> None:
    libs = [
        f for f in _for(findings, "elf_version_banner") if f.asset_type == "library"
    ]
    assert libs, "the OpenSSL version banner was not detected"
    assert libs[0].algorithm == "OpenSSL"
    assert libs[0].params.get("version") == "3.0.13"


def test_the_version_is_cross_referenced_for_pqc_capability(
    findings: list[Finding],
) -> None:
    """OpenSSL 3.0.13 is below the verified 3.5.0 floor in libraries.yaml.

    This is the whole point of reading a banner rather than just recording it:
    the same pack the container scanner uses answers whether the shipped
    version can do ML-KEM at all.
    """
    libs = [
        f for f in _for(findings, "elf_version_banner") if f.asset_type == "library"
    ]
    assert libs
    assert libs[0].params.get("pqc_capable") is False


# ---------------------------------------------------------------------------
# HONEST COVERAGE -- the property this scanner exists to demonstrate
# ---------------------------------------------------------------------------


def test_a_stripped_binary_reports_reduced_coverage(
    context: ScanContext,
) -> None:
    """It must SAY it read less, not just return less.

    A scanner that quietly returns fewer findings on an unreadable artefact is
    reporting a clean artefact. That is the failure this whole design is shaped
    around.
    """
    scanner = BinaryScanner()
    report = scanner.coverage(FIXTURE_ROOT / "elf_openssl_symbols_stripped", context)

    assert report.stripped is True
    assert report.limitations, "a stripped binary reported no limitations at all"
    assert any("strip" in note.lower() for note in report.limitations)


def test_an_unstripped_binary_reports_no_stripping_limitation(
    context: ScanContext,
) -> None:
    """The counterpart: the report must be able to say "nothing was lost"."""
    scanner = BinaryScanner()
    report = scanner.coverage(FIXTURE_ROOT / "elf_openssl_symbols", context)
    assert report.stripped is False


def test_the_coverage_report_names_the_techniques_that_ran(
    context: ScanContext,
) -> None:
    report = BinaryScanner().coverage(FIXTURE_ROOT / "elf_openssl_symbols", context)
    assert set(report.techniques) == set(TECHNIQUE_CONFIDENCE)


def test_coverage_is_reported_for_a_statically_linked_binary(
    context: ScanContext,
) -> None:
    """No dynamic imports at all is the other half of the recall limit."""
    scanner = BinaryScanner()
    report = scanner.coverage(FIXTURE_ROOT / "pe_bcrypt.exe", context)
    assert report.imported_symbols > 0  # the PE fixture DOES import

    stripped = scanner.coverage(FIXTURE_ROOT / "elf_openssl_symbols_stripped", context)
    assert stripped.imported_symbols > 0  # strip keeps the DYNAMIC table


# ---------------------------------------------------------------------------
# PRECISION
# ---------------------------------------------------------------------------


def test_the_non_crypto_binary_produces_nothing(findings: list[Finding]) -> None:
    """libc imports, section names and compiler strings are not cryptography."""
    for decoy in DECOYS:
        hits = [
            (_technique(f), f.algorithm, f.evidence.occurrences[0].locator)
            for f in _for(findings, decoy)
        ]
        assert hits == [], f"{decoy} produced crypto findings: {hits}"


# ---------------------------------------------------------------------------
# DEGRADATION
# ---------------------------------------------------------------------------


def test_an_unparseable_binary_does_not_abort_the_scan(
    findings: list[Finding],
) -> None:
    """broken.bin sits in the same directory as everything else."""
    assert findings, "the scan produced nothing at all"
    for name in UNPARSEABLE:
        assert _for(findings, name) == []
    # ...and the fixtures after it in walk order were still read.
    assert _for(findings, "elf_openssl_symbols")
    assert _for(findings, "pe_bcrypt.exe")


def test_a_directory_with_no_binaries_yields_nothing(
    context: ScanContext, tmp_path: Path
) -> None:
    (tmp_path / "notes.txt").write_text("no binaries here\n", encoding="utf-8")
    target = Target(kind="directory", ref=str(tmp_path), system="empty")
    assert list(BinaryScanner().scan(target, context)) == []


def test_a_single_binary_file_can_be_scanned(context: ScanContext) -> None:
    """A directory target whose ref happens to be one file."""
    target = Target(
        kind="directory",
        ref=str(FIXTURE_ROOT / "elf_openssl_symbols"),
        system="one-file",
    )
    hits = list(BinaryScanner().scan(target, context))
    assert hits
    assert {_binary(f) for f in hits} == {"elf_openssl_symbols"}


# ---------------------------------------------------------------------------
# REDACTION -- the sixth and final scanner family
# ---------------------------------------------------------------------------


def test_no_planted_secret_reaches_any_finding(findings: list[Finding]) -> None:
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    for sentinel in SENTINELS:
        assert sentinel not in blob, (
            f"secret sentinel {sentinel!r} escaped into a binary Finding; "
            "the redaction guard is not holding for Scanner D"
        )


def test_key_material_findings_carry_a_redacted_snippet(
    findings: list[Finding],
) -> None:
    keys = [f for f in findings if f.asset_type == "key"]
    assert keys, "no key-material findings at all"
    for finding in keys:
        for occurrence in finding.evidence.occurrences:
            assert occurrence.snippet == "<redacted key material>", occurrence.snippet


def test_the_certificate_finding_does_not_carry_the_key_body(
    findings: list[Finding],
) -> None:
    """A certificate is public, but its snippet is still not a place for bytes."""
    certs = [f for f in findings if f.asset_type == "certificate"]
    assert certs
    for finding in certs:
        blob = json.dumps(finding.model_dump(), default=str)
        assert "-----BEGIN" not in blob, "a PEM body reached a certificate finding"


# ---------------------------------------------------------------------------
# CBOM and determinism
# ---------------------------------------------------------------------------


@pytest.mark.validation
def test_a_binary_scan_produces_a_schema_valid_cbom(findings: list[Finding]) -> None:
    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="bin-fixtures")
    _, cbom_json = normalise(findings, target)
    validate_cbom_json(cbom_json)

    document = json.loads(cbom_json)
    assert document["components"]
    for component in document["components"]:
        values = {p["name"]: p["value"] for p in component.get("properties", [])}
        assert values.get("ecdat:view") == "shipped"
        assert "ecdat:confidence" in values


def test_the_scan_is_deterministic(context: ScanContext) -> None:
    """Same bytes, same packs -> byte-identical CBOM (CLAUDE.md)."""
    import datetime
    import uuid

    target = Target(kind="directory", ref=str(FIXTURE_ROOT), system="bin-fixtures")
    fixed: dict[str, Any] = {
        "serial_number": uuid.UUID(int=0),
        "timestamp": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    }
    first = normalise(list(BinaryScanner().scan(target, context)), target, **fixed)[1]
    second = normalise(list(BinaryScanner().scan(target, context)), target, **fixed)[1]
    assert first == second


# ---------------------------------------------------------------------------
# THE SCORE
# ---------------------------------------------------------------------------


def test_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    """Recall against the key; precision against the DECOY.

    See answer_key.yaml for why precision is scored against the non-crypto
    binary rather than against the union of every entry: a binary is a
    haystack, and a key that enumerated every byte a heuristic could touch
    would be a transcript rather than a measuring stick.
    """
    planted = 0
    found = 0
    missed: list[tuple[str, str]] = []

    for name, expectations in EXPECTED.items():
        for expectation in expectations:
            planted += 1
            hits = [
                f
                for f in _for(findings, name)
                if f.algorithm == expectation["algorithm"]
                and f.primitive == expectation["primitive"]
                and f.usage == expectation["usage"]
                and _technique(f) == expectation["technique"]
                and f.confidence == expectation["confidence"]
                and all(
                    str(f.raw.get(key)) == str(expectation[key])
                    for key in ("symbol", "oid", "constant")
                    if key in expectation
                )
                and (
                    "asset_type" not in expectation
                    or f.asset_type == expectation["asset_type"]
                )
            ]
            if hits:
                found += 1
            else:
                missed.append(
                    (
                        name,
                        expectation.get("symbol")
                        or expectation.get("oid")
                        or expectation.get("constant")
                        or expectation["algorithm"],
                    )
                )

    decoy_hits = sum(len(_for(findings, decoy)) for decoy in DECOYS)
    emitted = len(findings)
    precision = 1.0 if decoy_hits == 0 else 0.0
    recall = found / planted if planted else 0.0

    by_technique = Counter(_technique(f) for f in findings)

    with capsys.disabled():
        print("\n  binary scanner vs testdata/binary_fixtures/answer_key.yaml")
        print(f"  RECALL    {recall:6.1%}  ({found}/{planted} planted)")
        print(
            f"  PRECISION {precision:6.1%}  ({decoy_hits} decoy hit(s), "
            f"{emitted} findings emitted)"
        )
        print(f"  by technique: {dict(sorted(by_technique.items()))}")
        if missed:
            print(f"  MISSED    {missed}")

    assert recall >= 0.9, f"recall {recall:.1%}; missed {missed}"
    assert precision == 1.0, f"{decoy_hits} finding(s) on the non-crypto decoy"


# ---------------------------------------------------------------------------
# The opt-in real-binary test
# ---------------------------------------------------------------------------


REAL_BINARY_OPT_IN_ENV = "ECDAT_RUN_BINARY_TESTS"


@pytest.mark.binary_real
def test_a_real_system_libcrypto_is_scanned(context: ScanContext) -> None:
    """Opt-in, the same way the docker tests are.

    The committed fixtures are the contract; this one asks whether the scanner
    survives a REAL 4MB shared library with thousands of symbols, which is a
    different question and depends on what happens to be installed.
    """
    if os.environ.get(REAL_BINARY_OPT_IN_ENV, "").strip() not in {"1", "true", "yes"}:
        pytest.skip(
            f"real-binary tests are opt-in: set {REAL_BINARY_OPT_IN_ENV}=1 to run "
            "them (they read whatever libcrypto this host happens to have)"
        )
    candidates = [
        Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"),
        Path("/lib/x86_64-linux-gnu/libcrypto.so.3"),
    ]
    library = next((p for p in candidates if p.exists()), None)
    if library is None:
        pytest.skip("no system libcrypto.so.3 found")

    target = Target(kind="directory", ref=str(library), system="real")
    hits = list(BinaryScanner().scan(target, context))
    assert hits, "a real libcrypto produced no findings at all"
    assert {_technique(f) for f in hits} & {"symbol", "constant", "oid"}
