"""ADR-0036 -- no secret key material in a Finding's evidence, STRUCTURALLY.

Before this slice, "no key bytes in a snippet" was six separate conventions:
each scanner redacted its own key matches and a per-scanner test guarded it.
`Occurrence.snippet` was a free-form string, and the normaliser copied it into
the CBOM unexamined. A SEVENTH scanner -- or a new rule in an existing one --
that forgot would have put key bytes in the store, and nothing in between would
have noticed.

The guard now sits where every finding passes: the schema's validators, and
again at the normaliser, which re-validates every finding before it builds a
CBOM so that a pydantic bypass cannot carry key bytes past it either.

What it redacts is KEY MATERIAL, not "anything high-entropy":

* private-key armour -- PEM, OpenSSH, PGP, PuTTY -> the whole text;
* a DER private-key STRUCTURE, however it is encoded (base64, hex, ``\\x``
  escapes, byte arrays, raw bytes) -> that run;
* a 32+ character high-entropy literal bound to a secret-named identifier
  (ADR-0034's discipline) -> that literal;
* in a finding its scanner flagged as key material (``asset_type == "key"``, or
  ADR-0034's ``candidate`` flag): every literal that is not an algorithm name
  -> that literal.

What it must NOT touch: a config line, an algorithm name, a certificate or a
public key, a hash digest, a bom-ref, ordinary code.
"""

from __future__ import annotations

import base64
import json
import logging
import tarfile
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

import scanners.binary as binary
import scanners.container as container
import scanners.source as source
from core import registry, store
from core.identity import finding_identity
from core.normalise import normalise
from core.orchestrator import run_scan
from core.scanner import ScanContext, Target
from core.schema import AssetType, Evidence, Finding, Occurrence, View
from core.system import load_manifest, scan_system
from scanners.binary import BinaryScanner
from scanners.container import ContainerScanner
from scanners.source import SourceScanner
from tests.rulepack import load_answers

#: What the guard puts in place of a whole snippet, and of one value in it.
WHOLE = "<redacted key material>"
VALUE = "<redacted>"

KNOWLEDGE = Path("knowledge")
PY_FIXTURES = Path("testdata/python_fixtures")
JS_FIXTURES = Path("testdata/js_fixtures")
CONTAINER_IMAGE = Path("testdata/images/synthetic/certs-and-key.tar")
BINARY_FIXTURES = Path("testdata/binary_fixtures")
QUANTUMBANK = Path("testdata/quantumbank/system.yaml")

#: The guard logs every time it has to redact something a scanner left in.
#: Attached to directly: the `ecdat` logger does not propagate to the root.
BACKSTOP_LOGGER = "ecdat.core.redaction"
BACKSTOP_EVENT = "key_material_redacted"

PKCS8 = serialization.PrivateFormat.PKCS8
TRADITIONAL = serialization.PrivateFormat.TraditionalOpenSSL
OPENSSH = serialization.PrivateFormat.OpenSSH
PLAIN: serialization.KeySerializationEncryption = serialization.NoEncryption()
PASSPHRASE = serialization.BestAvailableEncryption(b"correct horse battery staple")

TARGET = Target(kind="directory", ref="/srv/seventh", system="seventh")
SERIAL = uuid.UUID(int=36)
WHEN = datetime(2026, 9, 11, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Material -- real keys, generated per run, never committed
# ---------------------------------------------------------------------------


def pem_of(key: PrivateKeyTypes, fmt: Any = PKCS8, encryption: Any = PLAIN) -> str:
    return key.private_bytes(serialization.Encoding.PEM, fmt, encryption).decode(
        "ascii"
    )


def der_of(key: PrivateKeyTypes, fmt: Any = PKCS8, encryption: Any = PLAIN) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, fmt, encryption)


def body(pem: str) -> list[str]:
    """The lines between the armour -- the part that IS the key."""
    return [line for line in pem.splitlines() if line and not line.startswith("-----")]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ed_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def pem_forms(
    rsa_key: rsa.RSAPrivateKey,
    ec_key: ec.EllipticCurvePrivateKey,
    ed_key: ed25519.Ed25519PrivateKey,
) -> dict[str, str]:
    return {
        "pkcs8": pem_of(rsa_key),
        "pkcs1-rsa": pem_of(rsa_key, TRADITIONAL),
        "sec1-ec": pem_of(ec_key, TRADITIONAL),
        "encrypted-pkcs8": pem_of(ec_key, PKCS8, PASSPHRASE),
        "openssh": pem_of(ed_key, OPENSSH),
    }


@pytest.fixture(scope="module")
def certificate(ec_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.quantumbank.in")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ec_key.public_key())
        .serial_number(0x2F1C)
        .not_valid_before(WHEN)
        .not_valid_after(WHEN + timedelta(days=365))
        .sign(ec_key, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def spki_pem(ec_key: ec.EllipticCurvePrivateKey) -> str:
    return (
        ec_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


# ---------------------------------------------------------------------------
# Builders -- a finding exactly as a forgetful scanner would emit it
# ---------------------------------------------------------------------------


def occurrence(snippet: str | None, **fields: Any) -> Occurrence:
    values: dict[str, Any] = {
        "view": "declared",
        "locator": "app/keys.py:3",
        "detail": "rule=seventh-rule",
        "snippet": snippet,
    }
    values.update(fields)
    return Occurrence(**values)


def finding(
    snippet: str | None,
    *,
    asset_type: AssetType = "algorithm",
    params: dict[str, Any] | None = None,
    scanner_id: str = "seventh.forgetful",
    **occurrence_fields: Any,
) -> Finding:
    return Finding(
        scanner_id=scanner_id,
        view=occurrence_fields.get("view", "declared"),
        asset_type=asset_type,
        primitive="unknown",
        algorithm="unknown",
        params=params or {},
        evidence=Evidence(occurrences=[occurrence(snippet, **occurrence_fields)]),
    )


def stored(item: Finding) -> str | None:
    """The snippet as it will reach the CBOM."""
    return item.evidence.occurrences[0].snippet


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def backstop() -> Iterator[list[logging.LogRecord]]:
    """Every time the guard had to redact something a scanner left in."""
    handler = _Records()
    logger = logging.getLogger(BACKSTOP_LOGGER)
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def fired(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [r for r in records if getattr(r, "event", None) == BACKSTOP_EVENT]


# ---------------------------------------------------------------------------
# 1. PEM armour: the whole text goes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "form", ["pkcs8", "pkcs1-rsa", "sec1-ec", "encrypted-pkcs8", "openssh"]
)
def test_a_pem_private_key_the_scanner_left_in_is_redacted_by_the_schema(
    form: str, pem_forms: dict[str, str]
) -> None:
    key_pem = pem_forms[form]

    kept = stored(finding(key_pem))

    assert kept == WHOLE
    for line in body(key_pem):
        assert line not in kept


@pytest.mark.parametrize(
    "text",
    [
        'SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----',
        'KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"',
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGbFillerForThePacket",
        "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nAAAAIE",
    ],
    ids=["armour-on-a-code-line", "armour-in-a-string", "pgp", "putty"],
)
def test_any_private_key_armour_redacts_the_whole_text(text: str) -> None:
    assert stored(finding(text)) == WHOLE


def test_key_material_in_a_detail_or_a_param_is_redacted_too(
    pem_forms: dict[str, str],
) -> None:
    key_pem = pem_forms["pkcs8"]
    fingerprint = "ab12" * 8

    item = Finding(
        scanner_id="seventh.forgetful",
        view="shipped",
        asset_type="algorithm",
        primitive="unknown",
        algorithm="unknown",
        params={"embedded": key_pem, "public_key_fingerprint": fingerprint},
        evidence=Evidence(occurrences=[occurrence(None, detail=f"pem dump {key_pem}")]),
    )

    assert item.evidence.occurrences[0].detail == WHOLE
    assert item.params["embedded"] == WHOLE
    assert item.params["public_key_fingerprint"] == fingerprint


# ---------------------------------------------------------------------------
# 2. DER private keys, however they are spelled: that run goes
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def der_cases(
    rsa_key: rsa.RSAPrivateKey,
    ec_key: ec.EllipticCurvePrivateKey,
    ed_key: ed25519.Ed25519PrivateKey,
) -> dict[str, tuple[str, str, str]]:
    """name -> (what a forgetful scanner stored, what must be kept, the secret)."""
    ec8 = der_of(ec_key)
    rsa1 = der_of(rsa_key, TRADITIONAL)
    sec1 = der_of(ec_key, TRADITIONAL)
    rsa8 = der_of(rsa_key)
    wrapped = der_of(ec_key, PKCS8, PASSPHRASE)
    openssh_body = "".join(body(pem_of(ed_key, OPENSSH)))
    ed8 = base64.urlsafe_b64encode(der_of(ed_key)).decode("ascii").rstrip("=")
    escapes = "".join(f"\\x{byte:02x}" for byte in sec1)
    java = ", ".join(f"(byte) 0x{byte:02x}" for byte in rsa8[:48])
    return {
        "pkcs8-ec-base64": (
            f'payload = base64.b64decode("{b64(ec8)}")',
            f'payload = base64.b64decode("{VALUE}")',
            b64(ec8),
        ),
        "pkcs1-rsa-hex": (
            f'data = bytes.fromhex("{rsa1.hex()}")',
            f'data = bytes.fromhex("{VALUE}")',
            rsa1.hex(),
        ),
        "sec1-ec-escapes": (f'BLOB = b"{escapes}"', f'BLOB = b"{VALUE}"', escapes),
        "pkcs8-rsa-java-byte-array": (
            f"byte[] table = {{{java}}};",
            f"byte[] table = {{{VALUE}}};",
            java,
        ),
        "encrypted-pkcs8-base64": (
            f'wrapped = "{b64(wrapped)}"',
            f'wrapped = "{VALUE}"',
            b64(wrapped),
        ),
        "openssh-body-without-armour": (
            f'material = "{openssh_body}"',
            f'material = "{VALUE}"',
            openssh_body,
        ),
        "pkcs8-ed25519-base64url": (f"x={ed8}", f"x={VALUE}", ed8),
    }


@pytest.mark.parametrize(
    "case",
    [
        "pkcs8-ec-base64",
        "pkcs1-rsa-hex",
        "sec1-ec-escapes",
        "pkcs8-rsa-java-byte-array",
        "encrypted-pkcs8-base64",
        "openssh-body-without-armour",
        "pkcs8-ed25519-base64url",
    ],
)
def test_a_der_private_key_is_redacted_in_place_whatever_its_encoding(
    case: str, der_cases: dict[str, tuple[str, str, str]]
) -> None:
    """Recognised by STRUCTURE, not by a name: every identifier here is neutral."""
    snippet, expected, secret = der_cases[case]

    kept = stored(finding(snippet))

    assert kept == expected, "only the key run may change -- the rest is evidence"
    assert secret not in (kept or "")


def test_raw_der_bytes_in_a_snippet_redact_the_whole_text(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    """A scanner that decoded a binary blob straight into the snippet."""
    raw = der_of(ec_key, TRADITIONAL).decode("latin-1")

    assert stored(finding(raw)) == WHOLE


# ---------------------------------------------------------------------------
# 3. The redaction-flagged material: a finding its scanner called key material
# ---------------------------------------------------------------------------


def test_a_key_findings_literals_are_redacted_even_when_its_scanner_forgot() -> None:
    line = 'self.key = b"YELLOW SUBMARINE"'

    assert stored(finding(line, asset_type="key")) == f'self.key = b"{VALUE}"'
    # The same line on an ordinary finding: untouched. The FLAG did it.
    assert stored(finding(line)) == line


def test_an_adr_0034_candidates_literal_is_redacted() -> None:
    line = 'WEBHOOK_TOKEN = "Zr2fWbT0mNvX4kL9pYs1"'

    flagged = finding(line, params={"candidate": True})

    assert stored(flagged) == f'WEBHOOK_TOKEN = "{VALUE}"'
    assert stored(finding(line)) == line


def test_a_key_byte_array_in_a_key_finding_is_redacted() -> None:
    line = (
        "byte[] key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, "
        "0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};"
    )

    assert stored(finding(line, asset_type="key")) == f"byte[] key = {{{VALUE}}};"
    # Sixteen bytes that are NOT a DER structure, on an ordinary finding: kept.
    assert stored(finding(line)) == line


@pytest.mark.parametrize(
    "line",
    [
        'key = SecretKeySpec(raw, "AES")',
        'mac = Mac.getInstance("HmacSHA256")',
        'factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")',
        'cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")',
        "key = crypto.createSecretKey(buffer, 'utf-8')",
    ],
)
def test_a_key_finding_keeps_its_algorithm_names(line: str) -> None:
    assert stored(finding(line, asset_type="key")) == line


def test_a_public_key_asset_is_not_key_material(spki_pem: str) -> None:
    line = f'PUBLIC_KEY = "{"".join(body(spki_pem))}"'

    public = finding(line, asset_type="key", params={"material": "public-key"})

    assert stored(public) == line


# ---------------------------------------------------------------------------
# 4. A high-entropy literal bound to a SECRET-named identifier (ADR-0034)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            f'aws_secret_access_key = "{VALUE}"',
        ),
        ("API_SECRET=3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c", f"API_SECRET={VALUE}"),
        ("signing_key: 5311553b827b1eb7ea26c27891eb47d4", f"signing_key: {VALUE}"),
        (
            'client = Client(api_key="q8Zr2fWbT0mNvX4kL9pYs1HcUe7Ja3DgPq")',
            f'client = Client(api_key="{VALUE}")',
        ),
    ],
    ids=["python-literal", "env-file", "yaml", "keyword-argument"],
)
def test_a_high_entropy_literal_bound_to_a_secret_name_is_redacted(
    line: str, expected: str
) -> None:
    assert stored(finding(line)) == expected


# ---------------------------------------------------------------------------
# 5. NO OVER-REDACTION -- surgical, not blanket
# ---------------------------------------------------------------------------

DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    "line",
    [
        # config lines
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;",
        "ssl_certificate_key /etc/nginx/ssl/api.quantumbank.key;",
        "ssl_password_file /etc/keys/global.pass;",
        "default_md = sha256",
        # algorithm names, including next to a key-ish word
        'Cipher.getInstance("AES/GCM/NoPadding")',
        'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")',
        "crypto.createCipheriv('aes-256-gcm', key, iv)",
        'KeyPairGenerator.getInstance("RSA")',
        # hash digests
        f'EXPECTED_SHA256 = "{DIGEST}"',
        f'key_digest = "{DIGEST}"',
        f"{DIGEST}  release.tar.gz",
        # high entropy with no key context at all
        'request_id = "8f14e45fceea167a5a36dedd4bea2543"',
        'trace = "4bf92f3577b34da6a3ce929d0e0e4736"',
        # ordinary code
        "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)",
        "private_key = serialization.load_pem_private_key(data, password=None)",
        'jwt.encode(claims, key, algorithm="RS256")',
        "digest = hashlib.sha256(payload).hexdigest()",
        'log.info("rotated the signing key for tenant %s", tenant)',
        'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]',
    ],
)
def test_legitimate_evidence_passes_through_unchanged(line: str) -> None:
    assert stored(finding(line)) == line


def test_a_certificate_and_a_public_key_pass_through_unchanged(
    certificate: x509.Certificate, spki_pem: str
) -> None:
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    cert_hex = certificate.public_bytes(serialization.Encoding.DER).hex()
    spki = "".join(body(spki_pem))
    cases: list[tuple[str, AssetType]] = [
        (cert_pem, "certificate"),
        (spki_pem, "algorithm"),
        (f'SIGNING_PUBLIC_KEY = "{spki}"', "algorithm"),
        # A secret-SOUNDING name, but the literal is a public structure.
        (f'VERIFY_KEY = "{spki}"', "algorithm"),
        (f'CERT_DER = bytes.fromhex("{cert_hex}")', "certificate"),
    ]
    for text, asset_type in cases:
        assert stored(finding(text, asset_type=asset_type)) == text, text[:40]


def test_a_bom_ref_a_layer_digest_and_detector_details_pass_through() -> None:
    ref = finding_identity(finding("AESGCM(key)"), TARGET)
    line = f'"bom-ref": "{ref}"'
    layer = f"sha256:{'9f3a' * 16}/etc/ssl/certs/api.pem"

    item = finding(line, locator=layer, detail="symbol=EVP_aes_256_gcm", view="shipped")

    occ = item.evidence.occurrences[0]
    assert (occ.snippet, occ.locator, occ.detail) == (
        line,
        layer,
        "symbol=EVP_aes_256_gcm",
    )


def test_ordinary_params_pass_through_unchanged() -> None:
    params = {
        "public_key_fingerprint": "ab12" * 8,
        "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        "curve": "P-256",
        "key_size": 2048,
    }

    assert finding("x", params=dict(params)).params == params


# ---------------------------------------------------------------------------
# 6. THE SEVENTH SCANNER -- a plugin that does no redaction at all
# ---------------------------------------------------------------------------


class ForgetfulScanner:
    """What the next plugin looks like on the day its author forgets.

    It redacts nothing. Every snippet is exactly what it read.
    """

    id: str = "seventh.forgetful"
    view: View = "shipped"
    version = "0.0.1"

    def __init__(self, leaks: list[tuple[str, AssetType, dict[str, Any], str]]) -> None:
        self.leaks = leaks

    def supports(self, target: Target) -> bool:
        return True

    def scan(self, target: Target, ctx: ScanContext) -> Iterator[Finding]:
        for name, asset_type, params, snippet in self.leaks:
            yield Finding(
                scanner_id=self.id,
                view=self.view,
                asset_type=asset_type,
                primitive="unknown",
                algorithm="unknown",
                params=params,
                evidence=Evidence(
                    occurrences=[
                        Occurrence(
                            view=self.view,
                            locator=f"image/{name}:1",
                            detail="read it, kept it",
                            snippet=snippet,
                        )
                    ]
                ),
            )


CANDIDATE = "Zr2fWbT0mNvX4kL9pYs1"
AWS = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@pytest.fixture
def seventh(
    pem_forms: dict[str, str], der_cases: dict[str, tuple[str, str, str]]
) -> ForgetfulScanner:
    der_snippet = der_cases["pkcs8-ec-base64"][0]
    return ForgetfulScanner(
        [
            ("private-key.pem", "key", {}, pem_forms["pkcs1-rsa"]),
            ("loader.py", "algorithm", {}, der_snippet),
            (
                "config.js",
                "algorithm",
                {"candidate": True},
                f'WEBHOOK_TOKEN = "{CANDIDATE}"',
            ),
            ("settings.py", "algorithm", {}, f'aws_secret_access_key = "{AWS}"'),
        ]
    )


def test_a_seventh_scanner_that_never_redacts_cannot_put_a_key_in_the_store(
    tmp_path: Path,
    seventh: ForgetfulScanner,
    pem_forms: dict[str, str],
    der_cases: dict[str, tuple[str, str, str]],
    backstop: list[logging.LogRecord],
) -> None:
    """The whole point: through the REAL pipeline -- orchestrator, normaliser,
    policy, store -- a plugin that redacts nothing still stores no key bytes."""
    ctx = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path / "scratch")

    scan_id = run_scan(TARGET, [seventh], ctx)

    row = store.get_scan(scan_id)
    assert row is not None
    cbom = row.cbom_json
    assert "PRIVATE KEY-----" not in cbom
    for secret in [
        *body(pem_forms["pkcs1-rsa"]),
        der_cases["pkcs8-ec-base64"][2],
        CANDIDATE,
        AWS,
    ]:
        assert secret not in cbom
    # Still EVIDENCE: every sighting is there, at its place, marked redacted.
    for name in ("private-key.pem", "loader.py", "config.js", "settings.py"):
        assert f"image/{name}" in cbom
    assert WHOLE in cbom
    assert VALUE in cbom
    # And the backstop said so, once per sighting, naming where.
    events = fired(backstop)
    assert {getattr(r, "locator", None) for r in events} == {
        "image/private-key.pem:1",
        "image/loader.py:1",
        "image/config.js:1",
        "image/settings.py:1",
    }


def test_the_backstops_own_log_line_carries_no_key_bytes(
    seventh: ForgetfulScanner,
    pem_forms: dict[str, str],
    backstop: list[logging.LogRecord],
) -> None:
    list(seventh.scan(TARGET, ScanContext(KNOWLEDGE, Path())))

    events = fired(backstop)
    assert events
    dump = json.dumps([vars(r) for r in events], default=str)
    for secret in [*body(pem_forms["pkcs1-rsa"]), CANDIDATE, AWS]:
        assert secret not in dump


def test_a_finding_that_skipped_validation_is_redacted_at_the_normaliser(
    pem_forms: dict[str, str],
) -> None:
    """`model_construct` and `model_copy(update=...)` skip pydantic's
    validators. The normaliser re-validates every finding, so neither path
    carries key bytes into a CBOM."""
    key_pem = pem_forms["sec1-ec"]
    raw = Occurrence.model_construct(
        view="shipped", locator="image/k.pem:1", detail="d", snippet=key_pem
    )
    constructed = Finding.model_construct(
        scanner_id="seventh.bypass",
        view="shipped",
        asset_type="key",
        primitive="unknown",
        algorithm="unknown",
        params={},
        usage="unknown",
        configurable=None,
        evidence=Evidence.model_construct(occurrences=[raw]),
        confidence=1.0,
        raw={},
    )
    copied = finding("AESGCM(key)").model_copy(
        update={"evidence": Evidence.model_construct(occurrences=[raw])}
    )
    assert constructed.evidence.occurrences[0].snippet == key_pem, "not a bypass"
    assert copied.evidence.occurrences[0].snippet == key_pem, "not a bypass"

    for smuggled in (constructed, copied):
        _, cbom = normalise([smuggled], TARGET, serial_number=SERIAL, timestamp=WHEN)
        assert "PRIVATE KEY-----" not in cbom
        for line in body(key_pem):
            assert line not in cbom


# ---------------------------------------------------------------------------
# 7. Under all SIX scanner families -- and every scanner registered after them
# ---------------------------------------------------------------------------

#: Read from the registry, not listed by hand: a scanner registered tomorrow is
#: in this parametrisation without anyone editing this file.
PLUGIN_IDS = [scanner.id for scanner in registry.get_scanners(None)]


def test_all_six_scanner_families_are_registered() -> None:
    assert set(registry.available_ids()) >= {
        "binary",
        "config",
        "container",
        "deps",
        "runtime-spool",
        "source",
    }
    assert len(PLUGIN_IDS) >= 6


@pytest.mark.parametrize("scanner_id", PLUGIN_IDS)
def test_the_guard_does_not_care_which_scanner_emitted_the_key(
    scanner_id: str,
    pem_forms: dict[str, str],
    der_cases: dict[str, tuple[str, str, str]],
) -> None:
    snippet, expected, _ = der_cases["pkcs8-ec-base64"]

    armour = finding(pem_forms["pkcs8"], scanner_id=scanner_id, asset_type="key")
    der = finding(snippet, scanner_id=scanner_id)

    assert stored(armour) == WHOLE
    assert stored(der) == expected


def _raw_line(occ: Occurrence) -> str:
    path, _, line = occ.locator.rpartition(":")
    return Path(path).read_text(encoding="utf-8").splitlines()[int(line) - 1]


def test_the_source_scanner_forgetting_to_redact_is_caught_by_the_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backstop: list[logging.LogRecord],
) -> None:
    """Switch the source scanner's own `_redact` OFF and scan the ADR-0034
    fixtures. Every finding it flags as key material still carries no key."""
    monkeypatch.setattr(source, "_redact", lambda line, **_: line.strip())
    sentinels = load_answers(PY_FIXTURES).sentinels
    ctx = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path)

    findings = list(
        SourceScanner().scan(Target(kind="repo", ref=str(PY_FIXTURES)), ctx)
    )

    material = [
        f
        for f in findings
        if f.asset_type == "key" or f.params.get("candidate") is True
    ]
    assert material
    raw_lines = [_raw_line(o) for f in material for o in f.evidence.occurrences]
    assert any(s in line for line in raw_lines for s in sentinels), (
        "no key line carries a sentinel -- the scanner was not really forgetful"
    )
    blob = json.dumps([f.model_dump() for f in material], default=str)
    for sentinel in sentinels:
        assert sentinel not in blob
    everything = json.dumps([f.model_dump() for f in findings], default=str)
    assert "PRIVATE KEY-----" not in everything
    assert fired(backstop), "the schema never had to act"


def _planted_container_key() -> str:
    with tarfile.open(CONTAINER_IMAGE) as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())  # type: ignore[union-attr]
        layer = manifest[0]["Layers"][-1]
        with tarfile.open(fileobj=tar.extractfile(layer)) as inner:
            handle = inner.extractfile("etc/ssl/private/api.quantumbank.key")
            assert handle is not None
            return handle.read().decode("ascii")


def test_the_container_scanner_forgetting_to_redact_is_caught_by_the_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backstop: list[logging.LogRecord],
) -> None:
    """A container scanner that wrote the key file into the snippet."""
    key_pem = _planted_container_key()
    monkeypatch.setattr(container, "REDACTED", key_pem)
    ctx = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path)
    image = Target(kind="image", ref=str(CONTAINER_IMAGE), system="fixtures")

    findings = list(ContainerScanner().scan(image, ctx))

    assert [f for f in findings if f.asset_type == "key"]
    blob = json.dumps([f.model_dump() for f in findings], default=str)
    assert "PRIVATE KEY-----" not in blob
    for line in body(key_pem):
        assert line not in blob
    assert fired(backstop)


def _planted_binary_key() -> str:
    data = (BINARY_FIXTURES / "elf_embedded_pem").read_bytes()
    for match in binary._PEM_BLOCK.finditer(data):
        if b"PRIVATE KEY" in match.group(1):
            return match.group(0).decode("ascii")
    raise AssertionError("the binary fixture no longer embeds a private key")


def test_the_binary_scanner_forgetting_to_redact_is_caught_by_the_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backstop: list[logging.LogRecord],
) -> None:
    """A binary scanner that decoded the embedded key into the snippet."""
    key_pem = _planted_binary_key()
    monkeypatch.setattr(binary, "REDACTED", key_pem)
    ctx = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path)
    fixtures = Target(kind="directory", ref=str(BINARY_FIXTURES), system="bin")

    findings = list(BinaryScanner().scan(fixtures, ctx))

    blob = json.dumps([f.model_dump() for f in findings], default=str)
    assert "BINSECRETSENTINEL" not in blob
    assert "PRIVATE KEY-----" not in blob
    assert fired(backstop)


def test_the_real_scanners_never_trip_the_backstop(
    tmp_path: Path, backstop: list[logging.LogRecord]
) -> None:
    """The six families already redact what they must. The guard is a
    backstop, not a second opinion: over QuantumBank (five families), the
    binary fixtures (the sixth) and the key-material rule fixtures, it rewrites
    NOTHING -- no legitimate evidence changes."""
    ctx = ScanContext(knowledge_dir=KNOWLEDGE, scratch_dir=tmp_path)

    scan_system(load_manifest(QUANTUMBANK), ctx)
    bins = Target(kind="directory", ref=str(BINARY_FIXTURES), system="bin")
    list(BinaryScanner().scan(bins, ctx))
    for root in (PY_FIXTURES, JS_FIXTURES):
        list(SourceScanner().scan(Target(kind="repo", ref=str(root)), ctx))

    assert fired(backstop) == [], [vars(r) for r in fired(backstop)][:3]


# ---------------------------------------------------------------------------
# 8. Determinism
# ---------------------------------------------------------------------------


def test_redaction_is_deterministic_and_idempotent(
    pem_forms: dict[str, str], der_cases: dict[str, tuple[str, str, str]]
) -> None:
    inputs = [
        pem_forms["pkcs8"],
        der_cases["pkcs1-rsa-hex"][0],
        f'aws_secret_access_key = "{AWS}"',
    ]
    for text in inputs:
        once = stored(finding(text))
        assert stored(finding(text)) == once
        assert stored(finding(once)) == once


def test_the_cbom_is_byte_identical_whatever_the_order(
    seventh: ForgetfulScanner,
) -> None:
    findings = list(seventh.scan(TARGET, ScanContext(KNOWLEDGE, Path())))

    _, first = normalise(findings, TARGET, serial_number=SERIAL, timestamp=WHEN)
    _, again = normalise(findings[::-1], TARGET, serial_number=SERIAL, timestamp=WHEN)

    assert first == again


def test_redaction_never_moves_a_bom_ref(pem_forms: dict[str, str]) -> None:
    """Snippets are not identifying (core/identity.py), so a component keeps
    its bom-ref whether its scanner redacted or the schema had to."""
    left_in = finding(pem_forms["pkcs8"], asset_type="key")
    pre_redacted = finding(WHOLE, asset_type="key")

    assert finding_identity(left_in, TARGET) == finding_identity(pre_redacted, TARGET)
