"""Hand-built Finding fixtures shared by the normaliser tests.

No scanner is involved anywhere in this package: every Finding here is written
by hand so the normaliser is tested against inputs we fully control.
"""

from __future__ import annotations

from typing import Any

from core.scanner import Target
from core.schema import Evidence, Finding, Occurrence


def occurrence(**overrides: Any) -> Occurrence:
    kwargs: dict[str, Any] = {
        "view": "declared",
        "locator": "services/auth/jwt.py:42",
        "detail": "rule=py-jwt-rs256@1.3",
        "snippet": 'jwt.encode(claims, key, algorithm="RS256")',
    }
    kwargs.update(overrides)
    return Occurrence(**kwargs)


def finding(**overrides: Any) -> Finding:
    """An RSA-2048 signing site declared in source, unless overridden."""
    kwargs: dict[str, Any] = {
        "scanner_id": "source.semgrep",
        "view": "declared",
        "asset_type": "algorithm",
        "primitive": "signature",
        "algorithm": "RSA",
        "params": {"key_size": 2048, "padding": "PKCS1v15"},
        "usage": "sign",
        "configurable": False,
        "evidence": Evidence(occurrences=[occurrence()]),
        "confidence": 1.0,
        "raw": {"rule_id": "py-jwt-rs256"},
    }
    kwargs.update(overrides)
    if "occurrences" in kwargs:
        kwargs["evidence"] = Evidence(occurrences=kwargs.pop("occurrences"))
    return Finding(**kwargs)


def repo_target() -> Target:
    return Target(
        kind="repo", ref="/srv/quantumbank", system="quantumbank", data_class="pii"
    )


# --------------------------------------------------------------------------
# The fixed corpus behind tests/golden/quantumbank.cbom.json.
# Covers every asset type, both a cross-view merge and a near-miss that must
# stay separate. Order here is deliberately not sorted: the golden test also
# shuffles it.
# --------------------------------------------------------------------------


def golden_target() -> Target:
    return repo_target()


def golden_findings() -> list[Finding]:
    return [
        # RSA signing, declared in source ...
        finding(),
        # ... and the same site seen executing: merges into one component.
        finding(
            scanner_id="runtime.ebpf",
            view="observed",
            confidence=0.9,
            configurable=None,
            raw={"probe": "RSA_sign"},
            occurrences=[
                occurrence(
                    view="observed",
                    locator="services/auth/jwt.py:pid2231",
                    detail="probe=RSA_sign nid=rsaEncryption",
                    snippet=None,
                )
            ],
        ),
        # AES-256-GCM at rest.
        finding(
            scanner_id="source.semgrep",
            primitive="block-cipher",
            algorithm="AES",
            params={"key_size": 256, "mode": "GCM"},
            usage="encrypt",
            occurrences=[
                occurrence(
                    locator="services/ledger/vault.py:88",
                    detail="rule=py-aes-gcm@2.0",
                    snippet="AESGCM(key)",
                )
            ],
        ),
        # A weak hash, hard-coded.
        finding(
            scanner_id="source.semgrep",
            primitive="hash",
            algorithm="SHA-1",
            params={},
            usage="hash",
            confidence=0.8,
            occurrences=[
                occurrence(
                    locator="services/ledger/legacy.py:7",
                    detail="rule=py-weak-hash@1.1",
                    snippet="hashlib.sha1(payload)",
                )
            ],
        ),
        # A shipped certificate.
        finding(
            scanner_id="container.certs",
            view="shipped",
            asset_type="certificate",
            primitive="signature",
            algorithm="ECDSA",
            params={
                "curve": "P-256",
                "subject": "CN=api.quantumbank.in",
                "issuer": "CN=QuantumBank Internal CA",
                "valid_to": "2027-03-01T00:00:00Z",
                "format": "X.509",
            },
            usage="verify",
            configurable=None,
            occurrences=[
                occurrence(
                    view="shipped",
                    locator="sha256:9f3a/etc/ssl/certs/api.pem",
                    detail="x509 serial=0x2f1c",
                    snippet="CN=api.quantumbank.in",
                )
            ],
        ),
        # A negotiated protocol.
        finding(
            scanner_id="network.handshake",
            view="observed",
            asset_type="protocol",
            primitive="key-agreement",
            algorithm="TLS",
            params={
                "version": "1.2",
                "group": "secp256r1",
                "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            },
            usage="key-exchange",
            configurable=True,
            occurrences=[
                occurrence(
                    view="observed",
                    locator="api.quantumbank.in:443",
                    detail="serverhello version=771",
                    snippet=None,
                )
            ],
        ),
        # A private key on disk (never its value).
        finding(
            scanner_id="container.certs",
            view="shipped",
            asset_type="key",
            primitive="pke",
            algorithm="RSA",
            params={"key_size": 4096, "material": "private-key"},
            usage="key-transport",
            configurable=None,
            occurrences=[
                occurrence(
                    view="shipped",
                    locator="sha256:9f3a/etc/ssl/private/api.key",
                    detail="pem type=RSA PRIVATE KEY",
                    snippet=None,
                )
            ],
        ),
        # The provider library itself: not a CycloneDX crypto asset.
        finding(
            scanner_id="deps.sbom",
            view="shipped",
            asset_type="library",
            primitive="unknown",
            algorithm="OpenSSL",
            params={"version": "3.0.2"},
            usage="unknown",
            configurable=None,
            occurrences=[
                occurrence(
                    view="shipped",
                    locator="sha256:9f3a/usr/lib/x86_64-linux-gnu/libssl.so.3",
                    detail="libssl.so.3=3.0.2",
                    snippet=None,
                )
            ],
        ),
    ]
