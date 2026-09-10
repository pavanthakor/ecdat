"""must_fire: py-hardcoded-key-der (ADR-0034).

A base64 DER structure is key material by its SHAPE alone. `MII` is a DER
SEQUENCE with a two-byte length (X.690 s8.1.3), the header of every RSA key and
every X.509 certificate (RFC 8017, RFC 5280). The body is filler; the sentinel
must reach no Finding.
"""
import hashlib
import hmac

PARTNER_KEY_DER = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAPYDERSENTINELnotARealKeyJustFillerForTheShapeOnly0123456789"


def partner_mac(data: bytes) -> bytes:
    # It reaches a key parameter too. The DER rule owns a shaped literal, so
    # this is still ONE finding -- not a DER finding plus a sink finding.
    return hmac.new(PARTNER_KEY_DER.encode(), data, hashlib.sha256).digest()
