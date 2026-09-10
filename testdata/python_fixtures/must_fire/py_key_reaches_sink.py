"""must_fire: py-hardcoded-key (ADR-0034) -- literals that REACH a key parameter.

The sentinels must reach no Finding.
"""
import hashlib
import hmac

import jwt
from cryptography.fernet import Fernet

# High-entropy, key-ish AND reaching a sink: py-hardcoded-key-candidate matches
# this assignment too, and the scanner folds it into the sink finding -- one
# key, one finding.
WEBHOOK_KEY = b"955e9a9751dca0fd2099741107479fea"


def mac_of(data: bytes) -> bytes:
    return hmac.new(WEBHOOK_KEY, data, hashlib.sha256).digest()


def issue(claims: dict) -> str:
    # Inline at the sink: PyJWT's HMAC secret.
    return jwt.encode(claims, "PYSINKSENTINELinlineJwtSecret", algorithm="HS256")


def vault() -> Fernet:
    # Through .encode() into a local, then the key parameter.
    fernet_key = "PYSINKSENTINELfernetKeyMaterial0123456789abc=".encode()
    return Fernet(fernet_key)
