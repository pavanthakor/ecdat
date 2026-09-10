"""must_fire: the cipher, and NO hard-coded-key finding (ADR-0034).

A literal reaches each cipher here without BEING the key. Both were false
positives a plain taint rule produced in ADR-0034's STEP 0.
"""
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def key_from_password(password: bytes, iv: bytes):
    # A KDF's output is not its salt: `taint_assume_safe_functions` stops the
    # salt literal flowing through derive() into the key.
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"PYNEARMISSstaticSaltValue", iterations=600_000)
    return AES.new(kdf.derive(password), AES.MODE_CBC, iv)


def tenant_cipher(tenant_secret: bytes, iv: bytes):
    # ASSEMBLED from a constant and a runtime value: py-assembled-key-material's
    # finding (ADR-0026), not a hard-coded key -- the literal is only a part.
    return AES.new(b"PYNEARMISSprefix" + tenant_secret, AES.MODE_CBC, iv)
