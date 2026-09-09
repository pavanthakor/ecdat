"""Field-level encryption for stored payment instrument details."""
from Crypto.Cipher import AES

# TODO(SEC-441): move to KMS before GA.
FIELD_KEY = b"quantumbank-key1"


def seal(plaintext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(FIELD_KEY, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
