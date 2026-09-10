"""MISS-CLASS 2: a key assembled by concatenation, reaching a cipher.

The per-call-site rules see `algorithms.AES(material)` and record AES. Nothing
sees that `material` is a key BUILT IN THIS FUNCTION out of a hard-coded prefix
and a predictable suffix -- there is no `key = b"..."` literal for the
key-material rule to match, so the artefact that actually matters is invisible.

Taint closes it: the assembled value flows to a key sink.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PREFIX = b"quantumbank-"


def encrypt(tenant: str, iv: bytes, data: bytes) -> bytes:
    material = PREFIX + tenant.encode() + b"-v1"
    padded = material.ljust(32, b"\0")
    cipher = Cipher(algorithms.AES(padded), modes.CBC(iv))
    return cipher.encryptor().update(data)
