"""Both rules see this one: the variable IS named, AND the value flows.

The name-scoped rule and the taint rule must not double-report it. They agree
on algorithm, primitive, usage and locus, so they carry one identity and the
normaliser folds them into a single component -- which is what
tests/test_dataflow.py asserts, rather than one of the rules being switched off.
"""

import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(iv: bytes, data: bytes) -> bytes:
    session_key = random.getrandbits(256)
    material = str(session_key).encode().ljust(32, b"\0")
    cipher = Cipher(algorithms.AES(material), modes.CBC(iv))
    return cipher.encryptor().update(data)
