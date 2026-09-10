"""WEAK RNG BY DATAFLOW: the name-scoped rule's blind spot.

`value` is not named key, token, secret or nonce, so `py-weak-random-secret`
does not fire -- that rule can only see the name. The value is nevertheless
turned into the bytes an AES key is built from, which is a key-recovery bug:
MT19937 state is recoverable from 624 consecutive outputs.

The taint rule sees the FLOW rather than the name.
"""

import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(iv: bytes, data: bytes) -> bytes:
    value = random.random()
    material = str(value).encode().ljust(32, b"\0")
    cipher = Cipher(algorithms.AES(material), modes.CBC(iv))
    return cipher.encryptor().update(data)
