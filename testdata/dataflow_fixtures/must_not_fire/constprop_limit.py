"""A DOCUMENTED LIMIT of constant propagation in the OSS build, not a decoy.

Semgrep OSS propagates literals -- strings and numbers -- through locals,
module constants and branches. It does NOT propagate a CLASS or ATTRIBUTE
reference, so `algo = algorithms.AES` followed by `algo(key)` is invisible to a
pattern written against `algorithms.AES(...)`.

Measured in ADR-0026's STEP 0 rather than assumed. This file sits in
must_not_fire because that is the behaviour today: it produces no AES finding,
and pretending otherwise in the answer key would hide a real recall gap. It is
listed in `known_limits`, NOT in `decoys` -- a decoy is something that SHOULD
stay silent, and this is something that should not.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    algo = algorithms.AES
    cipher = Cipher(algo(key), modes.CBC(iv))
    return cipher.encryptor().update(data)
