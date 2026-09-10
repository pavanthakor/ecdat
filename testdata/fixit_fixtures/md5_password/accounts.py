"""fixit fixture: MD5 over a user password.

The case the template must REFUSE. Swapping MD5 for SHA-256 here would leave a
fast unsalted hash over a credential, which is the wrong fix -- password
storage wants a memory-hard KDF, not a faster digest.
"""
import hashlib


def stored_credential(password: bytes, salt: bytes) -> str:
    return hashlib.md5(salt + password).hexdigest()
