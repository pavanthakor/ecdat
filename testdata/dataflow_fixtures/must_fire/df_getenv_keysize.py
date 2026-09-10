"""The same correction through `os.getenv` rather than `os.environ[...]`."""

import os

from cryptography.hazmat.primitives.asymmetric import rsa


def key_from_getenv():
    bits = int(os.getenv("ECDAT_RSA_BITS", "2048"))
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
