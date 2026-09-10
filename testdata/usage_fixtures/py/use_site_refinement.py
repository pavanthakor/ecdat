"""USE-SITE REFINEMENT: a key generated `unknown`, refined by where it goes.

ADR-0004 fixed `usage: unknown` at every keygen call and said the correlator
would refine it, because a freshly generated RSA key may sign or transport and
the replacement differs (ML-DSA vs ML-KEM). Nothing refined it until ADR-0030.

Intra-procedural only -- the OSS limit -- and the third function is the honest
case: no visible use site, so the usage STAYS unknown rather than being guessed.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def signing_key(data):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def transport_key(secret):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.public_key().encrypt(
        secret, padding.OAEP(None, hashes.SHA256(), None)
    )


def key_with_no_visible_use():
    """Returned to a caller. Intra-procedural analysis cannot see the use.

    Must stay `unknown`: guessing here would put a wrong PQC target on a real
    key, and the recommendation engine already has usage-agnostic advice for
    exactly this case.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)
