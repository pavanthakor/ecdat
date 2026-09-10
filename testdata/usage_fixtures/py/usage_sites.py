"""Python call sites whose API NAMES the usage (ADR-0030).

usage drives the recommendation: RSA-for-signing becomes ML-DSA (FIPS 204),
RSA-for-key-transport becomes ML-KEM (FIPS 203). A wrong usage is a wrong
recommendation, so where the API says which it is, the finding must say so too.
"""

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def issue_token(claims, key):
    """jwt.encode SIGNS."""
    return jwt.encode(claims, key, algorithm="RS256")


def check_token(token, key):
    """jwt.decode VERIFIES. Reported as `sign` before ADR-0030."""
    return jwt.decode(token, key, algorithms=["RS256"])


def wrap_session_key(public_key, session_key):
    """RSA used as a CIPHER is key transport, not bulk encryption."""
    return public_key.encrypt(
        session_key, padding.OAEP(None, hashes.SHA256(), None)
    )


def agree(private_key, peer_public_key):
    """ECDH is key exchange."""
    return private_key.exchange(ec.ECDH(), peer_public_key)


def sign_payload(private_key, payload):
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def verify_payload(public_key, signature, payload):
    return public_key.verify(
        signature, payload, padding.PKCS1v15(), hashes.SHA256()
    )


_ = rsa
