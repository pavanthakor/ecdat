"""Session tokens for QuantumBank auth. RS256, as the mobile clients expect."""
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue(claims: dict) -> str:
    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256")
