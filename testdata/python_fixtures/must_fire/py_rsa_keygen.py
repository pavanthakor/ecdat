"""must_fire: py-rsa-keygen.

Three call sites on purpose: a literal key_size (configurable=False,
confidence 1.0), a key_size read from a variable (configurable=True,
confidence < 1.0), and the pycryptodome spelling.
"""
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa

literal_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

configured_size = 3072
variable_key = rsa.generate_private_key(
    public_exponent=65537, key_size=configured_size
)

legacy_key = RSA.generate(1024)
