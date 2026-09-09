"""must_fire: py-ed25519-sign."""
from cryptography.hazmat.primitives.asymmetric import ed25519

signing_key = ed25519.Ed25519PrivateKey.generate()
signature = signing_key.sign(b"payload")
