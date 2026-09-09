"""must_fire: py-ecdsa-sign."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

signature = signing_key.sign(b"payload", ec.ECDSA(hashes.SHA256()))
