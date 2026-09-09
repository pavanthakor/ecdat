"""A minimal repo for pipe tests.

Two crypto call sites and nothing else, so the API, CLI and orchestrator tests
can assert an exact component count without depending on the 28-rule fixture
tree. One quantum-vulnerable asset and one control, which is enough to prove a
real scan reached the CBOM.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa

signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
digest = hashlib.sha256(b"payload").hexdigest()
