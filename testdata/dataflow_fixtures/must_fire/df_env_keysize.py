"""MISS-CLASS 1: a key size that IS configurable, misread as hard-coded.

`RSA_BITS` is ALL_CAPS, so the shape heuristic in scanners/source reads it as a
resolved constant and sets configurable=False. It is read from the environment:
changing it needs a restart, not a code change and a redeploy. That flag feeds
the crypto-agility score and the Mosca Y estimate, so getting it backwards
inflates the migration cost of every site like this one.
"""

import os

from cryptography.hazmat.primitives.asymmetric import rsa

RSA_BITS = int(os.environ["ECDAT_RSA_BITS"])


def key_from_env():
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
