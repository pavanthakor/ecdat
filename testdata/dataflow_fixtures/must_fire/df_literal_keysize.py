"""The control for MISS-CLASS 1: the SAME algorithm, genuinely hard-coded.

Only the `configurable` flag may differ between this file and
df_env_keysize.py. If both come back the same, the correction is not working.
"""

from cryptography.hazmat.primitives.asymmetric import rsa


def key_from_literal():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
