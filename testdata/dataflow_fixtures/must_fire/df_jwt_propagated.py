"""CONST-PROP REACH: a JWT algorithm selected through a variable.

The four `py-jwt-*` rules classify the algorithm with a `metavariable-regex`,
which sees the SOURCE TEXT bound to the metavariable -- `alg`, not `"RS256"` --
so every one of these call sites was invisible before ADR-0027 while the
literal-at-call-site form was reported normally.

This is the shape that shows up in real code: a signing algorithm chosen by a
settings value, a constant at the top of a module, or a per-tenant lookup with
a literal default.
"""

import jwt

SIGNING_ALG = "ES256"


def sign_rsa(claims: dict, key: str) -> str:
    alg = "RS256"
    return jwt.encode(claims, key, algorithm=alg)


def sign_ecdsa(claims: dict, key: str) -> str:
    return jwt.encode(claims, key, algorithm=SIGNING_ALG)


def sign_hmac(claims: dict, secret: str) -> str:
    alg = "HS256"
    return jwt.encode(claims, secret, algorithm=alg)


def sign_unsigned(claims: dict) -> str:
    alg = "none"
    return jwt.encode(claims, None, algorithm=alg)
