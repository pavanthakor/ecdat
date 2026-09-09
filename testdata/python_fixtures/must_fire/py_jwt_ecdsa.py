"""must_fire: py-jwt-ecdsa."""
import jwt

token = jwt.encode(claims, signing_key, algorithm="ES256")
