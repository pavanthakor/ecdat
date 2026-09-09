"""must_fire: py-jwt-rsa."""
import jwt

token = jwt.encode(claims, signing_key, algorithm="RS256")
