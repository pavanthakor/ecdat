"""must_fire: py-jwt-hmac."""
import jwt

token = jwt.encode(claims, shared_secret, algorithm="HS256")
