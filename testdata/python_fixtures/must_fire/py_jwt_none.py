"""must_fire: py-jwt-none -- the unsigned-token footgun."""
import jwt

token = jwt.encode(claims, None, algorithm="none")
